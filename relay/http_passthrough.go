// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package relay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/jfjallid/go-smb/smb/server"
)

// HTTPPassthrough handles a SOCKS-fronted HTTP conversation by raw-forwarding
// each request over the pooled upstream HTTP connection. The pinned upstream
// socket carries the NTLM-authenticated identity (per RFC 4559 §5), so the
// SOCKS-side client never sees the auth handshake — it just issues plain
// HTTP/1.1 requests and we forward them.
//
// The Authorization header (if any) is stripped from the inbound request so
// the SOCKS client cannot break the upstream's NTLM context.
type HTTPPassthrough struct {
	Local    net.Conn
	Target   string // upstream "host:port"
	Upstream *pooledSession
	Resolve  func(target string) *pooledSession
	Logger   server.Logger
}

// Run reads HTTP/1.1 requests from Local in a loop and forwards each over the
// pinned upstream connection. Returns when Local closes (clean EOF) or on
// transport error.
func (p *HTTPPassthrough) Run(ctx context.Context) error {
	if p.Logger == nil {
		p.Logger = log
	}
	if p.Upstream == nil && p.Resolve != nil {
		p.Upstream = p.Resolve(p.Target)
	}
	if p.Upstream == nil || p.Upstream.HTTP == nil {
		return p.writeBadGatewayAndClose("no pooled HTTP session for " + p.Target)
	}

	reader := bufio.NewReader(p.Local)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read inbound HTTP request: %w", err)
		}

		// Don't let the SOCKS-side client inject its own Authorization. The
		// upstream NTLM context lives on the pinned socket and would be
		// confused by a fresh NTLM token mid-stream.
		req.Header.Del("Authorization")
		req.Header.Del("Proxy-Authorization")
		// We pin one upstream socket — never close it from the SOCKS side.
		req.Header.Set("Connection", "Keep-Alive")
		req.Header.Del("Proxy-Connection")
		// Replace the Host header with the upstream's host so the upstream
		// routes the request correctly (the SOCKS client may have used a
		// different name).
		req.Host = upstreamHostHeader(p.Target, p.Upstream.HTTP.Target.TLS)

		// Drain the body into memory if any (we need to know its length to
		// emit Content-Length, and to release the bufio reader to the
		// passthrough loop).
		var body []byte
		if req.ContentLength != 0 && req.Body != nil {
			body, err = io.ReadAll(req.Body)
			_ = req.Body.Close()
			if err != nil {
				return fmt.Errorf("read inbound body: %w", err)
			}
		}

		resp, err := p.forwardOne(req, body)
		if err != nil {
			p.Logger.Debugf("forward to %s: %v", p.Target, err)
			p.Upstream.MarkDead()
			return fmt.Errorf("forward to %s: %w", p.Target, err)
		}
		p.Logger.Debugf("upstream %s -> %d", p.Target, resp.StatusCode)

		// Pipe response back to local. Strip hop-by-hop / NTLM headers that
		// would otherwise leak the upstream auth state.
		for _, h := range hopByHopHeaders {
			resp.Header.Del(h)
		}
		resp.Header.Del("WWW-Authenticate")

		if err := writeResponse(p.Local, resp); err != nil {
			resp.Body.Close()
			return fmt.Errorf("write response: %w", err)
		}
		resp.Body.Close()
		p.Upstream.Touch()

		if req.Close || strings.EqualFold(req.Header.Get("Connection"), "close") {
			return nil
		}
	}
}

// forwardOne sends one request/body over the pinned upstream socket and
// returns the response. Holds Upstream.HTTP.mu for the round-trip so multiple
// SOCKS clients on the same pooled session don't interleave.
//
// The request is serialized manually rather than via http.Request.Write so
// the inbound request's headers pass through verbatim (Authorization is
// already stripped earlier in Run) and we control framing for the pinned
// keepalive socket.
func (p *HTTPPassthrough) forwardOne(req *http.Request, body []byte) (*http.Response, error) {
	p.Upstream.mu.Lock()
	defer p.Upstream.mu.Unlock()
	p.Upstream.HTTP.Lock()
	defer p.Upstream.HTTP.Unlock()

	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	hdr := &bytes.Buffer{}
	fmt.Fprintf(hdr, "%s %s HTTP/1.1\r\n", req.Method, path)
	fmt.Fprintf(hdr, "Host: %s\r\n", req.Host)
	// Drop existing Content-Length / Transfer-Encoding; we re-emit based on
	// the buffered body length.
	req.Header.Del("Content-Length")
	req.Header.Del("Transfer-Encoding")
	if err := req.Header.WriteSubset(hdr, nil); err != nil {
		return nil, fmt.Errorf("write headers: %w", err)
	}
	fmt.Fprintf(hdr, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(hdr, "Connection: Keep-Alive\r\n")
	hdr.WriteString("\r\n")

	if _, err := p.Upstream.HTTP.conn.Write(hdr.Bytes()); err != nil {
		return nil, err
	}
	if len(body) > 0 {
		if _, err := p.Upstream.HTTP.conn.Write(body); err != nil {
			return nil, err
		}
	}
	resp, err := http.ReadResponse(p.Upstream.HTTP.reader, req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// writeBadGatewayAndClose emits a minimal 502 to Local and returns nil.
func (p *HTTPPassthrough) writeBadGatewayAndClose(msg string) error {
	body := []byte(msg + "\r\n")
	hdr := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
	if _, err := p.Local.Write([]byte(hdr)); err != nil {
		return err
	}
	_, _ = p.Local.Write(body)
	return nil
}

// writeResponse serializes an *http.Response onto the supplied writer in
// HTTP/1.1 wire format. Sends Content-Length when known; falls back to
// streamed chunked for unknown length.
func writeResponse(w net.Conn, resp *http.Response) error {
	// http.Response.Write writes the response in wire format including
	// Status line and body. Use it directly.
	return resp.Write(w)
}

// hopByHopHeaders is the standard RFC 7230 §6.1 hop-by-hop list. Strip from
// responses we proxy back to the SOCKS client.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// upstreamHostHeader returns the Host header value to send upstream. If the
// upstream port is the scheme default (80/443), the bare host is returned;
// otherwise host:port.
func upstreamHostHeader(target string, isTLS bool) string {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return target
	}
	defaultPort := "80"
	if isTLS {
		defaultPort = "443"
	}
	if port == defaultPort {
		return host
	}
	return host + ":" + port
}
