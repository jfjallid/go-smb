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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/unicode"
)

// httpUpstream wraps a single TCP/TLS connection on which NTLM authentication
// has been completed against an upstream HTTP target. Per RFC 4559 §5 the
// connection-oriented NTLM state lives on the underlying socket; subsequent
// HTTP requests issued on the same socket inherit the authenticated identity.
//
// Concurrent requests on the same upstream are serialized via mu; HTTP/1.1
// keepalive is one-at-a-time anyway.
type httpUpstream struct {
	Target Target

	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Reader
	closed bool
}

// newHTTPUpstream dials the upstream target. TLS is negotiated when
// Target.TLS is true. The caller is responsible for either driving NTLM via
// httpForwarder or using the upstream raw.
func newHTTPUpstream(target Target, dialTimeout time.Duration, tlsConfig *tls.Config) (*httpUpstream, error) {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	d := &net.Dialer{Timeout: dialTimeout}
	c, err := d.Dial("tcp", target.Host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target.Host, err)
	}
	if target.TLS {
		cfg := tlsConfig
		if cfg == nil {
			host, _, _ := net.SplitHostPort(target.Host)
			cfg = &tls.Config{ServerName: host, InsecureSkipVerify: true}
		}
		tc := tls.Client(c, cfg)
		if err := tc.Handshake(); err != nil {
			c.Close()
			return nil, fmt.Errorf("TLS handshake %s: %w", target.Host, err)
		}
		c = tc
	}
	return &httpUpstream{
		Target: target,
		conn:   c,
		reader: bufio.NewReader(c),
	}, nil
}

// Close tears down the pinned upstream socket. Idempotent.
func (u *httpUpstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	return u.conn.Close()
}

// IsClosed reports whether Close has been called.
func (u *httpUpstream) IsClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.closed
}

// Lock / Unlock expose the upstream's serialization mutex so SOCKS-side
// passthroughs can hold it across a request/response round-trip.
func (u *httpUpstream) Lock()   { u.mu.Lock() }
func (u *httpUpstream) Unlock() { u.mu.Unlock() }

// writeAndRead writes the supplied raw HTTP/1.1 request bytes and reads one
// HTTP response. Caller must hold u.mu (via Lock/Unlock or by calling from a
// path that already owns the mutex).
func (u *httpUpstream) writeAndRead(req []byte) (*http.Response, error) {
	if u.closed {
		return nil, fmt.Errorf("upstream closed")
	}
	if _, err := u.conn.Write(req); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	resp, err := http.ReadResponse(u.reader, nil)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return resp, nil
}

// httpForwarder drives an upstream NTLM-over-HTTP exchange. One forwarder is
// used per inbound authenticating HTTP client (i.e. per inbound TCP
// connection that begins an NTLM handshake).
type httpForwarder struct {
	target  Target
	logger  server.Logger
	dialer  func(target Target) (*httpUpstream, error)
	timeout time.Duration

	upstream        *httpUpstream
	serverChallenge [8]byte
}

func newHTTPForwarder(target Target, timeout time.Duration, tlsConfig *tls.Config, logger server.Logger) *httpForwarder {
	return &httpForwarder{
		target:  target,
		logger:  logger,
		timeout: timeout,
		dialer: func(t Target) (*httpUpstream, error) {
			return newHTTPUpstream(t, timeout, tlsConfig)
		},
	}
}

// Target satisfies the Forwarder interface.
func (f *httpForwarder) Target() Target { return f.target }

// Negotiate dials the upstream, sends a GET carrying the inbound NTLMSSP
// NEGOTIATE in an Authorization: NTLM header, and returns the upstream's raw
// NTLMSSP CHALLENGE (decoded from its WWW-Authenticate response). The input
// is the raw NTLMSSP NEGOTIATE bytes (no base64, no SPNEGO wrap).
func (f *httpForwarder) Negotiate(negotiate []byte) ([]byte, error) {
	if f.upstream != nil {
		return nil, fmt.Errorf("negotiate called twice")
	}
	if len(negotiate) < 8 || string(negotiate[:7]) != "NTLMSSP" {
		return nil, fmt.Errorf("negotiate: not an NTLMSSP message")
	}
	up, err := f.dialer(f.target)
	if err != nil {
		return nil, err
	}
	up.Lock()
	defer up.Unlock()

	req := buildHTTPNTLMRequest(f.target, "GET", negotiate)
	resp, err := up.writeAndRead(req)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("upstream NEGOTIATE: %w", err)
	}
	// Drain any body so the next request can reuse the pinned socket.
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		up.Close()
		return nil, fmt.Errorf("upstream did not challenge (status=%d)", resp.StatusCode)
	}
	chBytes, err := extractNTLMAuth(resp.Header.Values("WWW-Authenticate"))
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("parse WWW-Authenticate: %w", err)
	}
	chall := ntlmssp.NewChallenge()
	if err := chall.UnmarshalBinary(chBytes); err == nil {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(chall.ServerChallenge >> (8 * i))
		}
		f.serverChallenge = b
	} else if f.logger != nil {
		f.logger.Debugf("decode upstream CHALLENGE: %v", err)
	}
	f.upstream = up
	return chBytes, nil
}

// Authenticate forwards a raw NTLMSSP AUTHENTICATE token to the upstream over
// the same pinned connection used for Negotiate. mic is ignored — NTLM over
// HTTP carries no SPNEGO MIC. Returns the captured Credential and an NT-style
// status: 0 on HTTP 2xx/3xx, smb.StatusLogonFailure on HTTP 4xx/5xx.
func (f *httpForwarder) Authenticate(remote net.Addr, authenticate, mic []byte) (*Credential, uint32, error) {
	_ = mic // HTTP has no SPNEGO MIC.
	if f.upstream == nil {
		return nil, 0, fmt.Errorf("authenticate without prior Negotiate")
	}
	if len(authenticate) < 8 || string(authenticate[:7]) != "NTLMSSP" {
		return nil, 0, fmt.Errorf("authenticate: not an NTLMSSP message")
	}
	var auth ntlmssp.Authenticate
	if err := auth.UnmarshalBinary(authenticate); err != nil {
		return nil, 0, fmt.Errorf("decode AUTHENTICATE: %w", err)
	}
	cred := buildCredentialFromAuth(&auth, f.serverChallenge, remote)

	f.upstream.Lock()
	defer f.upstream.Unlock()
	req := buildHTTPNTLMRequest(f.target, "GET", authenticate)
	resp, err := f.upstream.writeAndRead(req)
	if err != nil {
		return cred, 0, fmt.Errorf("upstream AUTHENTICATE: %w", err)
	}
	// Drain response body so the pinned socket is ready for the next request.
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	if resp.StatusCode >= 400 {
		return cred, smb.StatusLogonFailure, nil
	}
	return cred, smb.StatusOk, nil
}

// Take returns the upstream and zeroes the field. Close is a no-op afterwards.
func (f *httpForwarder) Take() *httpUpstream {
	up := f.upstream
	f.upstream = nil
	return up
}

// Close tears down the upstream if still owned. Idempotent.
func (f *httpForwarder) Close() {
	if f.upstream == nil {
		return
	}
	f.upstream.Close()
	f.upstream = nil
}

// buildHTTPNTLMRequest assembles a minimal HTTP/1.1 request with an
// Authorization: NTLM <base64> header. Connection: Keep-Alive is required so
// the upstream doesn't reset the socket between NEGOTIATE and AUTHENTICATE.
func buildHTTPNTLMRequest(target Target, method string, ntlmToken []byte) []byte {
	hostHdr, _, _ := net.SplitHostPort(target.Host)
	if hostHdr == "" {
		hostHdr = target.Host
	}
	host, port, _ := net.SplitHostPort(target.Host)
	defaultPort := "80"
	if target.TLS {
		defaultPort = "443"
	}
	if port != "" && port != defaultPort {
		hostHdr = host + ":" + port
	}
	path := target.Path
	if path == "" {
		path = "/"
	}
	b := &bytes.Buffer{}
	fmt.Fprintf(b, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(b, "Host: %s\r\n", hostHdr)
	fmt.Fprintf(b, "User-Agent: go-smb-relay/1.0\r\n")
	fmt.Fprintf(b, "Authorization: NTLM %s\r\n", base64.StdEncoding.EncodeToString(ntlmToken))
	fmt.Fprintf(b, "Accept: */*\r\n")
	fmt.Fprintf(b, "Connection: Keep-Alive\r\n")
	fmt.Fprintf(b, "Content-Length: 0\r\n")
	fmt.Fprintf(b, "\r\n")
	return b.Bytes()
}

// extractNTLMAuth returns the raw NTLMSSP token bytes from a slice of
// WWW-Authenticate or Authorization header values, accepting only the "NTLM"
// scheme. Returns an error if no NTLM scheme is present or the base64 payload
// is malformed.
func extractNTLMAuth(values []string) ([]byte, error) {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		// Header form: "NTLM <base64>". Bare "NTLM" with no payload is the
		// initial challenge prompt the server sends before the client has
		// presented a NEGOTIATE — caller handles that case separately.
		if len(v) < 4 || !strings.EqualFold(v[:4], "NTLM") {
			continue
		}
		rest := strings.TrimSpace(v[4:])
		if rest == "" {
			return nil, fmt.Errorf("NTLM header has empty payload")
		}
		decoded, err := base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("no NTLM scheme in header values")
}

// buildCredentialFromAuth assembles a Credential from a parsed NTLMSSP
// Authenticate message and the server-side challenge that was used during the
// upstream exchange. Mirrors server.BuildCredential but takes net.Addr instead
// of *server.Conn so both forwarder backends share one code path.
func buildCredentialFromAuth(auth *ntlmssp.Authenticate, chal [8]byte, remote net.Addr) *Credential {
	cred := &Credential{
		LM:              auth.LmChallengeResponse,
		NT:              auth.NtChallengeResponse,
		ServerChallenge: chal,
		RemoteAddr:      remote,
	}
	cred.Username, _ = unicode.FromUnicodeString(auth.UserName)
	cred.Domain, _ = unicode.FromUnicodeString(auth.DomainName)
	cred.Workstation, _ = unicode.FromUnicodeString(auth.Workstation)
	if len(auth.NtChallengeResponse) > 24 {
		cred.Format = "Net-NTLMv2"
		cred.Hashcat = fmt.Sprintf("%s::%s:%x:%x:%x",
			cred.Username, cred.Domain, chal[:],
			auth.NtChallengeResponse[:16], auth.NtChallengeResponse[16:])
	} else if len(auth.NtChallengeResponse) == 24 {
		cred.Format = "Net-NTLMv1"
		cred.Hashcat = fmt.Sprintf("%s::%s:%x:%x:%x",
			cred.Username, cred.Domain,
			auth.LmChallengeResponse, auth.NtChallengeResponse, chal[:])
	}
	return cred
}
