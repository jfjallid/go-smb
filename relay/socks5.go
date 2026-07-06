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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/smb/server"
)

// SOCKS5 reply codes (RFC 1928).
const (
	socksReplySuccess              byte = 0x00
	socksReplyGeneralFailure       byte = 0x01
	socksReplyConnNotAllowed       byte = 0x02
	socksReplyHostUnreachable      byte = 0x04
	socksReplyConnRefused          byte = 0x05
	socksReplyCmdNotSupported      byte = 0x07
	socksReplyAddrTypeNotSupported byte = 0x08
)

const (
	socksCmdConnect byte = 0x01

	socksAtypIPv4   byte = 0x01
	socksAtypDomain byte = 0x03
	socksAtypIPv6   byte = 0x04
)

// socksServer accepts SOCKS5 CONNECT requests, looks up the target in the
// session pool, and dispatches to the SMB raw-PDU passthrough.
type socksServer struct {
	rs     *RelayServer
	logger server.Logger
}

func newSocksServer(rs *RelayServer) *socksServer {
	return &socksServer{rs: rs, logger: rs.logger()}
}

// serve accepts SOCKS5 connections until ln is closed.
func (s *socksServer) serve(ln net.Listener) {
	for {
		nc, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Errorf("socks: accept: %v", err)
			return
		}
		s.rs.wg.Add(1)
		go func(c net.Conn) {
			defer s.rs.wg.Done()
			defer c.Close()
			// Isolate panics to this connection: a parser panic on a single
			// (untrusted) SOCKS/passthrough stream must not crash the whole relay
			// process and drop every other session. Mirrors the recover() in the
			// SMB server's per-connection goroutine.
			defer func() {
				if r := recover(); r != nil {
					s.logger.Errorf("socks: recovered from panic on %s: %v", c.RemoteAddr(), r)
				}
			}()
			s.handle(c)
		}(nc)
	}
}

// handle drives one SOCKS5 client through method negotiation, request, and
// dispatch. The pool lookup is deferred to passthrough-time: for SMB,
// SessionSetup leg 2 carries the username we filter on (via Resolve →
// resolveUpstream). HTTP and LDAP passthrough do not filter on any inbound
// identity — the pinned upstream's captured credentials are used as-is.
//
// Only the target is known at this point — but if no pooled session matches
// the target at all, refuse early so the SOCKS client sees a clear rejection
// instead of going through a useless SMB handshake.
//
// Note: SOCKS5 method negotiation accepts only no-auth (0x00). The SOCKS
// client therefore cannot prove an identity at the SOCKS layer; treat the
// listener as trusted-local-tools-only.
func (s *socksServer) handle(c net.Conn) {
	target, err := socks5Handshake(c)
	if err != nil {
		s.logger.Infof("socks: handshake from %s: %v", c.RemoteAddr(), err)
		return
	}

	matches := s.rs.pool.FindMatches(target, "")
	if len(matches) == 0 {
		s.logger.Infof("socks: no pooled session for target %s (request from %s)", target, c.RemoteAddr())
		_ = writeSocksReply(c, socksReplyConnRefused, c.LocalAddr())
		return
	}
	// HTTP, LDAP, and SMB upstreams share the same pool keyed by host:port.
	// Pick the passthrough kind from the first candidate; entries for any
	// given target are all of the same kind (an ldap://dc01:636 target never
	// collides with an smb://dc01:636 target on the same listener config).
	kind := pickUpstreamKind(matches[0])
	s.logger.Debugf("socks: %d match(es) for target=%s; first entry kind=%v dead=%v",
		len(matches), target, kind, matches[0].IsDead())

	if err := writeSocksReply(c, socksReplySuccess, c.LocalAddr()); err != nil {
		s.logger.Debugf("socks: reply to %s: %v", c.RemoteAddr(), err)
		return
	}
	if cb := s.rs.Config.OnSocksClient; cb != nil {
		cb(c.RemoteAddr(), target)
	}

	remote := c.RemoteAddr()
	switch kind {
	case upstreamKindHTTP:
		p := &HTTPPassthrough{
			Local:   c,
			Target:  target,
			Logger:  s.logger,
			Resolve: s.rs.resolveHTTPUpstream(remote),
		}
		if err := p.Run(context.Background()); err != nil {
			s.logger.Debugf("socks: http passthrough %s: %v", c.RemoteAddr(), err)
		}
	case upstreamKindLDAP:
		p := &LDAPPassthrough{
			Local:   c,
			Target:  target,
			Logger:  s.logger,
			Resolve: s.rs.resolveLDAPUpstream(remote),
		}
		if err := p.Run(context.Background()); err != nil {
			s.logger.Debugf("socks: ldap passthrough %s: %v", c.RemoteAddr(), err)
		}
	default:
		p := &SMBPassthrough{
			Local:   c,
			Target:  target,
			Logger:  s.logger,
			Resolve: s.rs.resolveUpstream(remote),
		}
		if err := p.Run(context.Background()); err != nil {
			s.logger.Debugf("socks: smb passthrough %s: %v", c.RemoteAddr(), err)
		}
	}
}

type upstreamKind int

const (
	upstreamKindSMB upstreamKind = iota
	upstreamKindHTTP
	upstreamKindLDAP
)

func pickUpstreamKind(ps *pooledSession) upstreamKind {
	switch {
	case ps.IsLDAP():
		return upstreamKindLDAP
	case ps.IsHTTP():
		return upstreamKindHTTP
	}
	return upstreamKindSMB
}

// socks5Handshake performs RFC 1928 method negotiation and request parsing.
// Returns the requested target as "host:port" on success.
func socks5Handshake(c net.Conn) (string, error) {
	// Method negotiation: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != 0x05 {
		return "", fmt.Errorf("unsupported SOCKS version 0x%02x", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return "", fmt.Errorf("read methods: %w", err)
	}
	// We only support no-auth (0x00). Reject otherwise.
	noAuth := false
	for _, m := range methods {
		if m == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = c.Write([]byte{0x05, 0xff})
		return "", fmt.Errorf("client did not offer no-auth method")
	}
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", fmt.Errorf("write method selection: %w", err)
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return "", fmt.Errorf("read request: %w", err)
	}
	if req[0] != 0x05 {
		return "", fmt.Errorf("request bad ver 0x%02x", req[0])
	}
	if req[1] != socksCmdConnect {
		_ = writeSocksReply(c, socksReplyCmdNotSupported, c.LocalAddr())
		return "", fmt.Errorf("unsupported command 0x%02x", req[1])
	}

	var host string
	switch req[3] {
	case socksAtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case socksAtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = net.IP(buf).String()
	case socksAtypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return "", err
		}
		// l[0] is uint8 so naturally ≤255 (the SOCKS5 cap), but reject
		// a zero-length domain — it's never valid and would otherwise
		// produce a confusing "no pooled session for target :port" log.
		if l[0] == 0 {
			return "", fmt.Errorf("zero-length domain in SOCKS5 request")
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		_ = writeSocksReply(c, socksReplyAddrTypeNotSupported, c.LocalAddr())
		return "", fmt.Errorf("unsupported address type 0x%02x", req[3])
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(c, portBytes); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(portBytes)
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// writeSocksReply writes a reply with BND.ADDR/PORT taken from bnd. The
// reply format is VER REP RSV ATYP BND.ADDR BND.PORT.
func writeSocksReply(c net.Conn, code byte, bnd net.Addr) error {
	host, portStr, err := net.SplitHostPort(addrString(bnd))
	if err != nil {
		host = "0.0.0.0"
		portStr = "0"
	}
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)

	out := []byte{0x05, code, 0x00}
	if ip4 := ip.To4(); ip4 != nil {
		out = append(out, socksAtypIPv4)
		out = append(out, ip4...)
	} else if ip != nil {
		out = append(out, socksAtypIPv6)
		out = append(out, ip.To16()...)
	} else {
		out = append(out, socksAtypDomain)
		out = append(out, byte(len(host)))
		out = append(out, []byte(host)...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	_, err = c.Write(out)
	return err
}

// addrString returns the canonical host:port form of a net.Addr, including
// for the * unbound case.
func addrString(a net.Addr) string {
	if a == nil {
		return "0.0.0.0:0"
	}
	s := a.String()
	if !strings.Contains(s, ":") {
		return s + ":0"
	}
	return s
}
