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

package relay_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb/server"
)

// ntlmHTTPUpstream is a tiny NTLM-accepting HTTP server used in HTTP relay
// tests. It mimics IIS: bare 401+WWW-Authenticate:NTLM with no payload to
// prompt the client, then the standard 3-leg dance keyed by *http.Server's
// per-connection state. Once authenticated, requests on the same TCP
// connection return 200 with the configured protected payload (no further
// auth required).
type ntlmHTTPUpstream struct {
	t              *testing.T
	listener       net.Listener
	srv            *http.Server
	expectedUser   string
	expectedDomain string
	protectedBody  []byte

	mu     sync.Mutex
	states map[net.Conn]*ntlmHTTPState

	authedConns atomic.Int32
}

type ntlmHTTPState struct {
	server *ntlmssp.Server
	authed bool
}

func newNtlmHTTPUpstream(t *testing.T, expectedUser, expectedDomain string, body []byte) *ntlmHTTPUpstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	up := &ntlmHTTPUpstream{
		t:              t,
		listener:       ln,
		expectedUser:   expectedUser,
		expectedDomain: expectedDomain,
		protectedBody:  body,
		states:         map[net.Conn]*ntlmHTTPState{},
	}
	up.srv = &http.Server{
		Handler: http.HandlerFunc(up.handle),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, upstreamConnKey{}, c)
		},
		ConnState: func(c net.Conn, s http.ConnState) {
			if s == http.StateClosed {
				up.mu.Lock()
				delete(up.states, c)
				up.mu.Unlock()
			}
		},
	}
	go func() {
		_ = up.srv.Serve(ln)
	}()
	return up
}

type upstreamConnKey struct{}

func (u *ntlmHTTPUpstream) Addr() string {
	return u.listener.Addr().String()
}

func (u *ntlmHTTPUpstream) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = u.srv.Shutdown(ctx)
}

func (u *ntlmHTTPUpstream) handle(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Context().Value(upstreamConnKey{}).(net.Conn)
	u.mu.Lock()
	st := u.states[c]
	u.mu.Unlock()

	auth := r.Header.Get("Authorization")
	if auth == "" {
		// Already authenticated on this conn — serve content.
		if st != nil && st.authed {
			w.Header().Set("Content-Length", fmt.Sprint(len(u.protectedBody)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(u.protectedBody)
			return
		}
		w.Header().Set("WWW-Authenticate", "NTLM")
		w.Header().Set("Connection", "Keep-Alive")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if !strings.HasPrefix(strings.ToLower(auth), "ntlm ") {
		http.Error(w, "bad scheme", http.StatusBadRequest)
		return
	}
	token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[5:]))
	if err != nil || len(token) < 12 || string(token[:7]) != "NTLMSSP" {
		http.Error(w, "bad payload", http.StatusBadRequest)
		return
	}
	switch token[8] {
	case 0x01: // NEGOTIATE
		srv := &ntlmssp.Server{
			TargetName:    "UPSTREAM",
			NetBIOSName:   "UPSTREAM",
			NetBIOSDomain: u.expectedDomain,
		}
		ch, err := srv.AcceptNegotiate(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		u.mu.Lock()
		u.states[c] = &ntlmHTTPState{server: srv}
		u.mu.Unlock()
		w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ch))
		w.Header().Set("Connection", "Keep-Alive")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusUnauthorized)

	case 0x03: // AUTHENTICATE
		if st == nil || st.server == nil {
			http.Error(w, "no NEGOTIATE first", http.StatusBadRequest)
			return
		}
		auth, err := st.server.AcceptAuthenticate(token)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Cheap check: we just verify the asserted user/domain match what we
		// expect — relay tests aren't testing NTLM hash validation here.
		user, _ := utf16ToString(auth.UserName)
		domain, _ := utf16ToString(auth.DomainName)
		if user != u.expectedUser || domain != u.expectedDomain {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		st.authed = true
		u.authedConns.Add(1)
		w.Header().Set("Content-Length", fmt.Sprint(len(u.protectedBody)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(u.protectedBody)

	default:
		http.Error(w, "bad ntlm type", http.StatusBadRequest)
	}
}

// utf16ToString reads a NTLMSSP UTF-16LE field into Go string.
func utf16ToString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("odd utf16 length")
	}
	out := make([]rune, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		out = append(out, rune(uint16(b[i])|uint16(b[i+1])<<8))
	}
	return string(out), nil
}

// driveHTTPNTLMVictim performs the 3-leg NTLM-over-HTTP exchange as a victim
// client would, against the supplied relay HTTP listener. Returns the final
// status code (always 401 for capture-and-drop).
func driveHTTPNTLMVictim(t *testing.T, listenerAddr, user, password, domain string) int {
	t.Helper()
	c, err := net.DialTimeout("tcp", listenerAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial relay: %v", err)
	}
	defer c.Close()
	r := bufio.NewReader(c)

	// Leg 1: build NEGOTIATE via ntlmssp.Client.
	cl := &ntlmssp.Client{
		Workstation: "VICTIM",
		Domain:      domain,
		User:        user,
		Password:    password,
	}
	neg, err := cl.Negotiate()
	if err != nil {
		t.Fatalf("ntlm Negotiate: %v", err)
	}

	// Send GET / with the NEGOTIATE.
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: relay\r\nConnection: Keep-Alive\r\nAuthorization: NTLM %s\r\nContent-Length: 0\r\n\r\n",
		base64.StdEncoding.EncodeToString(neg))
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write neg: %v", err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("leg1 status = %d, want 401", resp.StatusCode)
	}
	wa := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(wa), "ntlm ") {
		t.Fatalf("leg1 WWW-Authenticate = %q", wa)
	}
	chBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wa[5:]))
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	// Leg 2: NTLM client produces AUTHENTICATE.
	authMsg, err := cl.Authenticate(chBytes)
	if err != nil {
		t.Fatalf("ntlm Authenticate: %v", err)
	}
	req = fmt.Sprintf("GET / HTTP/1.1\r\nHost: relay\r\nConnection: Keep-Alive\r\nAuthorization: NTLM %s\r\nContent-Length: 0\r\n\r\n",
		base64.StdEncoding.EncodeToString(authMsg))
	if _, err := c.Write([]byte(req)); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	resp, err = http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}

// TestHTTPRelayEndToEnd boots a mock NTLM HTTP upstream, starts a RelayServer
// with an HTTP listener pointed at it, drives an inbound NTLM exchange, and
// verifies that:
//   - the upstream HTTP session gets pooled
//   - OnCredentialCaptured fires with the captured user/domain
//   - the upstream accepted the relayed auth (200 was returned to the relay)
//   - a SOCKS5 client can fetch /content through the proxy without
//     authenticating, and the response body matches the upstream's content
func TestHTTPRelayEndToEnd(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	upstreamBody := []byte("relay-served from upstream\n")
	up := newNtlmHTTPUpstream(t, user, domain, upstreamBody)
	defer up.Stop()

	var (
		credsMu sync.Mutex
		creds   []*relay.Credential
	)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			SocksAddr:      "127.0.0.1:0",
			HTTPListenAddr: "127.0.0.1:0",
			Targets:        []string{"http://" + up.Addr()},
			OnCredentialCaptured: func(_ *server.Conn, c *relay.Credential) {
				credsMu.Lock()
				creds = append(creds, c)
				credsMu.Unlock()
			},
		},
	}

	if err := rs.Start(); err != nil {
		t.Fatalf("RelayServer.Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rs.Shutdown(ctx)
	}()

	relayAddr := rs.HTTPAddr().(*net.TCPAddr).String()
	socksAddr := rs.SocksAddr().(*net.TCPAddr).String()

	// Drive an inbound NTLM-over-HTTP exchange. The relay returns 401 to the
	// victim regardless (capture-and-drop); we just want the upstream
	// session pooled.
	if status := driveHTTPNTLMVictim(t, relayAddr, user, password, domain); status != 401 {
		t.Errorf("victim final status = %d, want 401", status)
	}

	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 1 }) {
		t.Fatalf("HTTP upstream session never pooled (have %d)", len(rs.Snapshot()))
	}

	credsMu.Lock()
	if len(creds) == 0 {
		credsMu.Unlock()
		t.Fatalf("OnCredentialCaptured never fired")
	}
	gotCred := creds[0]
	credsMu.Unlock()
	if gotCred.Username != user || gotCred.Domain != domain {
		t.Errorf("captured cred = %s\\%s, want %s\\%s", gotCred.Domain, gotCred.Username, domain, user)
	}
	if up.authedConns.Load() == 0 {
		t.Errorf("upstream never saw a successful AUTHENTICATE")
	}

	// SOCKS5 fetch through the pooled session.
	conn, err := socks5Connect(socksAddr, up.Addr())
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	host, _, _ := net.SplitHostPort(up.Addr())
	_, port, _ := net.SplitHostPort(up.Addr())
	getReq := fmt.Sprintf("GET /content HTTP/1.1\r\nHost: %s:%s\r\nConnection: close\r\n\r\n", host, port)
	if _, err := conn.Write([]byte(getReq)); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read GET reply: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("SOCKS-fronted GET status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != string(upstreamBody) {
		t.Errorf("SOCKS-fronted GET body = %q, want %q", body, upstreamBody)
	}
}

// TestHTTPForwarderHandshake covers the forwarder against the mock upstream
// without any relay scaffolding — useful as a thin sanity check that the
// outbound NTLM-over-HTTP plumbing produces a successful exchange when fed
// the same NTLMSSP messages we would relay.
func TestHTTPForwarderHandshake(t *testing.T) {
	const (
		user     = "bob"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	up := newNtlmHTTPUpstream(t, user, domain, []byte("ok"))
	defer up.Stop()

	// Drive an NTLM client to obtain a valid NEGOTIATE + AUTHENTICATE pair.
	// Then run those messages through the HTTPListener end-to-end via the
	// public flow: easier to just go through the listener.
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			HTTPListenAddr: "127.0.0.1:0",
			Targets:        []string{"http://" + up.Addr()},
		},
	}
	if err := rs.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = rs.Shutdown(ctx)
	}()

	if status := driveHTTPNTLMVictim(t, rs.HTTPAddr().String(), user, password, domain); status != 401 {
		t.Errorf("victim final status = %d, want 401", status)
	}
	if !waitFor(2*time.Second, func() bool { return up.authedConns.Load() >= 1 }) {
		t.Fatalf("upstream never saw AUTHENTICATE")
	}
}
