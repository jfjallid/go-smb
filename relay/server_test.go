// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestRelayServerEndToEnd boots two upstream SMB servers, starts a
// RelayServer with both as targets and a SOCKS5 listener, drives two inbound
// auth attempts through the SMB listener, and verifies that:
//   - both upstream sessions get pooled (round-robin spreads them across the
//     two targets);
//   - OnRelaySuccess and OnCredentialCaptured fire;
//   - a SOCKS5 client can CONNECT to upstream1:445 through the proxy and
//     issue TreeConnect against the upstream's registered share.
func TestRelayServerEndToEnd(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	mkUpstream := func(name string) (*server.Server, *net.TCPAddr, func()) {
		s := &server.Server{
			Config: &server.ServerConfig{
				Authenticator: &server.MapAuthenticator{
					Domain:   domain,
					Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
				},
			},
		}
		s.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen %s: %v", name, err)
		}
		ch := make(chan error, 1)
		go func() { ch <- s.Serve(l) }()
		return s, l.Addr().(*net.TCPAddr), func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = s.Shutdown(ctx)
			if e := <-ch; e != nil && e != server.ErrServerClosed {
				t.Errorf("upstream %s Serve: %v", name, e)
			}
		}
	}

	_, up1Addr, up1Stop := mkUpstream("up1")
	defer up1Stop()
	_, up2Addr, up2Stop := mkUpstream("up2")
	defer up2Stop()

	var (
		credsMu       sync.Mutex
		credsCaptured []*relay.Credential
		successMu     sync.Mutex
		successes     []string
	)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr:   "127.0.0.1:0",
			SocksAddr:    "127.0.0.1:0",
			Targets:      []string{"smb://" + up1Addr.String(), "smb://" + up2Addr.String()},
			SelectTarget: relay.RoundRobin(),
			OnCredentialCaptured: func(_ *server.Conn, cred *relay.Credential) {
				credsMu.Lock()
				credsCaptured = append(credsCaptured, cred)
				credsMu.Unlock()
			},
			OnRelaySuccess: func(target string, _ *smb.Connection, _ *relay.Credential) {
				successMu.Lock()
				successes = append(successes, target)
				successMu.Unlock()
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

	relayAddr := rs.SMBAddr().(*net.TCPAddr)
	socksAddr := rs.SocksAddr().(*net.TCPAddr)

	// Drive two inbound auths through the relay.
	for i := 0; i < 2; i++ {
		opts := smb.Options{
			Host:              relayAddr.IP.String(),
			Port:              relayAddr.Port,
			User:              user,
			Password:          password,
			Domain:            domain,
			Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
			DisableSigning:    true,
			DisableEncryption: true,
			ForceSMB2:         true,
			DialTimeout:       2 * time.Second,
		}
		_, _ = smb.NewConnection(opts) // expected to fail (capture-and-drop)
	}

	// Wait for both upstream sessions to appear in the pool.
	if !waitFor(2*time.Second, func() bool {
		return len(rs.Snapshot()) >= 2
	}) {
		t.Fatalf("did not pool 2 sessions; have %d", len(rs.Snapshot()))
	}

	credsMu.Lock()
	gotCreds := append([]*relay.Credential(nil), credsCaptured...)
	credsMu.Unlock()
	if len(gotCreds) < 2 {
		t.Errorf("OnCredentialCaptured fired %d times, want >=2", len(gotCreds))
	}

	// Round-robin should have hit both upstream targets.
	successMu.Lock()
	gotSuccesses := append([]string(nil), successes...)
	successMu.Unlock()
	seen := map[string]bool{}
	for _, t := range gotSuccesses {
		seen[t] = true
	}
	if len(seen) < 2 {
		t.Errorf("round-robin did not spread across both targets, got %v", gotSuccesses)
	}

	// SOCKS5 client: drive smb.NewConnection against upstream1 through the
	// proxy. The Initiator's username must match the captured credential — the
	// SOCKS server parses the NTLMSSP AUTHENTICATE and routes to a pool entry
	// matching (target, user).
	socksOpts := smb.Options{
		Host:              up1Addr.IP.String(),
		Port:              up1Addr.Port,
		User:              user,
		Password:          "ignored",
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: "ignored", Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
		ProxyDialer:       &fixedSocksDialer{socksAddr: socksAddr.String(), target: up1Addr.String()},
	}
	conn, err := smb.NewConnection(socksOpts)
	if err != nil {
		t.Fatalf("SOCKS-fronted NewConnection: %v", err)
	}
	defer conn.Close()
	if err := conn.TreeConnect(share); err != nil {
		t.Fatalf("SOCKS-fronted TreeConnect %q: %v", share, err)
	}
	defer conn.TreeDisconnect(share)

	// Exercise Create + Write + Close + Read translation by round-tripping a
	// small file through the SOCKS-fronted upstream session.
	body := []byte("relay socks roundtrip\n")
	off := 0
	if err := conn.PutFile(share, "hello.txt", 0, func(buf []byte) (int, error) {
		if off >= len(body) {
			return 0, io.EOF
		}
		n := copy(buf, body[off:])
		off += n
		return n, nil
	}); err != nil {
		t.Fatalf("SOCKS-fronted PutFile: %v", err)
	}

	var got []byte
	if err := conn.RetrieveFile(share, "hello.txt", 0, func(b []byte) (int, error) {
		got = append(got, b...)
		return len(b), nil
	}); err != nil {
		t.Fatalf("SOCKS-fronted RetrieveFile: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("SOCKS-fronted RetrieveFile body=%q want %q", got, body)
	}
}

// TestSocksPiggybackReusesPooledSession opens two SOCKS-fronted SMB
// connections sequentially against the same pooled upstream session. This
// regression-tests MessageID translation in smb_passthrough.forward: the
// first piggy-back happens to align because both counters start near zero,
// but the second arrives when the upstream MessageID counter has advanced
// past anything the new local client has sent — without per-PDU MID
// translation the client would reject every reply with "Message Id (N) not
// found in outstanding packets".
func TestSocksPiggybackReusesPooledSession(t *testing.T) {
	const (
		user     = "carol"
		password = "Reuse-Me-1!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	up := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	up.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	upL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	upCh := make(chan error, 1)
	go func() { upCh <- up.Serve(upL) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = up.Shutdown(ctx)
		<-upCh
	}()
	upAddr := upL.Addr().(*net.TCPAddr)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			SocksAddr:  "127.0.0.1:0",
			Targets:    []string{"smb://" + upAddr.String()},
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
	relayAddr := rs.SMBAddr().(*net.TCPAddr)
	socksAddr := rs.SocksAddr().(*net.TCPAddr)

	// Drive one inbound auth so the upstream session gets pooled.
	bait := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		User:              user,
		Password:          password,
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	_, _ = smb.NewConnection(bait)
	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 1 }) {
		t.Fatalf("upstream session never pooled (have %d)", len(rs.Snapshot()))
	}

	socksOpts := smb.Options{
		Host:              upAddr.IP.String(),
		Port:              upAddr.Port,
		User:              user,
		Password:          "ignored",
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: "ignored", Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
		ProxyDialer:       &fixedSocksDialer{socksAddr: socksAddr.String(), target: upAddr.String()},
	}

	doRoundtrip := func(label, filename string, body []byte) {
		conn, err := smb.NewConnection(socksOpts)
		if err != nil {
			t.Fatalf("%s NewConnection: %v", label, err)
		}
		defer conn.Close()
		if err := conn.TreeConnect(share); err != nil {
			t.Fatalf("%s TreeConnect: %v", label, err)
		}
		defer conn.TreeDisconnect(share)

		off := 0
		if err := conn.PutFile(share, filename, 0, func(buf []byte) (int, error) {
			if off >= len(body) {
				return 0, io.EOF
			}
			n := copy(buf, body[off:])
			off += n
			return n, nil
		}); err != nil {
			t.Fatalf("%s PutFile: %v", label, err)
		}
		var got []byte
		if err := conn.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
			got = append(got, b...)
			return len(b), nil
		}); err != nil {
			t.Fatalf("%s RetrieveFile: %v", label, err)
		}
		if string(got) != string(body) {
			t.Errorf("%s body=%q want %q", label, got, body)
		}
	}

	doRoundtrip("first piggy-back", "first.txt", []byte("piggyback-1\n"))
	doRoundtrip("second piggy-back", "second.txt", []byte("piggyback-2\n"))
}

// TestPostAuthAction wires a FuncAction into RelayServer and verifies it runs
// against the captured upstream session.
func TestPostAuthAction(t *testing.T) {
	const (
		user     = "bob"
		password = "Letmein!"
		domain   = "WORKGROUP"
		share    = "data"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	up := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	up.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	upL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen up: %v", err)
	}
	upCh := make(chan error, 1)
	go func() { upCh <- up.Serve(upL) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = up.Shutdown(ctx)
		<-upCh
	}()

	var actionFired atomic.Bool
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			Targets:    []string{"smb://" + upL.Addr().String()},
			PostAuthActions: []relay.PostAuthAction{
				relay.FuncAction{
					NameStr: "smoke",
					Fn: func(_ context.Context, conn *smb.Connection, cred *relay.Credential, _ server.Logger) error {
						if conn == nil {
							return fmt.Errorf("nil conn")
						}
						if cred == nil || cred.Username != user {
							return fmt.Errorf("wrong cred")
						}
						actionFired.Store(true)
						return nil
					},
				},
			},
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
	relayAddr := rs.SMBAddr().(*net.TCPAddr)

	clientOpts := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		User:              user,
		Password:          password,
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	_, _ = smb.NewConnection(clientOpts)

	if !waitFor(2*time.Second, actionFired.Load) {
		t.Fatalf("PostAuthAction did not fire")
	}
}

// TestSocksUserRouting verifies that when two pooled sessions for the same
// target but different captured users are present, two SOCKS clients
// authenticating as those respective users each get routed to the correct
// pool entry. This is the regression test for the "always reuses first
// connection in pool" bug.
func TestSocksUserRouting(t *testing.T) {
	const (
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	// Single upstream server with two accounts.
	up := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain: domain,
				Accounts: map[string]*server.Account{
					"alice": {NTHash: ntHash},
					"bob":   {NTHash: ntHash},
				},
			},
		},
	}
	up.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	upL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	upCh := make(chan error, 1)
	go func() { upCh <- up.Serve(upL) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = up.Shutdown(ctx)
		<-upCh
	}()
	upAddr := upL.Addr().(*net.TCPAddr)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			SocksAddr:  "127.0.0.1:0",
			Targets:    []string{"smb://" + upAddr.String()},
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
	relayAddr := rs.SMBAddr().(*net.TCPAddr)
	socksAddr := rs.SocksAddr().(*net.TCPAddr)

	// Two bait connections — one per user — both land in the pool against
	// the same upstream target.
	for _, u := range []string{"alice", "bob"} {
		bait := smb.Options{
			Host:              relayAddr.IP.String(),
			Port:              relayAddr.Port,
			User:              u,
			Password:          password,
			Domain:            domain,
			Initiator:         &spnego.NTLMInitiator{User: u, Password: password, Domain: domain},
			DisableSigning:    true,
			DisableEncryption: true,
			ForceSMB2:         true,
			DialTimeout:       2 * time.Second,
		}
		_, _ = smb.NewConnection(bait)
	}
	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 2 }) {
		t.Fatalf("expected 2 pooled sessions, got %d", len(rs.Snapshot()))
	}

	// Each user drops a file via SOCKS. The SOCKS server must route alice
	// onto the alice-pool-entry and bob onto the bob-pool-entry. We verify
	// by writing a per-user file and reading it back through the SAME pool
	// entry (the file name encodes the user). If routing were broken (e.g.
	// both clients land on alice's session), the read for bob would either
	// fail or return alice's content.
	drop := func(user, body string) error {
		opts := smb.Options{
			Host:              upAddr.IP.String(),
			Port:              upAddr.Port,
			User:              user,
			Password:          "ignored",
			Domain:            domain,
			Initiator:         &spnego.NTLMInitiator{User: user, Password: "ignored", Domain: domain},
			DisableSigning:    true,
			DisableEncryption: true,
			ForceSMB2:         true,
			DialTimeout:       2 * time.Second,
			ProxyDialer:       &fixedSocksDialer{socksAddr: socksAddr.String(), target: upAddr.String()},
		}
		conn, err := smb.NewConnection(opts)
		if err != nil {
			return fmt.Errorf("NewConnection: %w", err)
		}
		defer conn.Close()
		if err := conn.TreeConnect(share); err != nil {
			return fmt.Errorf("TreeConnect: %w", err)
		}
		defer conn.TreeDisconnect(share)
		off := 0
		buf := []byte(body)
		if err := conn.PutFile(share, user+".txt", 0, func(b []byte) (int, error) {
			if off >= len(buf) {
				return 0, io.EOF
			}
			n := copy(b, buf[off:])
			off += n
			return n, nil
		}); err != nil {
			return fmt.Errorf("PutFile: %w", err)
		}
		var got []byte
		if err := conn.RetrieveFile(share, user+".txt", 0, func(b []byte) (int, error) {
			got = append(got, b...)
			return len(b), nil
		}); err != nil {
			return fmt.Errorf("RetrieveFile: %w", err)
		}
		if string(got) != body {
			return fmt.Errorf("body mismatch: got %q want %q", got, body)
		}
		return nil
	}

	if err := drop("alice", "from-alice"); err != nil {
		t.Errorf("alice via SOCKS: %v", err)
	}
	if err := drop("bob", "from-bob"); err != nil {
		t.Errorf("bob via SOCKS: %v", err)
	}

	// A SOCKS client claiming an unmatched user should be rejected at
	// SessionSetup with LOGON_FAILURE.
	bogusOpts := smb.Options{
		Host:              upAddr.IP.String(),
		Port:              upAddr.Port,
		User:              "nobody",
		Password:          "ignored",
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: "nobody", Password: "ignored", Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
		ProxyDialer:       &fixedSocksDialer{socksAddr: socksAddr.String(), target: upAddr.String()},
	}
	if _, err := smb.NewConnection(bogusOpts); err == nil {
		t.Errorf("expected unmatched-user SOCKS auth to fail, got success")
	}
}

// fixedSocksDialer is a proxy.Dialer that ignores the requested address and
// always asks the SOCKS server to CONNECT to the configured fixed target.
// Used in the test so smb.NewConnection's TCP dial lands on the SOCKS-fronted
// upstream session without us having to plumb the target through to it.
type fixedSocksDialer struct {
	socksAddr string
	target    string
}

func (d *fixedSocksDialer) Dial(_, _ string) (net.Conn, error) {
	return socks5Connect(d.socksAddr, d.target)
}

// DialContext is required by smb.NewConnection (asserts proxy.ContextDialer).
func (d *fixedSocksDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return socks5Connect(d.socksAddr, d.target)
}

// socks5Connect performs a minimal RFC 1928 CONNECT handshake against the
// SOCKS5 server at proxy and returns the established connection.
func socks5Connect(proxy, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxy, 2*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial socks: %w", err)
	}
	// Greet: VER=5 NMETHODS=1 NoAuth=0
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		c.Close()
		return nil, err
	}
	hdr := make([]byte, 2)
	if _, err := readFull(c, hdr); err != nil {
		c.Close()
		return nil, fmt.Errorf("read greeting: %w", err)
	}
	if hdr[0] != 0x05 || hdr[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("unexpected greeting reply % x", hdr)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := c.Write(req); err != nil {
		c.Close()
		return nil, err
	}
	resp := make([]byte, 4)
	if _, err := readFull(c, resp); err != nil {
		c.Close()
		return nil, fmt.Errorf("read connect reply: %w", err)
	}
	if resp[1] != 0x00 {
		c.Close()
		return nil, fmt.Errorf("socks reply status 0x%02x", resp[1])
	}
	// Drain BND.ADDR (depends on ATYP) + BND.PORT.
	switch resp[3] {
	case 0x01:
		_, err = readFull(c, make([]byte, 4))
	case 0x04:
		_, err = readFull(c, make([]byte, 16))
	case 0x03:
		l := make([]byte, 1)
		if _, err = readFull(c, l); err == nil {
			_, err = readFull(c, make([]byte, l[0]))
		}
	}
	if err == nil {
		_, err = readFull(c, make([]byte, 2))
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func readFull(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}
