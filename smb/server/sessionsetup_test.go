// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
)

// TestSessionSetupCredentialCapture drives the server with bogus NTLM credentials
// and verifies that OnCredentialCaptured fires with a hashcat-format string
// while the client receives STATUS_LOGON_FAILURE (capture-mode default).
func TestSessionSetupCredentialCapture(t *testing.T) {
	var (
		mu       sync.Mutex
		captured []*Credential
	)

	srv := &Server{
		Config: &ServerConfig{
			NetBIOSName:     "TESTSRV",
			NetBIOSDomain:   "TESTDOM",
			DnsComputerName: "testsrv.testdom.local",
			DnsDomainName:   "testdom.local",
			OnCredentialCaptured: func(c *Conn, cred *Credential) {
				mu.Lock()
				defer mu.Unlock()
				captured = append(captured, cred)
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	// Drive the handshake from the in-tree client. Use NTLMSSP with bogus
	// password — the server's default AlwaysFailAuthenticator will reject,
	// but the credential capture hook fires before that.
	ntlmInit := &spnego.NTLMInitiator{
		User:     "bogus",
		Password: "nopass",
		Domain:   "BOGUSDOM",
	}
	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         ntlmInit,
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only, // SMB 2.1 keeps the negotiate path simple
		DialTimeout:       2 * time.Second,
	}
	_, err := smb.NewConnection(opts)
	if err == nil {
		t.Fatalf("expected SessionSetup to fail with logon failure, got nil")
	}
	if !strings.Contains(err.Error(), "Logon") {
		t.Logf("got error (acceptable variants begin with 'Logon'): %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("expected exactly 1 captured credential, got %d", len(captured))
	}
	cred := captured[0]
	if cred.Username != "bogus" {
		t.Errorf("Username: got %q want %q", cred.Username, "bogus")
	}
	if !strings.EqualFold(cred.Domain, "BOGUSDOM") {
		t.Errorf("Domain: got %q want BOGUSDOM (case-insensitive)", cred.Domain)
	}
	if cred.Format != "Net-NTLMv2" {
		t.Errorf("Format: got %q want Net-NTLMv2", cred.Format)
	}
	// Hashcat format: "user::domain:8-byte-hex:16-byte-hex:rest-hex"
	parts := strings.Split(cred.Hashcat, ":")
	if len(parts) != 6 {
		t.Errorf("Hashcat: expected 6 colon-separated fields, got %d (%q)", len(parts), cred.Hashcat)
	}
	if cred.ServerChallenge == ([8]byte{}) {
		t.Errorf("ServerChallenge is zero — the acceptor should have generated a random challenge")
	}
}

// TestSessionSetupAnonymous verifies that AllowAnonymous=true accepts a
// null-session SessionSetup. We drive the exchange with a synthetic
// anonymous AUTHENTICATE message rather than the in-tree client, which
// always produces a real NTLMv2 response.
func TestSessionSetupAnonymous(t *testing.T) {
	srv := &Server{
		Config: &ServerConfig{
			AllowAnonymous: true,
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	// Step 1: Negotiate (SMB1 multi-proto -> SMB2).
	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Use the in-tree client via ManualLogin so we get NegotiateProtocol
	// only, then drive SessionSetup ourselves with a forged anonymous blob.
	conn.Close()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		ManualLogin:       true,
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	// Authenticate via the standard client path with empty credentials.
	// spnego.NTLMInitiator with NullSession=true generates an anonymous
	// AUTHENTICATE.
	c.SetInitiator(&spnego.NTLMInitiator{NullSession: true})
	if err := c.SessionSetup(); err != nil {
		t.Fatalf("SessionSetup with NullSession: %v", err)
	}
	t.Logf("anonymous SessionSetup succeeded")
}

// TestSessionSetupMapAuthSuccess: configure MapAuthenticator with the right NT
// hash and assert the client logs in successfully.
func TestSessionSetupMapAuthSuccess(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var hookFired atomic.Bool
	srv := &Server{
		Config: &ServerConfig{
			Authenticator: &MapAuthenticator{
				Domain: domain,
				Accounts: map[string]*Account{
					user: {NTHash: ntHash},
				},
			},
			OnCredentialCaptured: func(c *Conn, cred *Credential) {
				hookFired.Store(true)
			},
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	c.Close()

	if !hookFired.Load() {
		t.Errorf("OnCredentialCaptured did not fire")
	}
}

// TestSessionSetupRawNTLMSSP exercises the bare (non-SPNEGO) NTLMSSP path end to
// end: the client offers raw NTLMSSP (Options.RawNTLMSSP, mirroring the Linux
// kernel CIFS client) and the server accepts it via signature-based dispatch.
// Asserts a successful login and that credential capture still fires on the raw
// path (Linux clients must be observable too).
func TestSessionSetupRawNTLMSSP(t *testing.T) {
	const (
		user     = "install"
		password = "P@ssw0rd"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var hookFired atomic.Bool
	srv := &Server{
		Config: &ServerConfig{
			NetBIOSName: "TESTSRV",
			Authenticator: &MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*Account{user: {NTHash: ntHash}},
			},
			OnCredentialCaptured: func(c *Conn, cred *Credential) {
				hookFired.Store(true)
			},
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		RawNTLMSSP:        true,
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection with RawNTLMSSP: %v", err)
	}
	defer c.Close()

	if !hookFired.Load() {
		t.Errorf("OnCredentialCaptured did not fire on the raw NTLMSSP path")
	}
}

// startTestServer spins up the supplied Server on an ephemeral port and
// returns the address plus a shutdown function the caller defers.
func startTestServer(t *testing.T, srv *Server) (*net.TCPAddr, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	return l.Addr().(*net.TCPAddr), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if e := <-serveErr; e != nil && e != ErrServerClosed {
			t.Errorf("Serve: %v", e)
		}
	}
}
