// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"net"
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

// TestRelayClientEndToEnd boots an upstream server with a known account and
// a registered share, runs RelayClient pointed at it, drives a client through
// the relay listener with the matching credentials, and verifies that the
// returned *smb.Connection can TreeConnect against the upstream's share.
func TestRelayClientEndToEnd(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	// Upstream: real auth + real share.
	up := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	up.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	upAddr, upShutdown := startUpstream(t, up)
	defer upShutdown()

	// Pick a free port for the relay listener.
	relayLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen relay: %v", err)
	}
	relayAddr := relayLn.Addr().(*net.TCPAddr)
	_ = relayLn.Close()

	// RelayClient runs in a goroutine; the test client drives the inbound side.
	type relayResult struct {
		conn *smb.Connection
		cred *relay.Credential
		err  error
	}
	relayCh := make(chan relayResult, 1)

	var hookFired atomic.Bool
	go func() {
		c, cred, err := relay.RelayClient(relay.ClientConfig{
			ListenAddr: relayAddr.String(),
			Target:     upAddr.String(),
			OnCredentialCaptured: func(_ *server.Conn, _ *relay.Credential) {
				hookFired.Store(true)
			},
			Timeout: 10 * time.Second,
		})
		relayCh <- relayResult{c, cred, err}
	}()

	// Give the listener a moment to bind. The relay binds synchronously
	// inside RelayClient before its first auth-handler call; a tiny sleep
	// here keeps the test from racing the goroutine.
	if err := waitForListen(relayAddr.String(), 2*time.Second); err != nil {
		t.Fatalf("relay listener never came up: %v", err)
	}

	// Drive an inbound client through the relay. Force SMB 2.1 to match the
	// relay listener's default cap.
	clientOpts := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	// We expect this to fail (capture-and-drop returns LogonFailure to the
	// relayed client) — but the upstream auth must have succeeded.
	_, _ = smb.NewConnection(clientOpts)

	var rr relayResult
	select {
	case rr = <-relayCh:
	case <-time.After(10 * time.Second):
		t.Fatalf("RelayClient did not return within 10s")
	}
	if rr.err != nil {
		t.Fatalf("RelayClient: %v", rr.err)
	}
	if rr.conn == nil {
		t.Fatalf("RelayClient returned nil connection")
	}
	defer rr.conn.Close()

	if rr.cred == nil {
		t.Fatalf("RelayClient returned nil Credential")
	}
	if rr.cred.Username != user {
		t.Errorf("Credential.Username: got %q want %q", rr.cred.Username, user)
	}
	if !hookFired.Load() {
		t.Errorf("OnCredentialCaptured did not fire")
	}

	// The returned connection should be authenticated against the upstream.
	if err := rr.conn.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect on relayed connection: %v", err)
	}
	defer rr.conn.TreeDisconnect(share)
}

// startUpstream is local to this test package so we don't depend on the
// (unexported) helper in smb/server. Runs srv on an ephemeral port; returns
// addr + shutdown.
func startUpstream(t *testing.T, srv *server.Server) (*net.TCPAddr, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	return l.Addr().(*net.TCPAddr), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if e := <-serveErr; e != nil && e != server.ErrServerClosed {
			t.Errorf("upstream Serve: %v", e)
		}
	}
}

// waitForListen polls addr until a Dial succeeds or timeout elapses.
func waitForListen(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
