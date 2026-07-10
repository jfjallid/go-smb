// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestCrossProtocolHTTPInboundToSMBUpstream verifies that an HTTP-inbound NTLM
// authentication can be relayed onto an SMB upstream. The relay's HTTP
// listener is the inbound side, an SMB server is the upstream, and the unified
// Targets list contains a single smb:// entry — the HTTP listener must
// successfully dispatch onto a forwarder that speaks SMB.
func TestCrossProtocolHTTPInboundToSMBUpstream(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
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

	var (
		credsMu sync.Mutex
		creds   []*relay.Credential
	)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			HTTPListenAddr: "127.0.0.1:0",
			Targets:        []string{"smb://" + upAddr.String()},
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

	// Drive an inbound NTLM-over-HTTP exchange. The victim's NTLM client
	// produces a NEGOTIATE/AUTHENTICATE pair valid against the SMB upstream
	// (NTLM is portable between transports).
	relayAddr := rs.HTTPAddr().(*net.TCPAddr).String()
	if status := driveHTTPNTLMVictim(t, relayAddr, user, password, domain); status != 401 {
		t.Errorf("victim final status = %d, want 401 (capture-and-drop)", status)
	}

	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 1 }) {
		t.Fatalf("cross-protocol HTTP→SMB never pooled (have %d)", len(rs.Snapshot()))
	}
	snap := rs.Snapshot()[0]
	if snap.Target != upAddr.String() {
		t.Errorf("pool entry target = %q, want %q", snap.Target, upAddr.String())
	}

	credsMu.Lock()
	defer credsMu.Unlock()
	if len(creds) == 0 {
		t.Fatalf("OnCredentialCaptured never fired")
	}
	if creds[0].Username != user || creds[0].Domain != domain {
		t.Errorf("cred = %s\\%s, want %s\\%s", creds[0].Domain, creds[0].Username, domain, user)
	}
}

// TestCrossProtocolSMBInboundToHTTPUpstream verifies that an SMB-inbound NTLM
// authentication can be relayed onto an HTTP upstream. The relay's SMB
// listener is the inbound side, a mock NTLM HTTP server is the upstream, and
// the unified Targets list contains a single http:// entry — the SMB listener
// must successfully dispatch onto an HTTP forwarder.
func TestCrossProtocolSMBInboundToHTTPUpstream(t *testing.T) {
	const (
		user     = "bob"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	up := newNtlmHTTPUpstream(t, user, domain, []byte("relay ok"))
	defer up.Stop()

	var (
		credsMu sync.Mutex
		creds   []*relay.Credential
	)

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			Targets:    []string{"http://" + up.Addr()},
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
	relayAddr := rs.SMBAddr().(*net.TCPAddr)

	// Drive an inbound SMB auth — the victim is an ordinary go-smb client.
	// capture-and-drop returns an error to the client; we ignore it.
	bait := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	_, _ = smb.NewConnection(bait)

	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 1 }) {
		t.Fatalf("cross-protocol SMB→HTTP never pooled (have %d)", len(rs.Snapshot()))
	}
	snap := rs.Snapshot()[0]
	if snap.Target != up.Addr() {
		t.Errorf("pool entry target = %q, want %q", snap.Target, up.Addr())
	}
	if up.authedConns.Load() == 0 {
		t.Errorf("HTTP upstream never saw a successful AUTHENTICATE")
	}

	credsMu.Lock()
	defer credsMu.Unlock()
	if len(creds) == 0 {
		t.Fatalf("OnCredentialCaptured never fired")
	}
	if creds[0].Username != user || creds[0].Domain != domain {
		t.Errorf("cred = %s\\%s, want %s\\%s", creds[0].Domain, creds[0].Username, domain, user)
	}
}
