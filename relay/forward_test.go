// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestSMBForwarderRawNTLMBoundary verifies the SMB forwarder's interface
// boundary: it accepts a raw NTLMSSP NEGOTIATE message (no SPNEGO) and
// returns a raw NTLMSSP CHALLENGE; it then accepts a raw NTLMSSP
// AUTHENTICATE plus an optional MechListMIC and produces a captured
// Credential matching the asserted user/domain.
//
// We drive this via the public RelayServer with a single SMB upstream and
// inspect the captured credential — exercising the forwarder's raw-NTLM
// boundary through the listener's SPNEGO-unwrap path.
func TestSMBForwarderRawNTLMBoundary(t *testing.T) {
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

	var capturedCred *relay.Credential
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			Targets:    []string{"smb://" + upAddr.String()},
			OnCredentialCaptured: func(_ *server.Conn, c *relay.Credential) {
				capturedCred = c
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

	// Drive an SMB victim auth with a real NegTokenInit. The relay's
	// onSessionSetup unwraps it to a raw NTLMSSP NEGOTIATE before handing
	// to the forwarder; the response path re-wraps the CHALLENGE. If the
	// forwarder boundary regressed (e.g. the listener forgot to unwrap) the
	// upstream SessionSetup1 would reject the bytes and pooling would fail.
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
		t.Fatalf("upstream never pooled — forwarder boundary likely broken")
	}
	if capturedCred == nil {
		t.Fatalf("no credential captured")
	}
	if capturedCred.Username != user || capturedCred.Domain != domain {
		t.Errorf("captured = %s\\%s, want %s\\%s", capturedCred.Domain, capturedCred.Username, domain, user)
	}
	// ServerChallenge must be the upstream's challenge (8 bytes set).
	zero := [8]byte{}
	if capturedCred.ServerChallenge == zero {
		t.Errorf("captured ServerChallenge is all-zero — upstream CHALLENGE parsing regressed")
	}
}

// TestSMBForwarderMICPassthrough covers the MIC plumbing: the relay accepts
// a NegTokenResp carrying a MechListMIC and (by default) forwards it through
// to the upstream. We can't directly inspect the upstream's view of the MIC
// in this test (the in-tree NTLM server validates a self-derived MIC, not
// the relayed one), but we can at least exercise that the StripMechListMIC
// toggle does not break the basic relay flow.
func TestSMBForwarderMICStripDoesNotBreakRelay(t *testing.T) {
	const (
		user     = "carol"
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

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr:       "127.0.0.1:0",
			Targets:          []string{"smb://" + upAddr.String()},
			StripMechListMIC: true,
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
		t.Fatalf("strip-mic broke the relay flow (no pooled session)")
	}
}
