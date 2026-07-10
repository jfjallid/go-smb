// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestFakeServerRoundTrip stands up an upstream SMB server, points a
// RelayServer at it with FakeServer enabled against a temp directory, and
// drives a victim SMB client through the relay. After the upstream relay
// succeeds the relay must answer the victim with StatusOk + SessionFlagIsGuest
// instead of the capture-and-drop StatusLogonFailure; the victim then
// TreeConnects to the configured fake share, writes a file, reads it back,
// and the on-disk root reflects the write.
func TestFakeServerRoundTrip(t *testing.T) {
	const (
		user     = "victim"
		password = "P@ssw0rd!"
		domain   = "WORKGROUP"
		upShare  = "test"
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
	up.RegisterShare(upShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
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

	fakeRoot := t.TempDir()
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			Targets:    []string{"smb://" + upL.Addr().String()},
			FakeServer: &relay.FakeServerOptions{
				ShareName: "loot",
				Root:      fakeRoot,
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

	opts := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	conn, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("victim NewConnection: %v", err)
	}
	defer conn.Close()
	if !conn.IsGuestSession() {
		t.Errorf("expected guest session flag on victim connection, got false")
	}

	if !waitFor(2*time.Second, func() bool { return len(rs.Snapshot()) >= 1 }) {
		t.Fatalf("upstream session never pooled (have %d)", len(rs.Snapshot()))
	}

	if err := conn.TreeConnect("loot"); err != nil {
		t.Fatalf("victim TreeConnect %q: %v", "loot", err)
	}
	defer conn.TreeDisconnect("loot")

	body := []byte("planted by victim via fake server\n")
	off := 0
	if err := conn.PutFile("loot", "drop.txt", 0, func(buf []byte) (int, error) {
		if off >= len(body) {
			return 0, io.EOF
		}
		n := copy(buf, body[off:])
		off += n
		return n, nil
	}); err != nil {
		t.Fatalf("victim PutFile: %v", err)
	}

	var got []byte
	if err := conn.RetrieveFile("loot", "drop.txt", 0, func(b []byte) (int, error) {
		got = append(got, b...)
		return len(b), nil
	}); err != nil {
		t.Fatalf("victim RetrieveFile: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("RetrieveFile body=%q want %q", got, body)
	}

	// The file must exist on disk at the configured root.
	onDisk, err := os.ReadFile(filepath.Join(fakeRoot, "drop.txt"))
	if err != nil {
		t.Fatalf("read on-disk drop.txt: %v", err)
	}
	if string(onDisk) != string(body) {
		t.Errorf("on-disk drop.txt=%q want %q", onDisk, body)
	}
}

// TestFakeServerReadOnly verifies that -fake-server-read-only=true blocks
// writes (the victim's TreeConnect still succeeds, but PutFile fails with
// access denied).
func TestFakeServerReadOnly(t *testing.T) {
	const (
		user     = "victim"
		password = "P@ssw0rd!"
		domain   = "WORKGROUP"
		upShare  = "test"
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
	up.RegisterShare(upShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
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

	fakeRoot := t.TempDir()
	// Pre-seed a readable file so we can exercise read access on the share.
	if err := os.WriteFile(filepath.Join(fakeRoot, "seed.txt"), []byte("seeded"), 0o644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			ListenAddr: "127.0.0.1:0",
			Targets:    []string{"smb://" + upL.Addr().String()},
			FakeServer: &relay.FakeServerOptions{
				ShareName: "loot",
				Root:      fakeRoot,
				ReadOnly:  true,
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

	opts := smb.Options{
		Host:              relayAddr.IP.String(),
		Port:              relayAddr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	conn, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("victim NewConnection: %v", err)
	}
	defer conn.Close()
	if err := conn.TreeConnect("loot"); err != nil {
		t.Fatalf("victim TreeConnect: %v", err)
	}
	defer conn.TreeDisconnect("loot")

	// Read the seed file: must succeed.
	var got []byte
	if err := conn.RetrieveFile("loot", "seed.txt", 0, func(b []byte) (int, error) {
		got = append(got, b...)
		return len(b), nil
	}); err != nil {
		t.Fatalf("victim RetrieveFile seed.txt: %v", err)
	}
	if string(got) != "seeded" {
		t.Errorf("seed.txt body=%q want %q", got, "seeded")
	}

	// Write attempt: must fail. filevfs.ReadOnly returns StatusAccessDenied
	// on Create with write intent, which smb.PutFile surfaces as an error.
	body := []byte("should not land")
	off := 0
	err = conn.PutFile("loot", "nope.txt", 0, func(buf []byte) (int, error) {
		if off >= len(body) {
			return 0, io.EOF
		}
		n := copy(buf, body[off:])
		off += n
		return n, nil
	})
	if err == nil {
		t.Errorf("PutFile on read-only fake share unexpectedly succeeded")
	}
	if _, statErr := os.Stat(filepath.Join(fakeRoot, "nope.txt")); statErr == nil {
		t.Errorf("read-only fake share leaked write to disk at nope.txt")
	}
}
