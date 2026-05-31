// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
)

// TestShareWritableUsersGate asserts the per-account write gate on Share:
// alice (in WritableUsers) can put + retrieve a file, while bob (not in
// WritableUsers) can read alice's file but is denied any mutation.
func TestShareWritableUsersGate(t *testing.T) {
	const (
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "shared.txt"
	)
	payload := []byte("alice wrote this\n")
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
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
	srv.RegisterShare(share, server.Share{
		Type:          smb.ShareTypeDisk,
		VFS:           memvfs.New(memvfs.Options{}),
		WritableUsers: map[string]bool{"alice": true},
	})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	// Alice writes.
	alice := dialClient(t, addr.Port, "alice", password, domain)
	defer alice.Close()
	src := bytes.NewReader(payload)
	if err := alice.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("alice PutFile: %v", err)
	}

	// Bob reads — should succeed.
	bob := dialClient(t, addr.Port, "bob", password, domain)
	defer bob.Close()
	var got bytes.Buffer
	if err := bob.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("bob RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("bob read mismatch: got %q want %q", got.String(), string(payload))
	}

	// Bob tries to overwrite — should be denied at handleCreate (FileSupersede
	// is the disposition PutFile uses).
	src2 := bytes.NewReader([]byte("bob is here"))
	err := bob.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src2.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	})
	if err == nil {
		t.Fatal("bob PutFile: expected access-denied error, got nil")
	}
	if !errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) && !strings.Contains(err.Error(), "ACCESS_DENIED") {
		t.Fatalf("bob PutFile: expected access-denied, got %v", err)
	}

	// Bob tries to delete — should be denied. DeleteFile uses Create with
	// FILE_DELETE_ON_CLOSE.
	if err := bob.DeleteFile(share, filename); err == nil {
		t.Fatal("bob DeleteFile: expected access-denied, got nil")
	}

	// Verify the file still has alice's content.
	got.Reset()
	if err := bob.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("post-deny RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("file mutated despite denial: got %q want %q", got.String(), string(payload))
	}
}

// TestShareWritableUsersDefaultsToOpen asserts that a nil WritableUsers map
// preserves the historical default: every authenticated user can write.
func TestShareWritableUsersDefaultsToOpen(t *testing.T) {
	const (
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "f.txt"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
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
	// WritableUsers is nil — both users may write.
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	for _, user := range []string{"alice", "bob"} {
		c := dialClient(t, addr.Port, user, password, domain)
		body := []byte(user + " was here")
		src := bytes.NewReader(body)
		if err := c.PutFile(share, user+".txt", 0, func(buf []byte) (int, error) {
			n, err := src.Read(buf)
			if err == io.EOF && n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}); err != nil {
			t.Fatalf("%s PutFile: %v", user, err)
		}
		c.Close()
	}
}
