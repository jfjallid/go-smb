// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestFileRoundTrip drives the in-tree client through Create -> Write
// -> Close -> Create -> Read -> Close against a memvfs-backed share, then
// verifies the bytes round-trip.
func TestFileRoundTrip(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "hello.txt"
	)
	payload := []byte("hello from the server\n")
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	// PutFile: Create(write) + Write + Close.
	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	// RetrieveFile: Create(read) + Read + Close.
	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch: got %q want %q", got.String(), string(payload))
	}
}

// TestFileRoundTripFileVFS mirrors TestFileRoundTrip but uses
// the file-backed VFS so the dispatch path is exercised against a real
// host filesystem.
func TestFileRoundTripFileVFS(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "hello.txt"
	)
	payload := []byte("hello from filevfs\n")
	ntHash := ntlmssp.Ntowfv1(password)

	root := t.TempDir()
	fsBackend, err := filevfs.New(filevfs.Options{Root: root})
	if err != nil {
		t.Fatalf("filevfs.New: %v", err)
	}

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: fsBackend})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	// File should now exist on disk.
	gotDisk, err := os.ReadFile(filepath.Join(root, filename))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(gotDisk, payload) {
		t.Fatalf("disk mismatch: got %q want %q", gotDisk, payload)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch: got %q want %q", got.String(), string(payload))
	}
}

// TestListAndDelete drives the client through PutFile -> ListDirectory
// -> DeleteFile -> ListDirectory and verifies the file disappears from the
// directory listing after delete.
func TestListAndDelete(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	// Put two files.
	for _, name := range []string{"a.txt", "b.txt"} {
		body := []byte("body of " + name)
		src := bytes.NewReader(body)
		if err := c.PutFile(share, name, 0, func(buf []byte) (int, error) {
			n, err := src.Read(buf)
			if err == io.EOF && n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}); err != nil {
			t.Fatalf("PutFile %s: %v", name, err)
		}
	}

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}
	defer c.TreeDisconnect(share)

	files, err := c.ListDirectory(share, "", "*")
	if err != nil {
		t.Fatalf("ListDirectory: %v", err)
	}
	names := make(map[string]bool)
	for _, f := range files {
		names[f.Name] = true
	}
	if !names["a.txt"] || !names["b.txt"] {
		t.Fatalf("ListDirectory: missing file; got %v", names)
	}

	if err := c.DeleteFile(share, "a.txt"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	files, err = c.ListDirectory(share, "", "*")
	if err != nil {
		t.Fatalf("ListDirectory after delete: %v", err)
	}
	names = make(map[string]bool)
	for _, f := range files {
		names[f.Name] = true
	}
	if names["a.txt"] {
		t.Errorf("a.txt still present after delete: %v", names)
	}
	if !names["b.txt"] {
		t.Errorf("b.txt missing: %v", names)
	}
}

// dialClient wires up a standard NTLMSSP client connection to the test server.
func dialClient(t *testing.T, port int, user, password, domain string) *smb.Connection {
	t.Helper()
	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              port,
		User:              user,
		Password:          password,
		Domain:            domain,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		ForceSMB2:         true,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	return c
}
