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

package server_test

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestSendCancelKeepsConnectionAlive drives the client's SMB2 CANCEL against
// the server. A CANCEL deliberately reuses the MessageId of the request it
// cancels (MS-SMB2 §2.2.30), so the server must exempt it from duplicate-
// MessageId detection (§3.3.5.2.3) instead of treating the reuse as a sequence
// violation and dropping the connection. The client sends a cancel for an
// already-completed (and therefore already-seen) MessageId; the connection must
// survive and continue to serve a subsequent file round-trip.
func TestSendCancelKeepsConnectionAlive(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "files"
		filename = "after-cancel.txt"
	)
	payload := []byte("connection survived the cancel\n")
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{
		Type: smb.ShareTypeDisk,
		VFS:  memvfs.New(memvfs.Options{}),
	})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}

	// MessageId 1 was consumed during the negotiate/session-setup handshake, so
	// the server has already seen it. A cancel that reuses it must not trip the
	// duplicate-MessageId guard.
	if err := c.SendCancel(1, 0); err != nil {
		t.Fatalf("SendCancel: %v", err)
	}

	// Prove the socket is still alive with a real round-trip.
	src := bytes.NewReader(payload)
	err = c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	})
	if err != nil {
		t.Fatalf("PutFile after cancel failed — connection did not survive: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		return got.Write(b)
	}); err != nil {
		t.Fatalf("RetrieveFile after cancel: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Errorf("round-trip payload = %q, want %q", got.Bytes(), payload)
	}
}
