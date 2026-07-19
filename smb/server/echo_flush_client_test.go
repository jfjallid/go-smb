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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestEchoAndFlushClient exercises the client ECHO keepalive (MS-SMB2 §2.2.28)
// and FLUSH (§2.2.17) against the server. The ECHO must round-trip and fire the
// server's OnEcho hook; the FLUSH on an open, written handle must succeed.
func TestEchoAndFlushClient(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "files"
		filename = "flushme.txt"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var echoed atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			OnEcho: func(_ *server.Conn) error { echoed.Store(true); return nil },
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

	// ECHO keepalive.
	if err := c.Echo(); err != nil {
		t.Fatalf("Echo: %v", err)
	}
	if !echoed.Load() {
		t.Errorf("server OnEcho hook did not fire")
	}

	// FLUSH on a written handle.
	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}
	f, err := c.OpenFileExt(share, filename, &smb.CreateReqOpts{
		ImpersonationLevel: smb.ImpersonationLevelImpersonation,
		DesiredAccess:      smb.FAccMaskFileReadData | smb.FAccMaskFileWriteData | smb.FAccMaskSynchronize,
		ShareAccess:        smb.FileShareRead | smb.FileShareWrite,
		CreateDisp:         smb.FileOverwriteIf,
		CreateOpts:         smb.FileNonDirectoryFile,
	})
	if err != nil {
		t.Fatalf("OpenFileExt: %v", err)
	}
	defer f.CloseFile()

	if _, err := f.WriteFile([]byte("durable bytes\n"), 0); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := f.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}
