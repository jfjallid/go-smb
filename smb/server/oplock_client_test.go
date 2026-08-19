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

// TestUnsignedOplockBreakAcceptedOnSignedSession: an unsolicited oplock break
// arrives on the reserved MessageId without SMB2_FLAGS_SIGNED, and the client
// must handle it rather than treat it as a signing violation.
//
// MS-SMB2 §3.3.4.1 requires the server to sign a response to a signed request;
// a break notification answers no request, and Windows Server sends it
// unsigned even on a signing-required session. The client used to enforce
// "signed or die" on every non-pending PDU, so the first break killed the
// connection and the oplock path was unreachable against a real server.
//
// The break is injected from the OnEcho hook because go-smb's own server never
// grants an oplock and so never breaks one on its own.
func TestUnsignedOplockBreakAcceptedOnSignedSession(t *testing.T) {
	const (
		user     = "alice"
		password = "Passw0rd!"
		domain   = "CORP"
		share    = "files"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	fileID := make([]byte, 16)
	for i := range fileID {
		fileID[i] = byte(i + 1)
	}

	// The client drops any PDU whose SessionID does not match its own, so the
	// injected break has to carry the real one.
	var sessionID atomic.Uint64

	srv := &server.Server{
		Config: &server.ServerConfig{
			SigningRequired: true,
			OnSessionSetup: func(_ *server.Conn, s *server.Session, _ []byte, _ server.SessionSetupStage) (*server.Status, error) {
				if s != nil {
					sessionID.Store(s.ID)
				}
				return nil, nil
			},
			OnEcho: func(c *server.Conn) error {
				// Build an unsolicited, unsigned OPLOCK_BREAK exactly as
				// Windows does: reserved MessageId, no SIGNED flag.
				nb := smb.OplockBreak{
					Header: smb.Header{
						ProtocolID:    []byte(smb.ProtocolSmb2),
						StructureSize: 64,
						Command:       smb.CommandOplockBreak,
						Flags:         smb.SMB2_FLAGS_SERVER_TO_REDIR,
						MessageID:     0xFFFFFFFFFFFFFFFF,
						SessionID:     sessionID.Load(),
						Signature:     make([]byte, 16),
					},
					StructureSize: 24,
					OplockLevel:   smb.OpLockLevelII,
					FileId:        fileID,
				}
				buf, err := nb.MarshalBinary()
				if err != nil {
					return err
				}
				return c.SendUnsignedForTest(buf)
			},
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

	if !c.IsSigningRequired() {
		t.Fatal("session is not signed; the test would not exercise the signing gate")
	}

	got := make(chan byte, 1)
	c.SetOplockBreakHandler(func(_ *smb.Connection, nb smb.OplockBreak) byte {
		select {
		case got <- nb.OplockLevel:
		default:
		}
		return smb.OpLockLevelNone
	})

	// The Echo triggers the injected break.
	if err := c.Echo(); err != nil {
		t.Fatalf("Echo: %v", err)
	}

	select {
	case level := <-got:
		if level != smb.OpLockLevelII {
			t.Errorf("break level = %d, want %d", level, smb.OpLockLevelII)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("oplock break was never delivered to the handler")
	}

	// The connection must still be usable: rejecting the break used to tear it
	// down, so a second round trip is the real assertion here.
	if err := c.Echo(); err != nil {
		t.Errorf("connection unusable after an unsigned oplock break: %v", err)
	}
}
