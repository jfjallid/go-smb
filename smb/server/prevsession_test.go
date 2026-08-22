// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"encoding/binary"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/spnego"
)

// TestPreviousSessionEviction drives two back-to-back SessionSetups with
// the second one carrying PreviousSessionID = first session's ID, and
// verifies the first session is evicted from the server's tracking once
// the second one authenticates successfully (MS-SMB2 §3.3.5.5.3 step 13).
//
// The in-tree client does not expose PreviousSessionID on Options, so we
// inject it via OnRawRequest after the second connection's NegotiateProtocol
// completes — patching the SessionSetup1Req body at body-offset 16 (packet
// offset 80) before dispatch sees it.
func TestPreviousSessionEviction(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var capturedConn atomic.Pointer[server.Conn]
	var firstSessionID atomic.Uint64
	var secondSessionID atomic.Uint64
	var prevSessionToInject atomic.Uint64

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				// On the second connection, patch the PreviousSessionID
				// field of the first SessionSetup leg (NegTokenInit blob
				// starts with 0x60). Body starts at packet offset 64;
				// PreviousSessionID is at body offset 16 (packet 80).
				prev := prevSessionToInject.Load()
				if prev == 0 || capturedConn.Load() == c {
					return false, nil
				}
				if len(raw) < 88 || string(raw[0:4]) != smb.ProtocolSmb2 {
					return false, nil
				}
				cmd := binary.LittleEndian.Uint16(raw[12:14])
				if cmd != smb.CommandSessionSetup {
					return false, nil
				}
				// Only patch leg 1 (NegTokenInit, 0x60 tag in the blob).
				blobOff := int(binary.LittleEndian.Uint16(raw[64+12 : 64+14]))
				if blobOff == 0 || blobOff >= len(raw) {
					return false, nil
				}
				if raw[blobOff] != 0x60 {
					return false, nil
				}
				binary.LittleEndian.PutUint64(raw[80:88], prev)
				return false, nil
			},
			OnSessionSetup: func(c *server.Conn, s *server.Session, blob []byte, stage server.SessionSetupStage) (*server.Status, error) {
				if stage == server.SessionSetupStageAuthenticate {
					if firstSessionID.Load() == 0 {
						firstSessionID.Store(s.ID)
						capturedConn.Store(c)
					} else if secondSessionID.Load() == 0 {
						secondSessionID.Store(s.ID)
					}
				}
				return nil, nil
			},
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:           "127.0.0.1",
		Port:           addr.Port,
		Initiator:      &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning: true,
		Encryption:     smb.EncryptionDisabled,
		Dialects:       smb.DialectsSMB2Only,
		DialTimeout:    2 * time.Second,
	}
	c1, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("first NewConnection: %v", err)
	}
	defer c1.Close()
	if firstSessionID.Load() == 0 {
		t.Fatalf("first SessionSetup did not observe an authenticate stage")
	}

	// Arm the patcher with the first session's ID, then open a second
	// connection. Its SessionSetup1 body gets PreviousSessionID injected.
	prevSessionToInject.Store(firstSessionID.Load())
	c2, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("second NewConnection: %v", err)
	}
	defer c2.Close()
	if secondSessionID.Load() == 0 {
		t.Fatalf("second SessionSetup did not observe an authenticate stage")
	}

	// Confirm the first session was evicted: the captured Conn no longer
	// has a Session under firstSessionID.
	cConn := capturedConn.Load()
	if cConn == nil {
		t.Fatalf("no Conn captured")
	}
	if got := cConn.RemoveSession(firstSessionID.Load()); got != nil {
		t.Errorf("first session %d still alive on its Conn after PreviousSessionID eviction", firstSessionID.Load())
	}
}
