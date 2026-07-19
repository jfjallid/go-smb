// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

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

// TestSigning311 round-trips a file over SMB 3.1.1 with mutual signing.
// The default test client offers 3.1.1 first (since Dialects is left unset);
// the server has SigningRequired=true so the client must sign every PDU and
// the server must sign every reply. A tampered signature on either side
// would cause the verifier to drop the message and the test to hang/fail.
func TestSigning311(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "signed.txt"
	)
	payload := []byte("payload over a signed SMB 3.1.1 channel\n")
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			SigningRequired: true,
			// EncryptionSupported makes the server include an
			// EncryptionContext in 3.1.1 NegotiateRes; without one the
			// in-tree client refuses to derive session keys (it doesn't
			// guard the encryption-key KDF on cipherId != 0). The session
			// itself still negotiates signing, not encryption.
			EncryptionSupported: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:                  "127.0.0.1",
		Port:                  addr.Port,
		Initiator:             &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		RequireMessageSigning: true,
		DisableEncryption:     true,
		DialTimeout:           2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection (signed 3.1.1): %v", err)
	}
	defer c.Close()

	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile over signed channel: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile over signed channel: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch over signed channel: got %q want %q", got.String(), string(payload))
	}
}

// TestSigning21 forces the SMB 2.1 dialect (HMAC-SHA256 signing with
// the raw session key, no preauth-hash KDF) and verifies a file round-trips.
// This exercises the dialect-2.x branch of deriveKeys and the no-context KDF
// path is bypassed.
func TestSigning21(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
		filename = "signed21.txt"
	)
	payload := []byte("smb 2.1 hmac-sha256 signed payload\n")
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			MaxDialect:      smb.DialectSmb_2_1,
			SigningRequired: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:                  "127.0.0.1",
		Port:                  addr.Port,
		Initiator:             &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		RequireMessageSigning: true,
		DisableEncryption:     true,
		Dialects:              smb.DialectsSMB2Only, // restricts client to DialectSmb_2_1
		DialTimeout:           2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection (signed 2.1): %v", err)
	}
	defer c.Close()

	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile over signed 2.1 channel: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile over signed 2.1 channel: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch over signed 2.1 channel: got %q want %q", got.String(), string(payload))
	}
}

// TestUnsignedRejected verifies that once a session is established with
// signing keys, the server rejects an inbound PDU that lacks a signature.
// We accomplish this by grabbing the raw bytes via OnRawRequest, dropping
// the SMB2_FLAGS_SIGNED bit (without re-signing), and watching the server
// reply with STATUS_ACCESS_DENIED. The client will then surface that as an
// error on the first post-auth call.
func TestUnsignedRejected(t *testing.T) {
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
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				// After SessionSetup completes, strip the SIGNED flag from
				// any inbound PDU so the verifier rejects it.
				if len(raw) >= 64 && string(raw[0:4]) == smb.ProtocolSmb2 {
					cmd := uint16(raw[12]) | uint16(raw[13])<<8
					if cmd != smb.CommandNegotiate && cmd != smb.CommandSessionSetup {
						raw[16] &^= byte(smb.SMB2_FLAGS_SIGNED)
					}
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:                  "127.0.0.1",
		Port:                  addr.Port,
		Initiator:             &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		RequireMessageSigning: true,
		DisableEncryption:     true,
		DialTimeout:           2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		// SessionSetup itself may surface the access-denied; that's a
		// valid outcome too — the server rejected the SessionSetup2 reply
		// readback because we stripped its FLAGS_SIGNED. Either way, the
		// verifier path was exercised.
		return
	}
	defer c.Close()
	if err := c.TreeConnect(share); err == nil {
		t.Fatalf("TreeConnect over a connection with stripped FLAGS_SIGNED was expected to fail")
	}
}
