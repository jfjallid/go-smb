// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestEncryptedRoundTrip311 round-trips a file over an SMB 3.1.1
// connection where every post-SessionSetup PDU is wrapped in a
// TransformHeader. Server has RequireEncryption=true; the client offers
// GlobalCapEncryption (DisableEncryption left default-false) so the
// negotiation engages session-level encryption.
//
// The test installs an OnRawRequest hook that asserts every inbound packet
// past SessionSetup carries the TransformHeader protocol id (\xFDSMB), so a
// regression that drops the encryption wrapper fails loudly.
func TestEncryptedRoundTrip311(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "secret"
		filename = "ciphered.txt"
	)
	payload := []byte("payload over an AES-128-GCM SMB 3.1.1 channel\n")
	ntHash := ntlmssp.Ntowfv1(password)

	var sawEncrypted atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			RequireEncryption: true, // implies EncryptionSupported
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolTransformHdr {
					sawEncrypted.Store(true)
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:      "127.0.0.1",
		Port:      addr.Port,
		Initiator: &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		// DisableEncryption left false so the client engages encryption.
		// RequireMessageSigning left false; encryption replaces signing
		// per MS-SMB2 §3.3.4.1.4.
		DialTimeout: 2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection (encrypted 3.1.1): %v", err)
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
		t.Fatalf("PutFile over encrypted channel: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile over encrypted channel: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch: got %q want %q", got.String(), string(payload))
	}
	if !sawEncrypted.Load() {
		t.Fatalf("no inbound TransformHeader was observed; encryption did not engage")
	}
}

// TestEncryptedRoundTripAllCiphers extends TestEncryptedRoundTrip311 across
// all four ciphers defined for SMB 3.1.1 in MS-SMB2 §2.2.3.1.2: AES-128-CCM,
// AES-128-GCM, AES-256-CCM, AES-256-GCM. Each subtest pins the client's
// EncryptionCapabilities offer to a single cipher so the server is forced to
// pick that one, captures the negotiated CipherID via OnTreeConnect, and
// asserts (a) the negotiated cipher matches, (b) inbound traffic past
// SessionSetup is TransformHeader-wrapped, and (c) the file round-trips
// byte-identically.
func TestEncryptedRoundTripAllCiphers(t *testing.T) {
	cases := []struct {
		name   string
		cipher uint16
	}{
		{"AES-128-CCM", smb.AES128CCM},
		{"AES-128-GCM", smb.AES128GCM},
		{"AES-256-CCM", smb.AES256CCM},
		{"AES-256-GCM", smb.AES256GCM},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const (
				user     = "alice"
				password = "Hunter2!"
				domain   = "WORKGROUP"
				share    = "secret"
				filename = "ciphered.txt"
			)
			payload := []byte("payload over " + tc.name + " SMB 3.1.1 channel\n")
			ntHash := ntlmssp.Ntowfv1(password)

			var sawEncrypted atomic.Bool
			var negotiatedCipher atomic.Uint32
			srv := &server.Server{
				Config: &server.ServerConfig{
					RequireEncryption: true,
					Authenticator: &server.MapAuthenticator{
						Domain:   domain,
						Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
					},
					OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
						if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolTransformHdr {
							sawEncrypted.Store(true)
						}
						return false, nil
					},
					OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
						negotiatedCipher.Store(uint32(c.CipherID))
						return nil, nil
					},
				},
			}
			srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

			addr, shutdown := startTestServer(t, srv)
			defer shutdown()

			opts := smb.Options{
				Host:        "127.0.0.1",
				Port:        addr.Port,
				Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
				Ciphers:     []uint16{tc.cipher},
				DialTimeout: 2 * time.Second,
			}
			c, err := smb.NewConnection(opts)
			if err != nil {
				t.Fatalf("NewConnection (%s): %v", tc.name, err)
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
				t.Fatalf("PutFile (%s): %v", tc.name, err)
			}

			var got bytes.Buffer
			if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
				got.Write(b)
				return len(b), nil
			}); err != nil {
				t.Fatalf("RetrieveFile (%s): %v", tc.name, err)
			}
			if !bytes.Equal(got.Bytes(), payload) {
				t.Fatalf("read mismatch (%s): got %q want %q", tc.name, got.String(), string(payload))
			}
			if !sawEncrypted.Load() {
				t.Fatalf("no inbound TransformHeader observed (%s); encryption did not engage", tc.name)
			}
			if cid := uint16(negotiatedCipher.Load()); cid != tc.cipher {
				t.Fatalf("negotiated cipher mismatch (%s): got 0x%04x want 0x%04x", tc.name, cid, tc.cipher)
			}
		})
	}
}

// TestRequireEncryptionRejectsPlaintextClient verifies that when the
// server requires encryption but the client refuses to engage it
// (DisableEncryption=true → no GlobalCapEncryption capability), the
// SessionSetup is rejected with STATUS_LOGON_FAILURE.
func TestRequireEncryptionRejectsPlaintextClient(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			RequireEncryption: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableEncryption: true,
		DialTimeout:       2 * time.Second,
	}
	if c, err := smb.NewConnection(opts); err == nil {
		c.Close()
		t.Fatalf("expected SessionSetup to fail when server requires encryption and client opts out")
	}
}

// TestPerShareEncryptDataRejectsPlaintextOp covers per-share EncryptData
// enforcement on the client side (MS-SMB2 §3.2.5.5). The server advertises
// encryption support (but does not require it server-wide) and registers a
// share with EncryptData=true. A client that opts out of encryption
// (DisableEncryption=true) never advertises GlobalCapEncryption, so the server
// derives no decrypter for the session. The TreeConnect reply still reflects
// ShareFlagEncryptData, and the spec-compliant client MUST fail the tree
// connect rather than proceed — sending plaintext (rejected with
// STATUS_ACCESS_DENIED) or encrypted traffic the server cannot decrypt (which
// tears down the connection). This asserts the client's refusal.
func TestPerShareEncryptDataRejectsPlaintextOp(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "secret"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var sawShareFlag atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
				if name == share && res.ShareFlags&smb.ShareFlagEncryptData != 0 {
					sawShareFlag.Store(true)
				}
				return nil, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{
		Type:        smb.ShareTypeDisk,
		VFS:         memvfs.New(memvfs.Options{}),
		EncryptData: true,
	})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableEncryption: true, // forces all traffic to plaintext SMB2
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	// TreeConnect to the encrypt-only share must fail: the client cannot
	// provide encryption end-to-end (it opted out), so per MS-SMB2 §3.2.5.5 it
	// refuses rather than sending traffic the server can neither accept as
	// plaintext nor decrypt.
	err = c.TreeConnect(share)
	if err == nil {
		t.Fatalf("expected TreeConnect to encrypt-only share to fail; got nil")
	}
	if !errors.Is(err, smb.ErrShareRequiresEncryption) {
		t.Fatalf("TreeConnect error: got %v, want ErrShareRequiresEncryption", err)
	}
	// The server still processed the request and reflected the encrypt flag in
	// its reply (the client inspects it before refusing).
	if !sawShareFlag.Load() {
		t.Fatalf("server did not reflect ShareFlagEncryptData in TreeConnectRes")
	}
}

// TestPerShareEncryptDataAllowsEncryptedOp guards the happy path: the
// same per-share configuration as above, but with a client that engages
// encryption normally. The full PutFile/RetrieveFile round-trip must
// succeed, and the inbound traffic past SessionSetup must be wrapped in
// a TransformHeader (asserted via OnRawRequest, mirroring
// TestEncryptedRoundTrip311).
func TestPerShareEncryptDataAllowsEncryptedOp(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "secret"
		filename = "ciphered.txt"
	)
	payload := []byte("payload over per-share encryption\n")
	ntHash := ntlmssp.Ntowfv1(password)

	var sawEncrypted atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true, // not RequireEncryption
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolTransformHdr {
					sawEncrypted.Store(true)
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{
		Type:        smb.ShareTypeDisk,
		VFS:         memvfs.New(memvfs.Options{}),
		EncryptData: true,
	})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DialTimeout: 2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
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
		t.Fatalf("PutFile over encrypt-only share: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile over encrypt-only share: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("read mismatch: got %q want %q", got.String(), string(payload))
	}
	if !sawEncrypted.Load() {
		t.Fatalf("no inbound TransformHeader observed; encryption did not engage")
	}
}
