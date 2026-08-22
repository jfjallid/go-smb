// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestDefaultPrefersEncryption pins the default client encryption policy:
// with Options.Encryption left at its default (EncryptionPreferred), a client that
// negotiated a cipher end-to-end encrypts everything it sends, including
// traffic to shares the server never flagged EncryptData.
//
// The server here *supports but does not require* encryption and serves one
// plain share and one EncryptData share, so nothing on the server side forces
// the issue — the decision is the client's alone. Both phases must therefore be
// Transform-wrapped and no data PDU may arrive as cleartext SMB2. Encryption
// engages session-wide rather than per-tree, which is what "prefer encryption
// where available" means: per-tree EncryptData enforcement is subsumed once the
// session encrypts, and only decides matters when the connection cannot encrypt
// at all — see TestPerShareEncryptDataRejectsPlaintextOp.
func TestDefaultPrefersEncryption(t *testing.T) {
	const (
		user       = "alice"
		password   = "Hunter2!"
		domain     = "WORKGROUP"
		plainShare = "public"
		encShare   = "secret"
		filename   = "f.txt"
	)
	payload := []byte("mixed per-share encryption payload\n")
	ntHash := ntlmssp.Ntowfv1(password)

	// phase selects which share the current client traffic targets: 0 while we
	// exercise the plaintext share, 1 while we exercise the encrypt share. The
	// OnRawRequest hook tags each observed frame by the phase in effect.
	var phase atomic.Int32
	var (
		plainTreeID          atomic.Uint32
		plainDataSeen        atomic.Bool // cleartext data PDU on the plaintext share (regression signal)
		transformInPhase0    atomic.Bool // Transform frame while on the plaintext share (expected)
		transformInPhase1    atomic.Bool // Transform frame while on the encrypt share (expected)
		sessionGlobalEncrypt atomic.Bool // server session carried SESSION_FLAG_ENCRYPT_DATA
	)

	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true, // supported, NOT required — the mixed case
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) < 4 {
					return false, nil
				}
				switch string(raw[0:4]) {
				case smb.ProtocolTransformHdr:
					if phase.Load() == 0 {
						transformInPhase0.Store(true)
					} else {
						transformInPhase1.Store(true)
					}
				case smb.ProtocolSmb2:
					// SMB2 sync header: Command at offset 12, TreeId at 36.
					if len(raw) < 40 {
						return false, nil
					}
					cmd := binary.LittleEndian.Uint16(raw[12:14])
					treeID := binary.LittleEndian.Uint32(raw[36:40])
					if phase.Load() == 0 && treeID == plainTreeID.Load() && treeID != 0 &&
						(cmd == smb.CommandCreate || cmd == smb.CommandWrite || cmd == smb.CommandRead) {
						plainDataSeen.Store(true)
					}
				}
				return false, nil
			},
			OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
				if s.Flags&smb.SessionFlagEncryptData != 0 {
					sessionGlobalEncrypt.Store(true)
				}
				if name == plainShare {
					plainTreeID.Store(res.Header.TreeID)
				}
				return nil, nil
			},
		},
	}
	srv.RegisterShare(plainShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	srv.RegisterShare(encShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{}), EncryptData: true})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:      "127.0.0.1",
		Port:      addr.Port,
		Initiator: &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		// Options.Encryption left unset, so the client neither opts out nor
		// demands encryption — exactly the configuration where the
		// prefer-where-available default decides.
		DialTimeout: 2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	putGet := func(share string) {
		t.Helper()
		src := bytes.NewReader(payload)
		if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
			n, err := src.Read(buf)
			if err == io.EOF && n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}); err != nil {
			t.Fatalf("PutFile on %q: %v", share, err)
		}
		var got bytes.Buffer
		if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
			got.Write(b)
			return len(b), nil
		}); err != nil {
			t.Fatalf("RetrieveFile on %q: %v", share, err)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Fatalf("read mismatch on %q: got %q want %q", share, got.String(), string(payload))
		}
	}

	// Phase 0: plaintext share. All of its traffic must be cleartext SMB2.
	phase.Store(0)
	putGet(plainShare)

	// Phase 1: encrypt share. Its data PDUs must be Transform-wrapped. (The
	// TreeConnect itself still travels plaintext on TreeId 0; the encryption
	// kicks in for the per-tree ops that follow.)
	phase.Store(1)
	putGet(encShare)

	// The server's Session.Flags reflect the *server's* policy (it sets
	// SMB2_SESSION_FLAG_ENCRYPT_DATA only when its own RequireEncryption is
	// set), not the client's. It stays clear here, which is the point: the
	// client encrypts everything below purely on its own default, with nothing
	// in the server's replies asking it to.
	if sessionGlobalEncrypt.Load() {
		t.Fatalf("server set SMB2_SESSION_FLAG_ENCRYPT_DATA; this server only supports encryption, it does not require it")
	}
	if plainDataSeen.Load() {
		t.Fatalf("observed a cleartext data PDU on the plaintext share; the default must encrypt everything it can")
	}
	if !transformInPhase0.Load() {
		t.Fatalf("no TransformHeader observed while exercising the plaintext share; encryption did not engage by default")
	}
	if !transformInPhase1.Load() {
		t.Fatalf("no TransformHeader observed while exercising the encrypt share; encryption did not engage")
	}
}

// TestEncryptedRoundTrip311 round-trips a file over an SMB 3.1.1
// connection where every post-SessionSetup PDU is wrapped in a
// TransformHeader. Server has RequireEncryption=true; the client offers
// GlobalCapEncryption (Encryption left at its default) so the
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
		// Encryption left at its default so the client engages it.
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

// TestServerRequireEncryptionRejectsPlaintextClient verifies that when the
// server requires encryption but the client refuses to engage it
// (EncryptionDisabled → no GlobalCapEncryption capability), the
// SessionSetup is rejected with STATUS_LOGON_FAILURE.
func TestServerRequireEncryptionRejectsPlaintextClient(t *testing.T) {
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
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionDisabled,
		DialTimeout: 2 * time.Second,
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
// (EncryptionDisabled) never advertises GlobalCapEncryption, so the server
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
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionDisabled, // forces all traffic to plaintext SMB2
		DialTimeout: 2 * time.Second,
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

// TestEncryptionRequiredRefusesUnencryptableConnection covers the client-side
// EncryptionRequired policy: when the server will not encrypt, the
// connection is refused at the end of NEGOTIATE rather than silently running in
// plaintext. Each subtest drives one of the ways a real server leaves the
// connection without a cipher, and each was a silent downgrade before: the
// option was consulted exactly once, in a branch that required encryption to
// already be negotiated, so failing to negotiate it made the option a no-op.
func TestEncryptionRequiredRefusesUnencryptableConnection(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	for _, tc := range []struct {
		name string
		cfg  func(*server.ServerConfig)
		// wantDialect is the dialect the connection is expected to settle on,
		// named in the error so an operator can see why encryption was absent.
		wantDialect string
	}{
		{
			// SMB 2.1 has no encryption at all. The client offers 3.x, the
			// server caps the negotiation below it, and the downgrade is only
			// visible in the response — so this cannot be caught in
			// validateOptions the way an explicit 2.x-only Dialects list is.
			name: "server caps the dialect at 2.1",
			cfg: func(c *server.ServerConfig) {
				c.MaxDialect = smb.DialectSmb_2_1
				c.EncryptionSupported = true
			},
			wantDialect: "2.1",
		},
		{
			// A 3.1.1 server that does not support encryption selects no cipher
			// and answers SMB2_ENCRYPTION_NONE (MS-SMB2 §3.3.5.4). The dialect
			// is fine; the cipher is what is missing.
			name: "3.1.1 server without encryption support",
			cfg: func(c *server.ServerConfig) {
				c.EncryptionSupported = false
			},
			wantDialect: "3.1.1",
		},
		{
			// Same, one dialect down: 3.0 negotiates encryption through the
			// SMB2_GLOBAL_CAP_ENCRYPTION capability rather than a context, so
			// this exercises the other detection path.
			name: "3.0 server without encryption support",
			cfg: func(c *server.ServerConfig) {
				c.MaxDialect = smb.DialectSmb_3_0
				c.EncryptionSupported = false
			},
			wantDialect: "3.0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &server.ServerConfig{
				Authenticator: &server.MapAuthenticator{
					Domain:   domain,
					Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
				},
			}
			tc.cfg(cfg)
			srv := &server.Server{Config: cfg}
			addr, shutdown := startTestServer(t, srv)
			defer shutdown()

			opts := smb.Options{
				Host:        "127.0.0.1",
				Port:        addr.Port,
				Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
				Encryption:  smb.EncryptionRequired,
				DialTimeout: 2 * time.Second,
			}
			c, err := smb.NewConnection(opts)
			if err == nil {
				c.Close()
				t.Fatalf("NewConnection succeeded; EncryptionRequired must refuse a connection that negotiated no encryption")
			}
			if !errors.Is(err, smb.ErrEncryptionNotNegotiated) {
				t.Fatalf("NewConnection error: got %v, want ErrEncryptionNotNegotiated", err)
			}
			// The negotiated dialect is named in the message because "no
			// encryption" and "too old a dialect" call for different fixes.
			if !strings.Contains(err.Error(), tc.wantDialect) {
				t.Errorf("error %q does not name the negotiated dialect %q", err, tc.wantDialect)
			}
		})
	}
}

// TestEncryptionRequiredSucceedsWhenAvailable is the positive control for the
// test above: with the same client options against a server that does support
// encryption, the connection comes up and its traffic is Transform-wrapped. A
// hard failure that also rejects working configurations would be no better than
// the silent downgrade it replaces.
func TestEncryptionRequiredSucceedsWhenAvailable(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "data"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var transformSeen atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolTransformHdr {
					transformSeen.Store(true)
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionRequired,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}
	defer c.TreeDisconnect(share)

	if !transformSeen.Load() {
		t.Fatalf("no TransformHeader observed; EncryptionRequired did not engage encryption")
	}
}

// TestEncryptionDisabledRemovesCipherFromNegotiation asserts that opting out
// takes encryption out of the negotiation rather than merely out of the send
// path. The server must see neither SMB2_GLOBAL_CAP_ENCRYPTION nor an
// EncryptionCapabilities context, and must therefore select no cipher — which
// is what stops it from deriving encryption keys for a session that will never
// use them.
func TestEncryptionDisabledRemovesCipherFromNegotiation(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var (
		sawCapEncrypt  atomic.Bool
		sawCipherCtx   atomic.Bool
		negotiatedCiph atomic.Uint32
	)
	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true, // server would happily encrypt
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnNegotiate: func(c *server.Conn, req *smb.NegotiateReq, res *smb.NegotiateRes) error {
				if req.Capabilities&smb.GlobalCapEncryption != 0 {
					sawCapEncrypt.Store(true)
				}
				for _, ctx := range req.ContextList {
					if ctx.ContextType == smb.EncryptionCapabilities {
						sawCipherCtx.Store(true)
					}
				}
				negotiatedCiph.Store(uint32(c.CipherID))
				return nil
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionDisabled,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	if sawCapEncrypt.Load() {
		t.Errorf("client advertised SMB2_GLOBAL_CAP_ENCRYPTION despite EncryptionDisabled")
	}
	if sawCipherCtx.Load() {
		t.Errorf("client sent an EncryptionCapabilities context despite EncryptionDisabled")
	}
	if got := negotiatedCiph.Load(); got != 0 {
		t.Errorf("server selected cipher 0x%04x; want none negotiated", got)
	}
	// The connection must still be usable: dropping encryption from the offer
	// must not disturb signing, which is what protects this session instead.
	if err := c.TreeConnect("IPC$"); err != nil {
		t.Fatalf("TreeConnect over the plaintext session: %v", err)
	}
	c.TreeDisconnect("IPC$")
}

// TestServerDirectedEncryptionMix locks in EncryptionServerDirected: within a
// single session against a server that *supports but does not require*
// encryption, traffic to a plaintext share stays unwrapped SMB2 while traffic
// to a share flagged EncryptData is wrapped in a TransformHeader (MS-SMB2
// §3.2.5.5).
//
// This is the mode's whole reason to exist, and it is what distinguishes it
// from EncryptionDisabled: a cipher is still negotiated, so the encrypt-only
// share remains reachable rather than failing its TreeConnect with
// ErrShareRequiresEncryption. Two invariants must hold together: the plaintext
// share's data PDUs arrive as cleartext SMB2, and the encrypt share's do not.
func TestServerDirectedEncryptionMix(t *testing.T) {
	const (
		user       = "alice"
		password   = "Hunter2!"
		domain     = "WORKGROUP"
		plainShare = "public"
		encShare   = "secret"
		filename   = "f.txt"
	)
	payload := []byte("server-directed encryption payload\n")
	ntHash := ntlmssp.Ntowfv1(password)

	// phase selects which share the current client traffic targets: 0 while we
	// exercise the plaintext share, 1 while we exercise the encrypt share.
	var phase atomic.Int32
	var (
		plainTreeID       atomic.Uint32
		plainDataSeen     atomic.Bool // cleartext data PDU on the plaintext share (expected)
		transformInPhase0 atomic.Bool // Transform frame while on the plaintext share (regression signal)
		transformInPhase1 atomic.Bool // Transform frame while on the encrypt share (expected)
	)

	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true, // supported, NOT required
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) < 4 {
					return false, nil
				}
				switch string(raw[0:4]) {
				case smb.ProtocolTransformHdr:
					if phase.Load() == 0 {
						transformInPhase0.Store(true)
					} else {
						transformInPhase1.Store(true)
					}
				case smb.ProtocolSmb2:
					// SMB2 sync header: Command at offset 12, TreeId at 36.
					if len(raw) < 40 {
						return false, nil
					}
					cmd := binary.LittleEndian.Uint16(raw[12:14])
					treeID := binary.LittleEndian.Uint32(raw[36:40])
					if phase.Load() == 0 && treeID == plainTreeID.Load() && treeID != 0 &&
						(cmd == smb.CommandCreate || cmd == smb.CommandWrite || cmd == smb.CommandRead) {
						plainDataSeen.Store(true)
					}
				}
				return false, nil
			},
			OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
				if name == plainShare {
					plainTreeID.Store(res.Header.TreeID)
				}
				return nil, nil
			},
		},
	}
	srv.RegisterShare(plainShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})
	srv.RegisterShare(encShare, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{}), EncryptData: true})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionServerDirected,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	putGet := func(share string) {
		t.Helper()
		src := bytes.NewReader(payload)
		if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
			n, err := src.Read(buf)
			if err == io.EOF && n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}); err != nil {
			t.Fatalf("PutFile on %q: %v", share, err)
		}
		var got bytes.Buffer
		if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
			got.Write(b)
			return len(b), nil
		}); err != nil {
			t.Fatalf("RetrieveFile on %q: %v", share, err)
		}
		if !bytes.Equal(got.Bytes(), payload) {
			t.Fatalf("read mismatch on %q: got %q want %q", share, got.String(), string(payload))
		}
	}

	phase.Store(0)
	putGet(plainShare)
	phase.Store(1)
	putGet(encShare)

	if !plainDataSeen.Load() {
		t.Errorf("no cleartext data PDU on the plaintext share; server-directed must not encrypt what the server did not ask for")
	}
	if transformInPhase0.Load() {
		t.Errorf("observed a TransformHeader on the plaintext share; encryption leaked beyond the encrypt share")
	}
	if !transformInPhase1.Load() {
		t.Errorf("no TransformHeader on the encrypt share; per-tree encryption did not engage")
	}
}

// TestServerDirectedReachesEncryptOnlyShare is the distinction between
// EncryptionServerDirected and EncryptionDisabled stated on its own: both leave
// ordinary traffic in plaintext, but only the former still negotiates a cipher,
// so only the former can open a share the server flagged EncryptData.
// EncryptionDisabled fails that TreeConnect (see
// TestPerShareEncryptDataRejectsPlaintextOp).
func TestServerDirectedReachesEncryptOnlyShare(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "secret"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			EncryptionSupported: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{}), EncryptData: true})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Encryption:  smb.EncryptionServerDirected,
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect to the encrypt-only share: %v", err)
	}
	c.TreeDisconnect(share)
}
