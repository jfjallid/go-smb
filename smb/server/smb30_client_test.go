package server_test

import (
	"bytes"
	"fmt"
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

func TestSMB30FamilySignedRoundTrip(t *testing.T) {
	testSMB30FamilyRoundTrip(t, false)
}

func TestSMB30FamilyEncryptedRoundTrip(t *testing.T) {
	testSMB30FamilyRoundTrip(t, true)
}

// ntlmrelayx's SMB SOCKS plugin presents the local SessionSetup as guest.
func TestSMB30FamilyGuestRelayStyleRoundTrip(t *testing.T) {
	for _, dialect := range []uint16{smb.DialectSmb_3_0, smb.DialectSmb_3_0_2} {
		t.Run(fmt.Sprintf("0x%04x", dialect), func(t *testing.T) {
			const (
				user     = "relayuser"
				domain   = "TESTDOMAIN"
				share    = "relay"
				filename = "guest.txt"
			)
			payload := []byte("relay-style guest transport over SMB 3.x\n")

			srv := &server.Server{Config: &server.ServerConfig{
				MinDialect: dialect,
				MaxDialect: dialect,
				AllowGuest: true,
				Authenticator: &server.MapAuthenticator{
					Domain:   domain,
					Accounts: map[string]*server.Account{},
				},
			}}
			srv.RegisterShare(share, server.Share{
				Type:          smb.ShareTypeDisk,
				VFS:           memvfs.New(memvfs.Options{}),
				GuestWritable: true,
			})

			addr, shutdown := startTestServer(t, srv)
			defer shutdown()

			c, err := smb.NewConnection(smb.Options{
				Host:      "127.0.0.1",
				Port:      addr.Port,
				User:      user,
				Domain:    domain,
				Initiator: &spnego.NTLMInitiator{User: user, Domain: domain},
				// Match the relay's unsigned, unencrypted local session.
				DisableEncryption: true,
				DialTimeout:       2 * time.Second,
			})
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
				return n, err
			}); err != nil {
				t.Fatalf("PutFile as guest: %v", err)
			}

			var got bytes.Buffer
			if err := c.RetrieveFile(share, filename, 0, func(buf []byte) (int, error) {
				return got.Write(buf)
			}); err != nil {
				t.Fatalf("RetrieveFile as guest: %v", err)
			}
			if !bytes.Equal(got.Bytes(), payload) {
				t.Fatalf("payload = %q, want %q", got.Bytes(), payload)
			}
		})
	}
}

func testSMB30FamilyRoundTrip(t *testing.T, encrypted bool) {
	for _, dialect := range []uint16{smb.DialectSmb_3_0, smb.DialectSmb_3_0_2} {
		t.Run(fmt.Sprintf("0x%04x", dialect), func(t *testing.T) {
			const (
				user     = "alice"
				password = "test-password"
				domain   = "WORKGROUP"
				share    = "test"
				filename = "roundtrip.txt"
			)
			payload := []byte("SMB 3.0-family authenticated file round-trip\n")
			ntHash := ntlmssp.Ntowfv1(password)

			var observedDialect atomic.Uint32
			var sawTransform atomic.Bool
			srv := &server.Server{Config: &server.ServerConfig{
				MinDialect:        dialect,
				MaxDialect:        dialect,
				SigningRequired:   !encrypted,
				RequireEncryption: encrypted,
				Authenticator: &server.MapAuthenticator{
					Domain: domain,
					Accounts: map[string]*server.Account{
						user: {NTHash: ntHash},
					},
				},
				OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
					if len(raw) >= 4 && string(raw[:4]) == smb.ProtocolTransformHdr {
						sawTransform.Store(true)
					}
					return false, nil
				},
				OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
					observedDialect.Store(uint32(c.Dialect))
					return nil, nil
				},
			}}
			srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

			addr, shutdown := startTestServer(t, srv)
			defer shutdown()

			opts := smb.Options{
				Host:                  "127.0.0.1",
				Port:                  addr.Port,
				User:                  user,
				Password:              password,
				Domain:                domain,
				Initiator:             &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
				RequireMessageSigning: !encrypted,
				DisableEncryption:     !encrypted,
				DialTimeout:           2 * time.Second,
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
				return n, err
			}); err != nil {
				t.Fatalf("PutFile: %v", err)
			}

			var got bytes.Buffer
			if err := c.RetrieveFile(share, filename, 0, func(buf []byte) (int, error) {
				return got.Write(buf)
			}); err != nil {
				t.Fatalf("RetrieveFile: %v", err)
			}
			if !bytes.Equal(got.Bytes(), payload) {
				t.Fatalf("payload = %q, want %q", got.Bytes(), payload)
			}
			if gotDialect := uint16(observedDialect.Load()); gotDialect != dialect {
				t.Fatalf("negotiated dialect = 0x%04x, want 0x%04x", gotDialect, dialect)
			}
			if encrypted != sawTransform.Load() {
				t.Fatalf("TransformHeader observed = %v, want %v", sawTransform.Load(), encrypted)
			}
		})
	}
}
