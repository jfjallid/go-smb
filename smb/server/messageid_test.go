// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/spnego"
)

// TestDuplicateMessageIDRejected exercises the MS-SMB2 §3.3.5.2.3 strict
// MessageId check: after the initial SMB2 NegotiateReq (MessageId=0) the
// server records that ID. A second PDU reusing the same MessageId must be
// rejected — for simplicity the server closes the connection.
//
// Regression coverage: the client's makeRequestResponse used to advance its
// MessageId counter by exactly CreditCharge bytes. SMB2 NegotiateReq sets
// CreditCharge=0 (dialect not yet known, so multi-credit can't apply), so
// the counter stayed put and the next request reused the Negotiate's ID.
// Strict servers (Windows) TCP-RST the connection in that case; without the
// server-side check below, the bug went unnoticed against go-smb's own
// server because it processed duplicates leniently.
func TestDuplicateMessageIDRejected(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{}}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Build a minimal SMB2 NegotiateReq with MessageId=0. We don't care
	// what dialect the server picks — only that it accepts the request and
	// remembers MessageId=0.
	req1 := smb.NegotiateReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandNegotiate,
			Credits:       1,
			MessageID:     0,
			Signature:     make([]byte, 16),
		},
		StructureSize: 36,
		DialectCount:  1,
		SecurityMode:  smb.SecurityModeSigningEnabled,
		ClientGuid:    make([]byte, 16),
		Dialects:      []uint16{smb.DialectSmb_2_1},
	}
	if err := writeSMB2Frame(conn, &req1); err != nil {
		t.Fatalf("write neg1: %v", err)
	}
	if _, err := readSMB2Frame(conn); err != nil {
		t.Fatalf("read neg1 reply: %v", err)
	}

	// Send a second request reusing MessageId=0. After SMB2 Negotiate the
	// connection's Dialect is set, so handleNegotiate will be reached again
	// only if the strict check is missing — i.e. the test fails when the
	// check is not in place. Either way we expect the server to close the
	// connection without producing a second reply.
	req2 := req1
	req2.Header.MessageID = 0
	if err := writeSMB2Frame(conn, &req2); err != nil {
		t.Fatalf("write neg2: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [4]byte
	_, err = io.ReadFull(conn, lenBuf[:])
	if err == nil {
		t.Fatalf("server replied to duplicate MessageId instead of disconnecting")
	}
}

// TestClientMessageIDAdvancesAfterNegotiate is the client-side counterpart:
// a real smb.NewConnection drives Negotiate then SessionSetup. The strict
// server check above (now active for every inbound PDU) will close the
// connection on a duplicate MessageId, so NewConnection failing means the
// client regressed on the "CreditCharge=0 must still advance MessageId by 1"
// rule. We run both code paths (multi-protocol SMB1->SMB2 and SMB2-only),
// since each path produces a Negotiate request with CreditCharge=0 and so
// each path can reproduce the bug independently.
func TestClientMessageIDAdvancesAfterNegotiate(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	for _, tc := range []struct {
		name     string
		dialects []uint16
	}{
		{"smb1_multiproto", nil},            // SMB1 multi-proto → SMB2 Negotiate (CC=0)
		{"smb2_only", smb.DialectsSMB2Only}, // SMB2-only Negotiate (CC=0)
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server.Server{
				Config: &server.ServerConfig{
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
				Encryption:  smb.EncryptionDisabled, // signing path is fine; SMB 3.1.1 refuses both off
				Dialects:    tc.dialects,
				DialTimeout: 2 * time.Second,
			}
			c, err := smb.NewConnection(opts)
			if err != nil {
				t.Fatalf("NewConnection: %v", err)
			}
			c.Close()
		})
	}
}

func writeSMB2Frame(conn net.Conn, v smb.Marshaller) error {
	body, err := v.MarshalBinary()
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err = conn.Write(frame)
	return err
}

func readSMB2Frame(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
