// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

// buildGmacPDU constructs a minimal SMB2 PDU suitable for GMAC sign/verify
// testing. The MessageID, the SERVER_TO_REDIR flag (response vs request),
// and the body bytes vary; everything else is fixed.
func buildGmacPDU(messageID uint64, serverToRedir bool) []byte {
	p := make([]byte, 96)
	copy(p[0:4], []byte(smb.ProtocolSmb2))
	binary.LittleEndian.PutUint16(p[4:6], 64)
	binary.LittleEndian.PutUint16(p[12:14], smb.CommandCreate)
	var flags uint32
	if serverToRedir {
		flags |= smb.SMB2_FLAGS_SERVER_TO_REDIR
	}
	binary.LittleEndian.PutUint32(p[16:20], flags)
	binary.LittleEndian.PutUint64(p[24:32], messageID)
	for i := 64; i < len(p); i++ {
		p[i] = byte(i)
	}
	return p
}

// TestGMACCrossImplementation proves the server's signPDU/verifyPDU and the
// client's gmacSigner/gmacVerifier are interoperable: they produce identical
// 16-byte tags over identical inputs, and each side accepts the other's
// output.
//
// The three sub-checks pin the spec-level invariants from MS-SMB2 §3.1.4.1 /
// §3.1.5.1 — same key + same canonical PDU bytes + same direction bit ⇒
// same tag — which is what makes the implementations interchangeable on the
// wire.
func TestGMACCrossImplementation(t *testing.T) {
	key := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	sess := &Session{
		signingAlg:    smb.AES_GMAC,
		signingKey:    key,
		SigningActive: true,
	}

	// 1. Byte-for-byte equality on the client-direction case (no
	//    SERVER_TO_REDIR ⇒ nonce flag byte = 0 on both sides). Demonstrates
	//    that the two wrappers around AES-GMAC produce literally the same
	//    bytes for the same canonical input.
	t.Run("byte_equality_client_direction", func(t *testing.T) {
		serverPkt := buildGmacPDU(0x4242, false)
		sess.signPDU(serverPkt)
		serverSig := append([]byte(nil), serverPkt[48:64]...)

		// Pre-normalize as the client's sign() does: FLAGS_SIGNED set, sig
		// field zeroed (already zero from buildGmacPDU).
		clientPkt := buildGmacPDU(0x4242, false)
		binary.LittleEndian.PutUint32(clientPkt[16:20], smb.SMB2_FLAGS_SIGNED)
		clientSig, err := smb.GMACSignForTest(key, clientPkt)
		if err != nil {
			t.Fatalf("GMACSignForTest: %v", err)
		}
		if len(clientSig) < 16 {
			t.Fatalf("client signature short: %d bytes", len(clientSig))
		}
		if !bytes.Equal(serverSig, clientSig[:16]) {
			t.Errorf("client/server signatures diverged for identical inputs:\n  server %x\n  client %x", serverSig, clientSig[:16])
		}
	})

	// 2. Client signs a request, server verifies. SERVER_TO_REDIR clear on
	//    both sides ⇒ matching nonces; the server must accept.
	t.Run("client_signs_server_verifies", func(t *testing.T) {
		pkt := buildGmacPDU(0x1234, false)
		// Mirror the client's sign() prep so the bytes fed to Sign match
		// what would be on the wire when verifyPDU sees them.
		binary.LittleEndian.PutUint32(pkt[16:20], smb.SMB2_FLAGS_SIGNED)
		sig, err := smb.GMACSignForTest(key, pkt)
		if err != nil {
			t.Fatalf("GMACSignForTest: %v", err)
		}
		copy(pkt[48:64], sig[:16])
		if !sess.verifyPDU(pkt) {
			t.Error("server verifyPDU rejected a client-signed request")
		}
	})

	// 3. Server signs a response, client verifies. SERVER_TO_REDIR set on
	//    both sides ⇒ matching nonces; the client must accept.
	t.Run("server_signs_client_verifies", func(t *testing.T) {
		pkt := buildGmacPDU(0xabcd, true)
		sess.signPDU(pkt)
		sig := append([]byte(nil), pkt[48:64]...)
		// Mirror the client's verify() prep: zero the sig field, then call
		// the verifier with the saved tag.
		for i := 48; i < 64; i++ {
			pkt[i] = 0
		}
		ok, err := smb.GMACVerifyForTest(key, pkt, sig)
		if err != nil {
			t.Fatalf("GMACVerifyForTest: %v", err)
		}
		if !ok {
			t.Error("client gmacVerifier rejected a server-signed response")
		}
	})

	// 4. Wrong-direction cross-check: a client-signed request must NOT
	//    verify under the client's verifier (which assumes server
	//    direction), because the nonce flag byte differs.
	t.Run("wrong_direction_rejected", func(t *testing.T) {
		pkt := buildGmacPDU(0x9999, false)
		binary.LittleEndian.PutUint32(pkt[16:20], smb.SMB2_FLAGS_SIGNED)
		sig, err := smb.GMACSignForTest(key, pkt)
		if err != nil {
			t.Fatalf("GMACSignForTest: %v", err)
		}
		// Try to verify a client-signed PDU as if it were a server response.
		ok, err := smb.GMACVerifyForTest(key, pkt, sig[:16])
		if err != nil {
			t.Fatalf("GMACVerifyForTest: %v", err)
		}
		if ok {
			t.Error("client verifier accepted a client-signed PDU (direction bit should diverge)")
		}
	})
}

// TestGMACRoundTrip verifies that signPDU / verifyPDU agree on AES-GMAC
// signatures: a session configured for GMAC signs a PDU, and the same
// session verifies it. Also asserts that tampering with the PDU body
// invalidates the signature, and that the GMAC nonce derivation from the
// MessageID prevents cross-message replay (different MessageIDs must
// produce different signatures over otherwise-identical bytes).
func TestGMACRoundTrip(t *testing.T) {
	key := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	sess := &Session{
		signingAlg:    smb.AES_GMAC,
		signingKey:    key,
		SigningActive: true,
		Flags:         0,
	}

	// Build a plausible SMB2 PDU: ProtocolSmb2 + minimal header + body.
	pdu := make([]byte, 64+16)
	copy(pdu[0:4], []byte(smb.ProtocolSmb2))
	pdu[4] = 64 // StructureSize low byte
	// MessageID = 0x1122334455667788
	pdu[24] = 0x88
	pdu[25] = 0x77
	pdu[26] = 0x66
	pdu[27] = 0x55
	pdu[28] = 0x44
	pdu[29] = 0x33
	pdu[30] = 0x22
	pdu[31] = 0x11

	sess.signPDU(pdu)

	// Verifier must accept.
	if !sess.verifyPDU(pdu) {
		t.Fatal("GMAC verify failed on freshly-signed PDU")
	}

	// Tamper with body — verify must fail.
	tampered := make([]byte, len(pdu))
	copy(tampered, pdu)
	tampered[len(tampered)-1] ^= 0x01
	if sess.verifyPDU(tampered) {
		t.Error("GMAC verify accepted a tampered PDU")
	}

	// Different MessageID over the same content must yield a different signature.
	pdu2 := make([]byte, len(pdu))
	copy(pdu2, pdu)
	pdu2[24] = 0x99 // change MessageID
	// Zero signature on pdu2 so signPDU recomputes
	for i := 48; i < 64; i++ {
		pdu2[i] = 0
	}
	sess.signPDU(pdu2)
	var sig1, sig2 [16]byte
	copy(sig1[:], pdu[48:64])
	copy(sig2[:], pdu2[48:64])
	if sig1 == sig2 {
		t.Error("GMAC produced identical signatures for different MessageIDs")
	}
}
