// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package smb

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb/crypto/ccm"
)

// frameNetBIOS wraps payload in a 4-byte big-endian NetBIOS length prefix.
func frameNetBIOS(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out[:4], uint32(len(payload)))
	copy(out[4:], payload)
	return out
}

// TestRunReceiverShortPacketNoCrash is the regression guard for client finding
// C1: a malicious/buggy server sending a NetBIOS frame shorter than an SMB2
// header must not crash the client. Before the fix, a 10-byte "0xFE S M B …"
// frame drove data[:64] out of range and panicked the runReceiver goroutine
// (no recover) → whole process down. After the fix the frame is length-guarded
// and skipped, and a defensive recover backstops any remaining parser panic.
func TestRunReceiverShortPacketNoCrash(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{"one byte", []byte{0xFE}},
		{"three bytes", []byte{0xFE, 'S', 'M'}},
		{"smb2 magic only", []byte{0xFE, 'S', 'M', 'B'}},
		{"short smb2 header", append([]byte{0xFE, 'S', 'M', 'B'}, make([]byte, 6)...)},
		{"short transform header", append([]byte{0xFD, 'S', 'M', 'B'}, make([]byte, 6)...)},
		{"unknown protocol", []byte{0x00, 0x11, 0x22, 0x33, 0x44}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			c := &Connection{
				outstandingRequests: newOutstandingRequests(),
				rdone:               make(chan struct{}, 1),
				wdone:               make(chan struct{}, 1),
				conn:                client,
			}
			// No session enabled, so runReceiver takes the pre-session path.

			done := make(chan struct{})
			go func() {
				c.runReceiver() // must neither panic nor hang
				close(done)
			}()

			// Feed the malformed frame, then close to drive runReceiver to its
			// clean-exit path.
			if _, err := server.Write(frameNetBIOS(tc.payload)); err != nil {
				t.Fatalf("write frame: %v", err)
			}
			server.Close()

			select {
			case <-done:
				// runReceiver returned without crashing the test process.
			case <-time.After(2 * time.Second):
				t.Fatal("runReceiver did not return; possible hang")
			}
		})
	}
}

// TestRunReceiverEncryptedResponseNotSigningRejected is the regression guard for
// the 3.0/3.0.2 signing-vs-encryption bug: when a signing-required session
// negotiates a pre-3.1.1 dialect with encryption enabled, the server encrypts
// its responses. An encrypted PDU carries its own AEAD integrity and never sets
// SMB2_FLAGS_SIGNED, so the reader must NOT run the plaintext signature check on
// it. Before the fix the check lacked a `!encrypted` guard for non-3.1.1
// dialects, so the first encrypted response (e.g. the TreeConnect reply) was
// rejected as "signing is required but PDU is not signed" and the connection was
// torn down. After the fix the decrypted PDU is delivered to its outstanding
// request as normal.
func TestRunReceiverEncryptedResponseNotSigningRejected(t *testing.T) {
	const (
		sessionID = uint64(0x1122334455667788)
		msgID     = uint64(7)
	)

	// A single symmetric AES-128-CCM AEAD stands in for both directions: the
	// "server" seals with it (via Session.encrypt) and the reader opens with it
	// (via Session.decrypt). CCM is stateless per-call, so one instance is fine.
	block, err := aes.NewCipher(bytes.Repeat([]byte{0x5a}, 16))
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	aead, err := ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	if err != nil {
		t.Fatalf("new ccm: %v", err)
	}

	sess := &Session{
		sessionID: sessionID,
		dialect:   DialectSmb_3_0,
		encrypter: aead,
		decrypter: aead,
	}
	sess.isSigningRequired.Store(true)

	// Build a plaintext, UNSIGNED SMB2 response header (as a server sends inside
	// the encrypted wrapper). Status OK, no SMB2_FLAGS_SIGNED, matching msg/session.
	plain := make([]byte, 64)
	plain[0], plain[1], plain[2], plain[3] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(plain[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(plain[12:14], CommandTreeConnect)
	binary.LittleEndian.PutUint32(plain[16:20], SMB2_FLAGS_SERVER_TO_REDIR)
	binary.LittleEndian.PutUint64(plain[24:32], msgID)
	binary.LittleEndian.PutUint64(plain[40:48], sessionID)

	encFrame, err := sess.encrypt(plain)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(encFrame[0:4]) != ProtocolTransformHdr {
		t.Fatalf("expected transform-header frame, got % x", encFrame[0:4])
	}

	client, server := net.Pipe()
	c := &Connection{
		Session:             sess,
		outstandingRequests: newOutstandingRequests(),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		conn:                client,
	}
	c.enableSession() // take the has-session path in runReceiver

	rr := &requestResponse{msgId: msgID, recv: make(chan []byte, 1)}
	c.outstandingRequests.set(msgID, rr)

	done := make(chan struct{})
	go func() {
		c.runReceiver()
		close(done)
	}()

	if _, err := server.Write(frameNetBIOS(encFrame)); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	select {
	case got := <-rr.recv:
		// The decrypted plaintext PDU must be delivered intact — proving the
		// signing check was correctly skipped for the encrypted response.
		if !bytes.Equal(got, plain) {
			t.Fatalf("delivered PDU mismatch:\n got  % x\n want % x", got, plain)
		}
	case <-done:
		t.Fatal("runReceiver exited without delivering the encrypted response (signing check wrongly rejected it)")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the encrypted response to be delivered")
	}

	server.Close()
	<-done
}
