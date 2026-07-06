// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package smb

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
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
