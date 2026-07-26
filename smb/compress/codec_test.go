// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package compress

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// smb2PDU builds a plausible plaintext SMB2 PDU of n bytes with a compressible
// (highly repetitive) body.
func smb2PDU(n int) []byte {
	buf := make([]byte, n)
	copy(buf, []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(buf[4:6], 64)
	for i := 64; i < n; i++ {
		buf[i] = byte('A' + (i % 3))
	}
	return buf
}

// TestCodecZeroValueRejectsFrames is the regression guard for the pre-negotiation
// decompression hole: an inbound 0xFCSMB frame used to be decompressed
// regardless of whether compression had been negotiated, so an unauthenticated
// peer could declare a 16 MiB original size in a ~100-byte frame and force that
// allocation, repeatedly. A codec that has not been Configured must refuse.
func TestCodecZeroValueRejectsFrames(t *testing.T) {
	var c Codec
	if c.Negotiated() {
		t.Error("zero-value Codec reports compression as negotiated")
	}

	// A well-formed frame that a configured codec would happily accept.
	cfg := &Config{Algorithms: []uint16{LZ77}, MinSize: 1}
	frame, ok := cfg.Frame(smb2PDU(4096))
	if !ok {
		t.Fatal("failed to build a compressed frame for the test")
	}

	if _, err := c.Decompress(frame); err == nil {
		t.Error("zero-value Codec decompressed a frame; want rejection")
	} else if !strings.Contains(err.Error(), "not negotiated") {
		t.Errorf("unexpected rejection reason: %v", err)
	}

	// A decompression bomb must be refused on the same grounds, before any
	// allocation is attempted.
	bomb := make([]byte, 32)
	copy(bomb, ProtocolID[:])
	binary.LittleEndian.PutUint32(bomb[4:8], 16<<20)
	if _, err := c.Decompress(bomb); err == nil {
		t.Error("zero-value Codec accepted a bomb frame")
	}
}

// TestCodecCompressIsInertWhenInactive checks the outbound half: an unconfigured
// codec must pass PDUs through untouched so callers can call Compress
// unconditionally.
func TestCodecCompressIsInertWhenInactive(t *testing.T) {
	var c Codec
	pdu := smb2PDU(8192)
	if got := c.Compress(pdu); !bytes.Equal(got, pdu) {
		t.Error("inactive Codec modified the PDU")
	}

	// Configured with a decode-only algorithm: still no outbound compression.
	c.Configure([]uint16{PatternV1}, false, 0)
	if !c.Negotiated() {
		t.Error("Codec configured with Pattern_V1 should still count as negotiated (receive-only)")
	}
	if got := c.Compress(pdu); !bytes.Equal(got, pdu) {
		t.Error("receive-only Codec emitted a compressed frame")
	}
}

// TestCodecRoundTrip exercises both wire forms end to end.
func TestCodecRoundTrip(t *testing.T) {
	for _, chained := range []bool{false, true} {
		for _, alg := range []uint16{LZ77, LZ77Huffman} {
			var c Codec
			c.Configure([]uint16{alg}, chained, 1)

			pdu := smb2PDU(16384)
			frame := c.Compress(pdu)
			if bytes.Equal(frame, pdu) {
				t.Fatalf("alg=0x%04x chained=%v: compression produced no frame", alg, chained)
			}
			if !IsCompressionFrame(frame) {
				t.Fatalf("alg=0x%04x chained=%v: output is not a compression frame", alg, chained)
			}
			got, err := c.Decompress(frame)
			if err != nil {
				t.Fatalf("alg=0x%04x chained=%v: decompress: %v", alg, chained, err)
			}
			if !bytes.Equal(got, pdu) {
				t.Fatalf("alg=0x%04x chained=%v: round trip mismatch", alg, chained)
			}
		}
	}
}

// TestCodecDecompressToleratesWireFormMismatch covers the receive-side
// robustness fix: chained-vs-unchained cannot be told apart by inspection (a
// single-payload chained frame may leave SMB2_COMPRESSION_FLAG_CHAINED clear),
// so a peer that frames with the form we did not negotiate must still be
// decoded rather than dropped.
func TestCodecDecompressToleratesWireFormMismatch(t *testing.T) {
	pdu := smb2PDU(16384)

	for _, senderChained := range []bool{false, true} {
		sender := &Config{Algorithms: []uint16{LZ77}, Chained: senderChained, MinSize: 1}
		frame, ok := sender.Frame(pdu)
		if !ok {
			t.Fatalf("senderChained=%v: failed to frame", senderChained)
		}

		// Receiver negotiated the OPPOSITE wire form.
		var c Codec
		c.Configure([]uint16{LZ77}, !senderChained, 0)

		got, err := c.Decompress(frame)
		if err != nil {
			t.Fatalf("senderChained=%v: decompress under mismatched form: %v", senderChained, err)
		}
		if !bytes.Equal(got, pdu) {
			t.Fatalf("senderChained=%v: mismatched-form round trip corrupted the PDU", senderChained)
		}
	}
}

// TestCodecRejectsOversizedDeclaration keeps the decompression-bomb bound in
// force for a configured codec.
func TestCodecRejectsOversizedDeclaration(t *testing.T) {
	var c Codec
	c.Configure([]uint16{LZ77}, false, 0)
	c.SetMaxFrame(4096)

	frame := make([]byte, 32)
	copy(frame, ProtocolID[:])
	binary.LittleEndian.PutUint32(frame[4:8], 1<<20) // 1 MiB declared, bound is 4 KiB
	if _, err := c.Decompress(frame); err == nil {
		t.Error("Codec accepted a frame declaring more than its bound")
	}
}

// TestCodecDecompressIfFramedPassesThrough checks the convenience wrapper leaves
// non-frames alone.
func TestCodecDecompressIfFramedPassesThrough(t *testing.T) {
	var c Codec
	pdu := smb2PDU(512)
	got, err := c.DecompressIfFramed(pdu)
	if err != nil {
		t.Fatalf("DecompressIfFramed on a plain PDU: %v", err)
	}
	if !bytes.Equal(got, pdu) {
		t.Error("DecompressIfFramed altered a non-frame buffer")
	}
}
