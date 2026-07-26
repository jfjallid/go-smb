// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package compress

import (
	"bytes"
	"math/rand"
	"testing"
)

func roundTrip(t *testing.T, alg uint16, data []byte) {
	t.Helper()
	comp, err := Compress(alg, data)
	if err != nil {
		t.Fatalf("Compress(0x%04x, %d bytes): %v", alg, len(data), err)
	}
	got, err := Decompress(alg, comp, len(data))
	if err != nil {
		t.Fatalf("Decompress(0x%04x): %v (compressed %d bytes)", alg, err, len(comp))
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("round-trip mismatch for 0x%04x: got %d bytes, want %d", alg, len(got), len(data))
	}
}

var corpus = map[string][]byte{
	"empty-like-1byte": []byte("A"),
	"abc":              []byte("abcabcabcabcabcabcabcabc"),
	"hello":            []byte("Hello, hello, hello world! Hello, hello, hello world!"),
	"zeros-1k":         make([]byte, 1024),
	"text": []byte("the quick brown fox jumps over the lazy dog. " +
		"the quick brown fox jumps over the lazy dog. " +
		"the quick brown fox jumps over the lazy dog."),
}

func TestRoundTripLZ77(t *testing.T) {
	for name, data := range corpus {
		t.Run(name, func(t *testing.T) { roundTrip(t, LZ77, data) })
	}
}

func TestRoundTripLZ77Huffman(t *testing.T) {
	for name, data := range corpus {
		t.Run(name, func(t *testing.T) { roundTrip(t, LZ77Huffman, data) })
	}
}

func TestRoundTripRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, size := range []int{1, 2, 3, 7, 16, 100, 1000, 5000, 40000, huffBlockSize} {
		// Mixed: partly random (incompressible), partly repetitive.
		data := make([]byte, size)
		for i := range data {
			if i%4 == 0 {
				data[i] = byte(rng.Intn(256))
			} else {
				data[i] = byte('a' + (i % 8))
			}
		}
		roundTrip(t, LZ77, data)
		roundTrip(t, LZ77Huffman, data)
	}
}

func TestRoundTripHighlyCompressible(t *testing.T) {
	data := bytes.Repeat([]byte("SMB2COMPRESSION"), 4000) // 60000 bytes
	roundTrip(t, LZ77, data)
	roundTrip(t, LZ77Huffman, data)
	comp, _ := Compress(LZ77Huffman, data)
	if len(comp) >= len(data) {
		t.Errorf("Huffman did not shrink compressible data: %d -> %d", len(data), len(comp))
	}
}

func TestPatternV1(t *testing.T) {
	payload := EncodePatternV1(0x41, 5000)
	got, err := patternDecompress(payload, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0x41}, 5000)) {
		t.Fatal("Pattern_V1 mismatch")
	}
	if _, ok := SingleByteRun(bytes.Repeat([]byte{7}, 10)); !ok {
		t.Fatal("SingleByteRun should detect a run")
	}
	if _, ok := SingleByteRun([]byte{1, 1, 2}); ok {
		t.Fatal("SingleByteRun false positive")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	pdu := append([]byte("\xfeSMB"), bytes.Repeat([]byte("PDU-BODY-"), 2000)...)
	for _, chained := range []bool{false, true} {
		for _, alg := range []uint16{LZ77, LZ77Huffman} {
			cfg := &Config{Algorithms: []uint16{alg}, Chained: chained, MinSize: 16}
			frame, ok := cfg.Frame(pdu)
			if !ok {
				t.Fatalf("Frame(alg=0x%04x chained=%v) did not compress", alg, chained)
			}
			if !IsCompressionFrame(frame) {
				t.Fatalf("framed output lacks compression signature")
			}
			got, err := Unframe(frame, chained, len(pdu)+64)
			if err != nil {
				t.Fatalf("Unframe(alg=0x%04x chained=%v): %v", alg, chained, err)
			}
			if !bytes.Equal(got, pdu) {
				t.Fatalf("frame round-trip mismatch (alg=0x%04x chained=%v)", alg, chained)
			}
		}
	}
}

func TestFrameSkipsIncompressible(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	pdu := make([]byte, 2048)
	for i := range pdu {
		pdu[i] = byte(rng.Intn(256))
	}
	cfg := &Config{Algorithms: []uint16{LZ77Huffman, LZ77}, Chained: true, MinSize: 16}
	if _, ok := cfg.Frame(pdu); ok {
		t.Error("Frame should decline to compress random data")
	}
	small := []byte("tiny")
	if _, ok := cfg.Frame(small); ok {
		t.Error("Frame should skip sub-MinSize PDUs")
	}
}

func TestUnframeChainedPatternAndRaw(t *testing.T) {
	// Hand-build a chained frame: a Pattern_V1 run of 100 'Z' followed by a raw
	// (None) payload "TAIL". Total original = 104.
	var frame []byte
	frame = append(frame, ProtocolID[:]...)
	frame = appendU32(frame, 104)
	// Pattern_V1 payload header + 8-byte pattern body.
	frame = appendU16(frame, PatternV1)
	frame = appendU16(frame, FlagChained)
	frame = appendU32(frame, patternPayloadSize)
	frame = append(frame, EncodePatternV1('Z', 100)...)
	// None payload header + raw data.
	tail := []byte("TAIL")
	frame = appendU16(frame, None)
	frame = appendU16(frame, FlagNone)
	frame = appendU32(frame, uint32(len(tail)))
	frame = append(frame, tail...)

	got, err := Unframe(frame, true, 200)
	if err != nil {
		t.Fatal(err)
	}
	want := append(bytes.Repeat([]byte{'Z'}, 100), tail...)
	if !bytes.Equal(got, want) {
		t.Fatalf("chained pattern+raw = %q, want %q", got, want)
	}
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// TestHuffmanDecoderKnownVector pins the DECODER against a fixed byte vector so
// a symmetric encoder/decoder bug cannot pass. The vector is a hand-built
// single-block stream: 256-byte table giving symbols 'A'(0x41) and 'B'(0x42)
// each a 1-bit code, encoding "AB" then... (see construction below).
func TestHuffmanDecoderKnownVector(t *testing.T) {
	// Two symbols, both length 1 is impossible for canonical (needs a 0 and a
	// 1 code of length 1). Assign 'A' and 'B' length 1 each: codes A=0, B=1.
	lengths := make([]byte, huffTableBytes)
	setLen := func(sym int, l byte) {
		if sym%2 == 0 {
			lengths[sym/2] |= l & 0x0f
		} else {
			lengths[sym/2] |= (l & 0x0f) << 4
		}
	}
	setLen('A', 1)
	setLen('B', 1)

	// Bitstream: encode A,B,A,B,B,A = 0,1,0,1,1,0 then pad. MSB-first into a
	// 16-bit word: bits 010110 00... -> word = 0b0101100000000000 = 0x5800.
	// Written little-endian: 0x00,0x58. Prime needs 2 words; add a zero word.
	stream := append([]byte{}, lengths...)
	stream = append(stream, 0x00, 0x58) // word0 = 0x5800
	stream = append(stream, 0x00, 0x00) // word1 (priming filler)

	got, err := lz77HuffmanDecompress(stream, 6)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(got) != "ABABBA" {
		t.Fatalf("known-vector decode = %q, want ABABBA", got)
	}
}
