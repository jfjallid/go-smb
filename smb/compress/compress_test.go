// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package compress

import (
	"bytes"
	"encoding/hex"
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
// TestHuffmanMultiBlock covers payloads larger than one 64 KiB Huffman block.
// The encoder was single-block only, and pickAlgorithm silently skipped
// LZ77+Huffman above that size — so against a server that negotiates only
// LZ77+Huffman (Windows Server 2022 answers with LZ77+Huffman and Pattern_V1),
// nothing above 64 KiB ever compressed. Every SMB WRITE of any consequence is
// larger than that, which made compression a no-op for bulk transfers.
//
// The sizes bracket the block boundary, where the inter-block padding has to be
// exactly right: the next block's code table must start on the byte the decoder
// left its cursor on.
func TestHuffmanMultiBlock(t *testing.T) {
	for _, size := range []int{
		huffBlockSize - 1, huffBlockSize, huffBlockSize + 1,
		huffBlockSize + 17, 2 * huffBlockSize, 2*huffBlockSize + 1,
		3*huffBlockSize + 12345, 1 << 20,
	} {
		src := make([]byte, size)
		// Compressible, but not so uniform that a single match covers a block:
		// a mix of runs and varying bytes exercises real token boundaries.
		for i := range src {
			switch {
			case i%97 < 40:
				src[i] = byte(i / 97)
			default:
				src[i] = byte(i % 251)
			}
		}
		comp, err := Compress(LZ77Huffman, src)
		if err != nil {
			t.Fatalf("size %d: compress: %v", size, err)
		}
		if len(comp) >= size {
			t.Errorf("size %d: compressed to %d bytes, no saving", size, len(comp))
		}
		got, err := Decompress(LZ77Huffman, comp, size)
		if err != nil {
			t.Fatalf("size %d: decompress: %v", size, err)
		}
		if !bytes.Equal(got, src) {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

// TestHuffmanBlockCountMatchesSize pins the block structure itself rather than
// just the round trip: a decoder that happened to tolerate a misaligned table
// would still pass a symmetric round-trip test, so count the tables.
func TestHuffmanBlockCountMatchesSize(t *testing.T) {
	// Incompressible input makes every block's bitstream dense and its length
	// unpredictable, which is exactly the case where padding arithmetic that is
	// off by a word shows up.
	src := make([]byte, 3*huffBlockSize)
	if _, err := rand.Read(src); err != nil {
		t.Fatalf("rand: %v", err)
	}
	comp, err := Compress(LZ77Huffman, src)
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	got, err := Decompress(LZ77Huffman, comp, len(src))
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(got, src) {
		t.Fatal("round trip mismatch on incompressible input")
	}
	// Three blocks means three 256-byte tables; the payload cannot be shorter.
	if min := 3 * huffTableBytes; len(comp) < min {
		t.Errorf("compressed %d bytes, want at least %d for 3 tables", len(comp), min)
	}
}

// TestFrameCompressesLargePDUWithHuffmanOnly reproduces the negotiated set a
// Windows Server 2022 host answers with — LZ77+Huffman plus the decode-only
// Pattern_V1 — and asserts that a MaxWriteSize-shaped PDU still gets framed.
// This is the exact configuration in which uploads silently went out in the
// clear.
func TestFrameCompressesLargePDUWithHuffmanOnly(t *testing.T) {
	cfg := &Config{Algorithms: []uint16{LZ77Huffman, PatternV1}, MinSize: DefaultMinSize}
	pdu := make([]byte, 1<<20)
	copy(pdu, []byte{0xFE, 'S', 'M', 'B'})
	for i := 4; i < len(pdu); i++ {
		pdu[i] = byte(i % 61)
	}
	frame, ok := cfg.Frame(pdu)
	if !ok {
		t.Fatal("1 MiB compressible PDU was not framed")
	}
	out, err := Unframe(frame, false, DefaultMaxFrame)
	if err != nil {
		t.Fatalf("unframe: %v", err)
	}
	if !bytes.Equal(out, pdu) {
		t.Fatal("round trip mismatch through the frame layer")
	}
}

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

// TestLZ77TrailingFlagBitsAreOnes: the unused trailing flag bits of the final
// group must be ones. MS-XCA §2.4 ends decompression on a match bit with no
// input left, so zero-filled trailing bits read as "a literal follows" and the
// decompressor runs off the end of the buffer. Windows answers
// STATUS_BAD_COMPRESSION_BUFFER, which made every LZ77-compressed PDU fatal.
//
// The expected streams below were produced by Windows' own RtlCompressBuffer
// with COMPRESSION_FORMAT_XPRESS and verified to round-trip through
// RtlDecompressBuffer.
func TestLZ77TrailingFlagBitsAreOnes(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want string // hex, as produced by Windows
	}{
		{"run24", bytes.Repeat([]byte("Z"), 24), "ffffff7f5a07000d"},
		{"run26", bytes.Repeat([]byte("Z"), 26), "ffffff7f5a07000f00"},
		{"run281", bytes.Repeat([]byte("Z"), 281), "ffffff7f5a07000fff1501"},
		{"shortmatch", bytes.Repeat([]byte("ABCD"), 4), "ffffff0f414243441f0002"},
		{"twolong", append(bytes.Repeat([]byte("ab"), 20), bytes.Repeat([]byte("cd"), 20)...),
			"ffffff2761620f00ff0d63640f000d"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Compress(LZ77, tc.in)
			if err != nil {
				t.Fatalf("Compress: %v", err)
			}
			if h := hex.EncodeToString(got); h != tc.want {
				t.Errorf("stream = %s\n    want %s (Windows RtlCompressBuffer)", h, tc.want)
			}
			back, err := Decompress(LZ77, got, len(tc.in))
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if !bytes.Equal(back, tc.in) {
				t.Error("round trip mismatch")
			}
		})
	}
}

// TestLZ77DecompressAcceptsTrailingOnes: a stream whose final group is padded
// with ones must decode, since that is what every conforming encoder emits.
func TestLZ77DecompressAcceptsTrailingOnes(t *testing.T) {
	// "ffffff7f 5a 07 00 0d" — 24 'Z' as Windows encodes it.
	stream, err := hex.DecodeString("ffffff7f5a07000d")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decompress(LZ77, stream, 24)
	if err != nil {
		t.Fatalf("Decompress of a Windows-produced stream: %v", err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte("Z"), 24)) {
		t.Errorf("got %q", got)
	}
}

// TestLZ77LongMatchEscape covers the 32-bit length escape: after the 255 byte,
// a zero 16-bit word means a 32-bit length follows. Windows emits it for any run
// over ~64 KiB. Without it on the decode side a Windows-produced stream derails;
// without it on the encode side long runs are split needlessly.
//
// The expected streams are Windows RtlCompressBuffer output.
func TestLZ77LongMatchEscape(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{1000000, "ffffff7f4107000fff00003c420f00"},
		{2000000, "ffffff7f4107000fff00007c841e00"},
	}
	for _, tc := range cases {
		in := bytes.Repeat([]byte("A"), tc.n)
		got, err := Compress(LZ77, in)
		if err != nil {
			t.Fatalf("Compress(%d): %v", tc.n, err)
		}
		if h := hex.EncodeToString(got); h != tc.want {
			t.Errorf("%d bytes -> %s\n    want %s (Windows RtlCompressBuffer)", tc.n, h, tc.want)
		}
		// And the same stream must decode.
		raw, err := hex.DecodeString(tc.want)
		if err != nil {
			t.Fatal(err)
		}
		back, err := Decompress(LZ77, raw, tc.n)
		if err != nil {
			t.Fatalf("Decompress of a Windows stream (%d): %v", tc.n, err)
		}
		if !bytes.Equal(back, in) {
			t.Errorf("%d: decoded content mismatch", tc.n)
		}
	}
}

// TestLZ77ExactlyFullFlagGroupTerminates: when the item count is a multiple of
// 32 the final flag group is full, so there are no trailing one-bits to stop on
// and a terminating all-ones group must follow. Without it the decompressor
// reads a flag word past the end of the buffer.
func TestLZ77ExactlyFullFlagGroupTerminates(t *testing.T) {
	// 32 distinct bytes match nothing, so they encode as exactly 32 literal
	// items and fill one flag group precisely.
	in := make([]byte, 32)
	for i := range in {
		in[i] = byte(i)
	}
	got, err := Compress(LZ77, in)
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	back, err := Decompress(LZ77, got, len(in))
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(back, in) {
		t.Fatal("round trip mismatch")
	}
	// Windows RtlCompressBuffer emits exactly this: an all-zero flag word, the
	// 32 literals, then a terminating all-ones flag group.
	const want = "00000000000102030405060708090a0b0c0d0e0f" +
		"101112131415161718191a1b1c1d1e1fffffffff"
	if h := hex.EncodeToString(got); h != want {
		t.Errorf("stream = %s\n    want %s (Windows RtlCompressBuffer)", h, want)
	}
}
