// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package compress

import "fmt"

// DefaultMinSize is the smallest PDU worth attempting to compress. Below this
// the transform-header overhead dominates any saving.
const DefaultMinSize = 256

// DefaultMaxFrame bounds the declared original size of an inbound compression
// frame — a decompression-bomb guard. It is deliberately the same value on both
// sides of the protocol so client and server share one policy.
const DefaultMaxFrame = 16 << 20 // 16 MiB

// DefaultAlgorithms is the algorithm set offered/advertised when a caller does
// not override it, in preference order.
var DefaultAlgorithms = []uint16{LZ77Huffman, LZ77, PatternV1}

// Codec holds the per-connection compression state negotiated with the peer and
// implements the two operations both endpoints need. The client
// (smb.Connection) and the server (server.Conn) each embed one, so the framing
// policy, the decompression-bomb bound, and — critically — the "was compression
// actually negotiated?" gate live in exactly one place.
//
// The zero value is a valid, inactive codec: Compress passes PDUs through
// untouched and Decompress rejects every frame. That is the correct posture
// before (and when a peer never completes) negotiation.
type Codec struct {
	// Algorithms is the negotiated algorithm set (intersection with the peer,
	// in our preference order). Empty means compression is not active.
	Algorithms []uint16
	// Chained records whether the chained transform wire form was negotiated.
	Chained bool

	// out is the outbound framing policy. It is nil when we negotiated
	// algorithms we can only decode (Pattern_V1), in which case we accept
	// compressed frames but never emit them.
	out *Config
	// maxFrame bounds an inbound frame's declared original size; zero means
	// DefaultMaxFrame.
	maxFrame int
}

// Configure records the negotiated result and builds the outbound policy.
// algorithms is the negotiated set; passing an empty set (or one containing
// nothing we can compress with) leaves the codec receive-only or fully
// inactive. minSize of 0 selects DefaultMinSize.
func (c *Codec) Configure(algorithms []uint16, chained bool, minSize int) {
	c.Algorithms = append([]uint16(nil), algorithms...)
	c.Chained = chained
	c.out = nil
	if minSize <= 0 {
		minSize = DefaultMinSize
	}
	if len(c.Algorithms) == 0 {
		return
	}
	// Only algorithms we can actually compress with may be emitted. Pattern_V1
	// is decode-only here: it is cheap to accept inside a chained frame but we
	// never generate it.
	var sendAlgs []uint16
	for _, alg := range c.Algorithms {
		if alg != PatternV1 && IsSupported(alg) {
			sendAlgs = append(sendAlgs, alg)
		}
	}
	if len(sendAlgs) == 0 {
		return
	}
	c.out = &Config{Algorithms: sendAlgs, Chained: chained, MinSize: minSize}
}

// Reset returns the codec to its inactive state.
func (c *Codec) Reset() {
	c.Algorithms = nil
	c.Chained = false
	c.out = nil
}

// Negotiated reports whether compression was negotiated with the peer. When it
// is false, an inbound compression frame is a protocol violation: no peer may
// compress before both sides agreed to it, so accepting one would let an
// unauthenticated client drive the decompressor.
func (c *Codec) Negotiated() bool { return len(c.Algorithms) > 0 }

// SetMaxFrame overrides the inbound decompression bound. Zero restores the
// default.
func (c *Codec) SetMaxFrame(n int) { c.maxFrame = n }

func (c *Codec) frameBound() int {
	if c.maxFrame > 0 {
		return c.maxFrame
	}
	return DefaultMaxFrame
}

// Compress wraps a plaintext SMB2 PDU in a compression-transform frame when
// compression is active and the framed result is actually smaller. Anything
// else — an inactive codec, a non-SMB2 buffer, an incompressible payload — is
// returned unchanged, so callers can use this unconditionally.
func (c *Codec) Compress(pdu []byte) []byte {
	if c.out == nil {
		return pdu
	}
	// Only a plaintext SMB2 PDU may be compressed. Guarding here keeps callers
	// from having to check, and stops an already-framed buffer (transform or
	// compression header) being wrapped a second time.
	if len(pdu) < 4 || pdu[0] != smb2ProtocolID[0] || pdu[1] != smb2ProtocolID[1] ||
		pdu[2] != smb2ProtocolID[2] || pdu[3] != smb2ProtocolID[3] {
		return pdu
	}
	out, ok := c.out.Frame(pdu)
	if !ok {
		// Frame declined (too small, no usable algorithm, or no saving) and
		// returned pdu unchanged. Nothing to report: not compressing is a
		// normal, correct outcome.
		return pdu
	}
	return out
}

// smb2ProtocolID is the plaintext SMB2 signature 0xFE 'S' 'M' 'B'. Mirrored
// here (rather than imported from the smb package) to keep this package
// dependency-free — smb and smb/server both import it.
var smb2ProtocolID = [4]byte{0xFE, 0x53, 0x4D, 0x42}

// Decompress unwraps a compression-transform frame into the original SMB2 PDU.
// It rejects frames outright when compression was never negotiated.
//
// The wire form (chained vs unchained) nominally follows what was negotiated,
// but the two cannot be told apart by inspection alone: the discriminating bit
// would be SMB2_COMPRESSION_FLAG_CHAINED in the first payload header, and a
// single-payload chained frame is permitted to leave it clear. So we parse with
// the negotiated form and, only if that fails, retry with the other. Both forms
// verify that the reconstructed output length equals the size the sender
// declared, which makes a silent mis-parse effectively impossible — a wrong
// guess errors rather than yielding wrong bytes.
func (c *Codec) Decompress(frame []byte) ([]byte, error) {
	if !c.Negotiated() {
		return nil, fmt.Errorf("compress: received a compression frame but compression was not negotiated")
	}
	out, err := Unframe(frame, c.Chained, c.frameBound())
	if err == nil {
		return out, nil
	}
	if alt, altErr := Unframe(frame, !c.Chained, c.frameBound()); altErr == nil {
		return alt, nil
	}
	return nil, err
}

// DecompressIfFramed is Decompress for call sites that may or may not be
// holding a compression frame: non-frames pass through untouched.
func (c *Codec) DecompressIfFramed(buf []byte) ([]byte, error) {
	if !IsCompressionFrame(buf) {
		return buf, nil
	}
	return c.Decompress(buf)
}
