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

import (
	"encoding/binary"
	"fmt"
)

// SMB2 compression framing (MS-SMB2 §2.2.42). Two on-wire forms share the first
// 8 bytes (ProtocolId + OriginalCompressedSegmentSize); which one is used is
// determined by whether SMB2_COMPRESSION_CAPABILITIES_FLAG_CHAINED was
// negotiated, so the receiver must be told (chained bool) rather than sniff it.
//
//	Unchained SMB2_COMPRESSION_TRANSFORM_HEADER (§2.2.42.1), 16-byte header:
//	  ProtocolId(4) OriginalSize(4) CompressionAlgorithm(2) Flags(2) Offset(4)
//	  then [Offset uncompressed bytes][compressed bytes]
//
//	Chained SMB2_COMPRESSION_TRANSFORM_HEADER_CHAINED (§2.2.42.2), 8-byte header:
//	  ProtocolId(4) OriginalSize(4)
//	  then one or more SMB2_COMPRESSION_CHAINED_PAYLOAD_HEADER (§2.2.42.2.1):
//	    CompressionAlgorithm(2) Flags(2) Length(4) [OriginalPayloadSize(4)] Data
//	  OriginalPayloadSize is present only for LZNT1/LZ77/LZ77+Huffman/LZ4, and
//	  Length counts it. Payload outputs concatenate to OriginalSize.

// ProtocolID is the 4-byte compression transform signature 0xFC 'S' 'M' 'B'.
var ProtocolID = [4]byte{0xFC, 0x53, 0x4D, 0x42}

// Chained payload header Flags (MS-SMB2 §2.2.42.2.1).
const (
	FlagNone    uint16 = 0x0000
	FlagChained uint16 = 0x0001
)

// hasOriginalSize reports whether a chained payload of the given algorithm
// carries the optional OriginalPayloadSize field (real compressors only).
func hasOriginalSize(alg uint16) bool {
	switch alg {
	case LZNT1, LZ77, LZ77Huffman, LZ4:
		return true
	default:
		return false
	}
}

// Config holds the negotiated outbound compression policy.
type Config struct {
	// Algorithms is the negotiated algorithm set in preference order. Frame
	// uses the first one it can apply.
	Algorithms []uint16
	// Chained selects the chained wire form (must match what was negotiated).
	Chained bool
	// MinSize is the smallest PDU worth attempting to compress.
	MinSize int
}

// IsCompressionFrame reports whether buf begins with the compression transform
// signature.
func IsCompressionFrame(buf []byte) bool {
	return len(buf) >= 4 && buf[0] == ProtocolID[0] && buf[1] == ProtocolID[1] &&
		buf[2] == ProtocolID[2] && buf[3] == ProtocolID[3]
}

// pickAlgorithm returns the first negotiated algorithm this package can compress
// with for a payload of the given size (Huffman is single-block only).
func (c *Config) pickAlgorithm(size int) (uint16, bool) {
	for _, a := range c.Algorithms {
		switch a {
		case LZ77Huffman:
			if size <= huffBlockSize {
				return a, true
			}
		case LZ77:
			return a, true
		}
	}
	return 0, false
}

// Frame compresses pdu into a transform frame. It returns (frame, true) when
// compression was applied and produced a smaller result, or (pdu, false) when
// compression was skipped (too small, no usable algorithm, or not beneficial),
// in which case the caller sends pdu uncompressed.
func (c *Config) Frame(pdu []byte) ([]byte, bool) {
	if len(pdu) < c.MinSize || len(c.Algorithms) == 0 {
		return pdu, false
	}
	alg, ok := c.pickAlgorithm(len(pdu))
	if !ok {
		return pdu, false
	}
	comp, err := Compress(alg, pdu)
	if err != nil {
		log.Debugf("compress %d bytes with 0x%04x: %v", len(pdu), alg, err)
		return pdu, false
	}

	var frame []byte
	if c.Chained {
		frame = frameChained(alg, comp, len(pdu))
	} else {
		frame = frameUnchained(alg, comp, len(pdu))
	}
	// Only worthwhile if the framed result is actually smaller than the raw PDU.
	if len(frame) >= len(pdu) {
		return pdu, false
	}
	return frame, true
}

func frameUnchained(alg uint16, comp []byte, origSize int) []byte {
	out := make([]byte, 16+len(comp))
	copy(out[0:4], ProtocolID[:])
	binary.LittleEndian.PutUint32(out[4:8], uint32(origSize))
	binary.LittleEndian.PutUint16(out[8:10], alg)
	binary.LittleEndian.PutUint16(out[10:12], 0) // Flags
	binary.LittleEndian.PutUint32(out[12:16], 0) // Offset: whole PDU compressed
	copy(out[16:], comp)
	return out
}

func frameChained(alg uint16, comp []byte, origSize int) []byte {
	// Single compressed payload. OriginalPayloadSize present, and Length counts
	// it (MS-SMB2 §2.2.42.2.1).
	payloadHdr := 8
	extra := 0
	if hasOriginalSize(alg) {
		extra = 4
	}
	out := make([]byte, 8+payloadHdr+extra+len(comp))
	copy(out[0:4], ProtocolID[:])
	binary.LittleEndian.PutUint32(out[4:8], uint32(origSize))
	p := 8
	binary.LittleEndian.PutUint16(out[p:], alg)
	binary.LittleEndian.PutUint16(out[p+2:], FlagChained) // first payload in chain
	binary.LittleEndian.PutUint32(out[p+4:], uint32(extra+len(comp)))
	p += payloadHdr
	if extra == 4 {
		binary.LittleEndian.PutUint32(out[p:], uint32(origSize))
		p += 4
	}
	copy(out[p:], comp)
	return out
}

// Unframe parses a compression transform frame and returns the reconstructed
// plaintext (an SMB2 PDU). chained selects the wire form; maxOutput bounds the
// declared original size to guard against decompression bombs.
func Unframe(frame []byte, chained bool, maxOutput int) ([]byte, error) {
	if !IsCompressionFrame(frame) {
		return nil, fmt.Errorf("compress: not a compression frame")
	}
	if len(frame) < 8 {
		return nil, fmt.Errorf("compress: truncated transform header")
	}
	origSize := int(binary.LittleEndian.Uint32(frame[4:8]))
	if origSize < 0 || origSize > maxOutput || origSize > maxDecompressedSize {
		return nil, fmt.Errorf("compress: declared original size %d exceeds bound %d", origSize, maxOutput)
	}
	if chained {
		return unframeChained(frame, origSize)
	}
	return unframeUnchained(frame, origSize)
}

func unframeUnchained(frame []byte, origSize int) ([]byte, error) {
	if len(frame) < 16 {
		return nil, fmt.Errorf("compress: truncated unchained header")
	}
	alg := binary.LittleEndian.Uint16(frame[8:10])
	offset := int(binary.LittleEndian.Uint32(frame[12:16]))
	if offset < 0 || 16+offset > len(frame) || offset > origSize {
		return nil, fmt.Errorf("compress: bad unchained offset %d", offset)
	}
	prefix := frame[16 : 16+offset]
	compressed := frame[16+offset:]
	decompressed, err := Decompress(alg, compressed, origSize-offset)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, origSize)
	out = append(out, prefix...)
	out = append(out, decompressed...)
	if len(out) != origSize {
		return nil, fmt.Errorf("compress: unchained output %d != declared %d", len(out), origSize)
	}
	return out, nil
}

func unframeChained(frame []byte, origSize int) ([]byte, error) {
	out := make([]byte, 0, origSize)
	pos := 8
	for pos < len(frame) {
		if pos+8 > len(frame) {
			return nil, fmt.Errorf("compress: truncated chained payload header")
		}
		alg := binary.LittleEndian.Uint16(frame[pos:])
		length := int(binary.LittleEndian.Uint32(frame[pos+4:]))
		pos += 8
		if length < 0 || pos+length > len(frame) {
			return nil, fmt.Errorf("compress: chained payload length %d out of range", length)
		}
		payload := frame[pos : pos+length]
		pos += length

		if hasOriginalSize(alg) {
			if len(payload) < 4 {
				return nil, fmt.Errorf("compress: chained payload missing OriginalPayloadSize")
			}
			payloadOrig := int(binary.LittleEndian.Uint32(payload[0:4]))
			if payloadOrig < 0 || len(out)+payloadOrig > origSize {
				return nil, fmt.Errorf("compress: chained payload size %d overruns %d", payloadOrig, origSize)
			}
			dec, err := Decompress(alg, payload[4:], payloadOrig)
			if err != nil {
				return nil, err
			}
			out = append(out, dec...)
			continue
		}

		switch alg {
		case None:
			if len(out)+len(payload) > origSize {
				return nil, fmt.Errorf("compress: raw chained payload overruns %d", origSize)
			}
			out = append(out, payload...)
		case PatternV1:
			if len(payload) != patternPayloadSize {
				return nil, fmt.Errorf("compress: bad Pattern_V1 payload length %d", len(payload))
			}
			reps := int(binary.LittleEndian.Uint32(payload[4:8]))
			if len(out)+reps > origSize {
				return nil, fmt.Errorf("compress: Pattern_V1 overruns %d", origSize)
			}
			dec, err := patternDecompress(payload, reps)
			if err != nil {
				return nil, err
			}
			out = append(out, dec...)
		default:
			return nil, fmt.Errorf("compress: unsupported chained algorithm 0x%04x", alg)
		}
	}
	if len(out) != origSize {
		return nil, fmt.Errorf("compress: chained output %d != declared %d", len(out), origSize)
	}
	return out, nil
}
