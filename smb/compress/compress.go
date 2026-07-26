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

// Package compress implements the SMB2/3 compression algorithms defined by
// MS-SMB2 §2.2.42 and MS-XCA. It has no dependency on the smb package so that
// smb (and smb/server) may import it without a cycle.
//
// Supported algorithms:
//
//	LZNT1          (0x0001) — not implemented
//	LZ77 (Plain)   (0x0002) — implemented (lzxpress.go)
//	LZ77+Huffman   (0x0003) — implemented (huffman.go)
//	Pattern_V1     (0x0004) — implemented (pattern.go)
//	LZ4            (0x0005) — not implemented
//
// The library exposes raw per-algorithm Compress/Decompress. Framing (the
// SMB2_COMPRESSION_TRANSFORM_HEADER, chained payloads, and the Pattern_V1
// payload header) lives in frame.go.
package compress

import (
	"fmt"

	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/compress").SetDisplayName("compress")

// Compression algorithm identifiers (MS-SMB2 §2.2.3.1.3). Mirrored from the
// smb package to keep this package dependency-free.
const (
	None        uint16 = 0x0000
	LZNT1       uint16 = 0x0001
	LZ77        uint16 = 0x0002
	LZ77Huffman uint16 = 0x0003
	PatternV1   uint16 = 0x0004
	LZ4         uint16 = 0x0005
)

// maxDecompressedSize is a hard ceiling on the output of a single Decompress
// call, a defense against decompression bombs. Callers that know the negotiated
// MaxReadSize/MaxWriteSize should pass a tighter originalSize; this is only the
// absolute cap when the declared size itself is used for allocation.
const maxDecompressedSize = 16 << 20 // 16 MiB

// IsSupported reports whether this package can both compress and decompress the
// given algorithm id (Pattern_V1 excepted — it is decode-heavy and only emitted
// inside chained frames).
func IsSupported(alg uint16) bool {
	switch alg {
	case LZ77, LZ77Huffman, PatternV1:
		return true
	default:
		return false
	}
}

// Decompress expands src (the compressed payload for a single algorithm, not a
// framed PDU) into exactly originalSize bytes. originalSize is the value the
// sender declared in the transform/payload header and is validated against
// maxDecompressedSize before any allocation.
func Decompress(alg uint16, src []byte, originalSize int) ([]byte, error) {
	if originalSize < 0 || originalSize > maxDecompressedSize {
		return nil, fmt.Errorf("compress: declared decompressed size %d out of range", originalSize)
	}
	switch alg {
	case LZ77:
		return lz77Decompress(src, originalSize)
	case LZ77Huffman:
		return lz77HuffmanDecompress(src, originalSize)
	case PatternV1:
		return patternDecompress(src, originalSize)
	default:
		return nil, fmt.Errorf("compress: decompress algorithm 0x%04x not implemented", alg)
	}
}

// Compress produces the compressed payload for src using the given algorithm.
// The returned bytes are the algorithm payload only; the caller frames them.
func Compress(alg uint16, src []byte) ([]byte, error) {
	switch alg {
	case LZ77:
		return lz77Compress(src), nil
	case LZ77Huffman:
		return lz77HuffmanCompress(src)
	default:
		return nil, fmt.Errorf("compress: compress algorithm 0x%04x not implemented", alg)
	}
}
