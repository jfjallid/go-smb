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

// SMB2_COMPRESSION_PATTERN_PAYLOAD_V1 (MS-SMB2 §2.2.42.2.1). Pattern_V1 encodes
// a run of a single repeated byte. It is only ever carried inside a chained
// SMB2_COMPRESSION_TRANSFORM_HEADER payload.
//
//	Pattern     (1 byte)  — the byte to repeat
//	Reserved1   (1 byte)  — MUST be 0
//	Reserved2   (2 bytes) — MUST be 0
//	Repetitions (4 bytes) — count of Pattern bytes to emit
const patternPayloadSize = 8

// patternDecompress expands an 8-byte Pattern_V1 payload into originalSize
// bytes of the single repeated pattern byte. originalSize MUST equal the
// declared Repetitions.
func patternDecompress(src []byte, originalSize int) ([]byte, error) {
	if len(src) != patternPayloadSize {
		return nil, fmt.Errorf("compress: Pattern_V1 payload is %d bytes, want %d", len(src), patternPayloadSize)
	}
	reps := binary.LittleEndian.Uint32(src[4:8])
	if int(reps) != originalSize {
		return nil, fmt.Errorf("compress: Pattern_V1 repetitions %d != declared size %d", reps, originalSize)
	}
	out := make([]byte, originalSize)
	if originalSize > 0 {
		out[0] = src[0]
		// Doubling fill: O(n) with log(n) copies.
		for filled := 1; filled < originalSize; filled *= 2 {
			copy(out[filled:], out[:filled])
		}
	}
	return out, nil
}

// EncodePatternV1 builds the 8-byte Pattern_V1 payload for a run of b repeated
// reps times. Exposed for the framing layer, which decides when a buffer is a
// pure run worth pattern-encoding.
func EncodePatternV1(b byte, reps uint32) []byte {
	out := make([]byte, patternPayloadSize)
	out[0] = b
	binary.LittleEndian.PutUint32(out[4:8], reps)
	return out
}

// SingleByteRun reports whether buf is a run of one repeated byte (length >= 1),
// returning that byte. The framing layer uses this to decide whether a
// Pattern_V1 payload is applicable.
func SingleByteRun(buf []byte) (b byte, ok bool) {
	if len(buf) == 0 {
		return 0, false
	}
	b = buf[0]
	for _, x := range buf[1:] {
		if x != b {
			return 0, false
		}
	}
	return b, true
}
