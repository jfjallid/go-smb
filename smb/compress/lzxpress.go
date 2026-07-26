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

// LZXPRESS Plain (a.k.a. LZ77, MS-XCA §2.3–2.4). The stream is a sequence of
// flag groups: a 32-bit little-endian "indicator" word followed by up to 32
// items. Reading the indicator MSB first, a 0 bit means the next item is a
// literal byte; a 1 bit means a (length, offset) back-reference encoded as a
// 16-bit word (offset = (word>>3)+1, length = word&7) with a nibble/byte/word
// extension ladder when length == 7.

const (
	lz77MinMatch  = 3
	lz77MaxOffset = 8192 // 13-bit offset field: offset-1 must fit in 13 bits
)

// lz77Decompress implements MS-XCA §2.4. originalSize is the expected output
// length and bounds both the output buffer and the loop.
func lz77Decompress(input []byte, originalSize int) ([]byte, error) {
	out := make([]byte, 0, originalSize)
	var (
		inPos        int
		indicator    uint32
		indicatorBit int
		nibblePos    int = -1 // index of a byte with a pending high nibble, -1 if none
	)

	for {
		if indicatorBit == 0 {
			if inPos+4 > len(input) {
				break
			}
			indicator = binary.LittleEndian.Uint32(input[inPos:])
			inPos += 4
			indicatorBit = 32
		}
		indicatorBit--

		if (indicator>>uint(indicatorBit))&1 == 0 {
			// Literal.
			if inPos >= len(input) {
				break
			}
			out = append(out, input[inPos])
			inPos++
		} else {
			// Match.
			if inPos+2 > len(input) {
				return nil, fmt.Errorf("compress/lz77: truncated match word at %d", inPos)
			}
			word := binary.LittleEndian.Uint16(input[inPos:])
			inPos += 2
			offset := int(word>>3) + 1
			length := int(word & 7)

			if length == 7 {
				// Nibble extension.
				if nibblePos < 0 {
					if inPos >= len(input) {
						return nil, fmt.Errorf("compress/lz77: truncated nibble at %d", inPos)
					}
					length = int(input[inPos] & 0x0f)
					nibblePos = inPos
					inPos++
				} else {
					length = int(input[nibblePos] >> 4)
					nibblePos = -1
				}
				if length == 15 {
					// Byte extension.
					if inPos >= len(input) {
						return nil, fmt.Errorf("compress/lz77: truncated length byte at %d", inPos)
					}
					length = int(input[inPos])
					inPos++
					if length == 255 {
						// Word extension.
						if inPos+2 > len(input) {
							return nil, fmt.Errorf("compress/lz77: truncated length word at %d", inPos)
						}
						length = int(binary.LittleEndian.Uint16(input[inPos:]))
						inPos += 2
						length -= 15 + 7
					}
					length += 15
				}
				length += 7
			}
			length += lz77MinMatch

			if offset > len(out) {
				return nil, fmt.Errorf("compress/lz77: back-reference offset %d exceeds output length %d", offset, len(out))
			}
			if len(out)+length > originalSize {
				return nil, fmt.Errorf("compress/lz77: output overruns declared size %d", originalSize)
			}
			// Copy byte-by-byte: overlapping runs (offset < length) are legal
			// and rely on bytes just produced.
			start := len(out) - offset
			for i := 0; i < length; i++ {
				out = append(out, out[start+i])
			}
		}

		if len(out) >= originalSize {
			break
		}
	}

	if len(out) != originalSize {
		return nil, fmt.Errorf("compress/lz77: decompressed %d bytes, expected %d", len(out), originalSize)
	}
	return out, nil
}

// lz77Compress produces a valid MS-XCA §2.4 stream for src using greedy hash-
// chain matching. Any valid encoding decompresses correctly; this favors
// simplicity over ratio.
func lz77Compress(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	var out []byte

	// Hash chains keyed on 3-byte sequences. head[h] = most recent position
	// with hash h; prev[pos] = previous position sharing the chain.
	const hashBits = 15
	const hashSize = 1 << hashBits
	head := make([]int, hashSize)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int, len(src))

	hash3 := func(p int) uint32 {
		h := uint32(src[p]) | uint32(src[p+1])<<8 | uint32(src[p+2])<<16
		return (h * 2654435761) >> (32 - hashBits)
	}

	// Flag-group bookkeeping: indicatorPos is the output index of the current
	// 32-bit indicator word (reserved, backfilled); indicator accumulates bits
	// MSB-first to match the decompressor.
	var (
		indicator    uint32
		indicatorBit int = -1 // next bit index (31..0); -1 forces a new word
		indicatorPos int
		nibblePos    int = -1
	)

	flushIndicator := func() {
		binary.LittleEndian.PutUint32(out[indicatorPos:], indicator)
	}
	newGroup := func() {
		indicatorPos = len(out)
		out = append(out, 0, 0, 0, 0)
		indicator = 0
		indicatorBit = 31
	}
	setBit := func(one bool) {
		if indicatorBit < 0 {
			newGroup()
		}
		if one {
			indicator |= 1 << uint(indicatorBit)
		}
		indicatorBit--
		if indicatorBit < 0 {
			flushIndicator()
		}
	}

	i := 0
	for i < len(src) {
		bestLen, bestOff := 0, 0
		if i+lz77MinMatch <= len(src) {
			h := hash3(i)
			cand := head[h]
			chainLimit := 64
			minPos := i - lz77MaxOffset
			for cand >= 0 && cand >= minPos && chainLimit > 0 {
				chainLimit--
				l := matchLen(src, cand, i)
				if l > bestLen {
					bestLen = l
					bestOff = i - cand
					if i+l >= len(src) {
						break
					}
				}
				cand = prev[cand]
			}
		}

		if bestLen >= lz77MinMatch {
			setBit(true)
			encodeLz77Match(&out, &nibblePos, bestLen, bestOff)
			// Insert hash entries for the covered span so later matches can
			// reference into it.
			end := i + bestLen
			for ; i < end && i+lz77MinMatch <= len(src); i++ {
				h := hash3(i)
				prev[i] = head[h]
				head[h] = i
			}
			i = end
		} else {
			setBit(false)
			out = append(out, src[i])
			if i+lz77MinMatch <= len(src) {
				h := hash3(i)
				prev[i] = head[h]
				head[h] = i
			}
			i++
		}
	}
	// Backfill the final (partial) indicator word.
	if indicatorBit >= 0 {
		flushIndicator()
	}
	return out
}

// matchLen returns the length of the common run at a (candidate) and b
// (current), capped so it stays within src.
func matchLen(src []byte, a, b int) int {
	n := 0
	for b+n < len(src) && src[a+n] == src[b+n] {
		n++
		if n == 0xffff+lz77MinMatch { // keep length encodable
			break
		}
	}
	return n
}

// encodeLz77Match writes a match of the given length/offset, mirroring the
// decompressor's nibble/byte/word extension ladder. nibblePos tracks the shared
// half-byte position across matches.
func encodeLz77Match(out *[]byte, nibblePos *int, length, offset int) {
	word := uint16((offset-1)<<3) & 0xfff8
	if length <= 9 {
		word |= uint16(length - lz77MinMatch)
		*out = appendU16(*out, word)
		return
	}
	word |= 7
	*out = appendU16(*out, word)

	nib := length - 10 // decompressor: match = nibble + 10 for nibble < 15
	if nib < 15 {
		writeNibble(out, nibblePos, byte(nib))
		return
	}
	writeNibble(out, nibblePos, 15)

	b := length - 25 // decompressor: match = byte + 25 for byte < 255
	if b < 255 {
		*out = append(*out, byte(b))
		return
	}
	*out = append(*out, 255)
	*out = appendU16(*out, uint16(length-lz77MinMatch)) // word branch: match = word + 3
}

// writeNibble stores v in the low nibble of a fresh byte (recording its
// position) or, if a byte with a pending high nibble exists, in that high
// nibble — matching the decompressor's shared-nibble bookkeeping.
func writeNibble(out *[]byte, nibblePos *int, v byte) {
	if *nibblePos < 0 {
		*nibblePos = len(*out)
		*out = append(*out, v&0x0f)
	} else {
		(*out)[*nibblePos] |= (v & 0x0f) << 4
		*nibblePos = -1
	}
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}
