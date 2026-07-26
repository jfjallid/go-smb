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

// LZXPRESS Huffman (LZ77+Huffman, MS-XCA §2.1–2.2). The decoder is a faithful
// port of the reference algorithm (matching Samba's tested implementation) and
// handles the full format: multi-block (64 KiB), the aligned length-extension
// ladder (byte/uint16/uint32), and distances up to 15 extra bits.
//
// The encoder is deliberately restricted to what round-trips bit-exactly with
// the least machinery: a single ≤64 KiB block, and matches capped at length 17
// so the Huffman length nibble is never 15 — which means no aligned
// length-extension bytes are ever emitted, so the bitstream and byte cursor do
// not interleave. Larger inputs are the caller's responsibility (fall back to
// LZ77 plain or send uncompressed).

const (
	huffAlphabet    = 512
	huffMaxCodeLen  = 15
	huffBlockSize   = 65536
	huffTableBytes  = 256 // 512 symbols × 4 bits
	huffMinMatch    = 3
	huffMaxEncMatch = 17 // encoder cap: length nibble stays ≤ 14
	huffMaxDistance = 65535
)

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

// huffBitReader shares a single byte cursor between the 16-bit-word bit
// accumulator and the aligned length-extension reads, exactly as MS-XCA
// specifies.
type huffBitReader struct {
	bytes     []byte
	pos       int
	bits      uint32
	remaining int
}

func (r *huffBitReader) prime() error {
	var w0, w1 uint16
	var err error
	if w0, err = r.readAlignedU16(); err != nil {
		return err
	}
	if w1, err = r.readAlignedU16(); err != nil {
		return err
	}
	r.bits = (uint32(w0) << 16) | uint32(w1)
	r.remaining = 32
	return nil
}

func (r *huffBitReader) pull() error {
	if r.pos+1 < len(r.bytes) {
		w, _ := r.readAlignedU16()
		r.remaining += 16
		r.bits = (r.bits << 16) | uint32(w)
	} else if r.pos < len(r.bytes) {
		b := r.bytes[r.pos]
		r.pos++
		r.remaining += 8
		r.bits = (r.bits << 8) | uint32(b)
	} else {
		return fmt.Errorf("compress/huffman: bitstream underrun")
	}
	return nil
}

func (r *huffBitReader) readBit() (uint32, error) {
	if r.remaining == 16 {
		if err := r.pull(); err != nil {
			return 0, err
		}
	}
	r.remaining--
	return (r.bits >> uint(r.remaining)) & 1, nil
}

func (r *huffBitReader) readAlignedU8() (uint8, error) {
	if r.pos >= len(r.bytes) {
		return 0, fmt.Errorf("compress/huffman: truncated aligned byte")
	}
	b := r.bytes[r.pos]
	r.pos++
	return b, nil
}

func (r *huffBitReader) readAlignedU16() (uint16, error) {
	if r.pos+2 > len(r.bytes) {
		return 0, fmt.Errorf("compress/huffman: truncated aligned u16")
	}
	v := binary.LittleEndian.Uint16(r.bytes[r.pos:])
	r.pos += 2
	return v, nil
}

func (r *huffBitReader) readAlignedU32() (uint32, error) {
	if r.pos+4 > len(r.bytes) {
		return 0, fmt.Errorf("compress/huffman: truncated aligned u32")
	}
	v := binary.LittleEndian.Uint32(r.bytes[r.pos:])
	r.pos += 4
	return v, nil
}

// huffDecoder is a canonical-Huffman decode structure built from 512 code
// lengths. Symbols are decoded bit-by-bit MSB-first, which reproduces the same
// canonical assignment MS-XCA uses (sort by (length, symbol), assign ascending
// codes).
type huffDecoder struct {
	firstCode   [huffMaxCodeLen + 1]uint32 // first canonical code of each length
	firstSymIdx [huffMaxCodeLen + 1]int    // index into sortedSyms where length begins
	count       [huffMaxCodeLen + 1]int
	sortedSyms  []uint16 // symbols ordered by (length, symbol)
}

func newHuffDecoder(lengths []uint8) (*huffDecoder, error) {
	d := &huffDecoder{}
	for _, l := range lengths {
		if l > huffMaxCodeLen {
			return nil, fmt.Errorf("compress/huffman: code length %d exceeds max %d", l, huffMaxCodeLen)
		}
		if l > 0 {
			d.count[l]++
		}
	}
	// sortedSyms grouped by length then ascending symbol.
	total := 0
	for l := 1; l <= huffMaxCodeLen; l++ {
		d.firstSymIdx[l] = total
		total += d.count[l]
	}
	d.sortedSyms = make([]uint16, total)
	next := d.firstSymIdx
	for sym, l := range lengths {
		if l > 0 {
			d.sortedSyms[next[l]] = uint16(sym)
			next[l]++
		}
	}
	// Canonical first codes.
	code := uint32(0)
	for l := 1; l <= huffMaxCodeLen; l++ {
		d.firstCode[l] = code
		code = (code + uint32(d.count[l])) << 1
	}
	return d, nil
}

func (d *huffDecoder) decodeSymbol(r *huffBitReader) (uint16, error) {
	code := uint32(0)
	for l := 1; l <= huffMaxCodeLen; l++ {
		b, err := r.readBit()
		if err != nil {
			return 0, err
		}
		code = (code << 1) | b
		if d.count[l] > 0 {
			if delta := code - d.firstCode[l]; delta < uint32(d.count[l]) {
				return d.sortedSyms[d.firstSymIdx[l]+int(delta)], nil
			}
		}
	}
	return 0, fmt.Errorf("compress/huffman: invalid Huffman code")
}

func lz77HuffmanDecompress(src []byte, originalSize int) ([]byte, error) {
	out := make([]byte, 0, originalSize)
	r := &huffBitReader{bytes: src}

	for len(out) < originalSize {
		// Each block re-reads a 256-byte code-length table and re-primes the
		// bit reader.
		if r.pos+huffTableBytes > len(r.bytes) {
			return nil, fmt.Errorf("compress/huffman: truncated code table")
		}
		lengths := make([]uint8, huffAlphabet)
		for i := 0; i < huffTableBytes; i++ {
			b := r.bytes[r.pos+i]
			lengths[2*i] = b & 0x0f
			lengths[2*i+1] = b >> 4
		}
		r.pos += huffTableBytes

		dec, err := newHuffDecoder(lengths)
		if err != nil {
			return nil, err
		}
		if err := r.prime(); err != nil {
			return nil, err
		}

		blockEnd := len(out) + huffBlockSize
		if blockEnd > originalSize {
			blockEnd = originalSize
		}

		for len(out) < blockEnd {
			sym, err := dec.decodeSymbol(r)
			if err != nil {
				return nil, err
			}
			if sym < 256 {
				out = append(out, byte(sym))
				continue
			}
			// Match.
			distanceBits := int((sym >> 4) & 15)
			length := int(sym & 15)
			if length == 15 {
				b, err := r.readAlignedU8()
				if err != nil {
					return nil, err
				}
				length += int(b)
				if length == 255+15 {
					l16, err := r.readAlignedU16()
					if err != nil {
						return nil, err
					}
					length = int(l16)
					if length == 0 {
						l32, err := r.readAlignedU32()
						if err != nil {
							return nil, err
						}
						length = int(l32)
					}
				}
			}
			length += huffMinMatch

			distance := 1 << uint(distanceBits)
			for i := distanceBits - 1; i >= 0; i-- {
				b, err := r.readBit()
				if err != nil {
					return nil, err
				}
				distance |= int(b) << uint(i)
			}

			if distance > len(out) {
				return nil, fmt.Errorf("compress/huffman: distance %d exceeds output %d", distance, len(out))
			}
			if len(out)+length > originalSize {
				return nil, fmt.Errorf("compress/huffman: match overruns declared size %d", originalSize)
			}
			start := len(out) - distance
			for i := 0; i < length; i++ {
				out = append(out, out[start+i])
			}
		}
	}

	if len(out) != originalSize {
		return nil, fmt.Errorf("compress/huffman: decompressed %d bytes, expected %d", len(out), originalSize)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

type huffToken struct {
	isMatch  bool
	literal  byte
	length   int // match length (3..17)
	distance int // match distance (>=1)
}

// symbolOf returns the Huffman alphabet symbol for a token (literals map to
// themselves; matches to 256 + distanceBits<<4 + (length-3)).
func (t huffToken) symbolOf() uint16 {
	if !t.isMatch {
		return uint16(t.literal)
	}
	distanceBits := bitLength(t.distance) - 1
	return uint16(256 + (distanceBits << 4) + (t.length - huffMinMatch))
}

func lz77HuffmanCompress(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, fmt.Errorf("compress/huffman: refusing to compress empty input")
	}
	if len(src) > huffBlockSize {
		return nil, fmt.Errorf("compress/huffman: input %d exceeds single-block limit %d", len(src), huffBlockSize)
	}

	tokens := huffTokenize(src)

	// Frequencies over the 512-symbol alphabet.
	freq := make([]int, huffAlphabet)
	for _, t := range tokens {
		freq[t.symbolOf()]++
	}

	lengths := lengthLimitedHuffman(freq, huffMaxCodeLen)
	codes := canonicalCodes(lengths)

	// 256-byte code-length table.
	out := make([]byte, huffTableBytes)
	for i := 0; i < huffTableBytes; i++ {
		out[i] = lengths[2*i] | (lengths[2*i+1] << 4)
	}

	// Bitstream.
	bw := &huffBitWriter{}
	for _, t := range tokens {
		sym := t.symbolOf()
		bw.writeBits(codes[sym], int(lengths[sym]))
		if t.isMatch {
			distanceBits := bitLength(t.distance) - 1
			extra := t.distance - (1 << uint(distanceBits))
			bw.writeBits(uint32(extra), distanceBits)
		}
	}
	bitBytes := bw.finish()
	out = append(out, bitBytes...)
	return out, nil
}

// huffTokenize does greedy hash-chain LZ77 matching capped at length 17 /
// distance 65535 so every match encodes without aligned length bytes.
func huffTokenize(src []byte) []huffToken {
	var tokens []huffToken

	const hashBits = 15
	head := make([]int, 1<<hashBits)
	for i := range head {
		head[i] = -1
	}
	prev := make([]int, len(src))
	hash3 := func(p int) uint32 {
		h := uint32(src[p]) | uint32(src[p+1])<<8 | uint32(src[p+2])<<16
		return (h * 2654435761) >> (32 - hashBits)
	}

	i := 0
	for i < len(src) {
		bestLen, bestDist := 0, 0
		if i+huffMinMatch <= len(src) {
			h := hash3(i)
			cand := head[h]
			minPos := i - huffMaxDistance
			chain := 64
			for cand >= 0 && cand >= minPos && chain > 0 {
				chain--
				l := 0
				for i+l < len(src) && l < huffMaxEncMatch && src[cand+l] == src[i+l] {
					l++
				}
				if l > bestLen {
					bestLen = l
					bestDist = i - cand
				}
				cand = prev[cand]
			}
		}
		if bestLen >= huffMinMatch {
			tokens = append(tokens, huffToken{isMatch: true, length: bestLen, distance: bestDist})
			end := i + bestLen
			for ; i < end && i+huffMinMatch <= len(src); i++ {
				h := hash3(i)
				prev[i] = head[h]
				head[h] = i
			}
			i = end
		} else {
			tokens = append(tokens, huffToken{literal: src[i]})
			if i+huffMinMatch <= len(src) {
				h := hash3(i)
				prev[i] = head[h]
				head[h] = i
			}
			i++
		}
	}
	return tokens
}

// huffBitWriter accumulates bits MSB-first into 16-bit little-endian words,
// mirroring the decoder's per-word MSB-first consumption.
type huffBitWriter struct {
	out        []byte
	word       uint32
	bitsInWord int
}

func (w *huffBitWriter) writeBit(b uint32) {
	w.word = (w.word << 1) | (b & 1)
	w.bitsInWord++
	if w.bitsInWord == 16 {
		w.out = append(w.out, byte(w.word), byte(w.word>>8))
		w.word = 0
		w.bitsInWord = 0
	}
}

func (w *huffBitWriter) writeBits(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		w.writeBit((v >> uint(i)) & 1)
	}
}

// finish flushes a partial word (left-justified, zero-padded) and appends the
// look-ahead words the decoder needs. The decoder primes two 16-bit words and
// always pulls one word ahead of the word it is consuming, so to decode the
// final data word it fetches the following word; two trailing zero words
// guarantee that pull (and the initial two-word prime) never underruns. Windows
// encoders pad for the same reason; the trailing bytes are inside the declared
// compressed length and are ignored once the output size is reached.
func (w *huffBitWriter) finish() []byte {
	if w.bitsInWord > 0 {
		w.word <<= uint(16 - w.bitsInWord)
		w.out = append(w.out, byte(w.word), byte(w.word>>8))
		w.word = 0
		w.bitsInWord = 0
	}
	w.out = append(w.out, 0, 0, 0, 0) // two look-ahead words
	for len(w.out) < 4 {
		w.out = append(w.out, 0)
	}
	return w.out
}

// ---------------------------------------------------------------------------
// Length-limited canonical Huffman (package-merge)
// ---------------------------------------------------------------------------

// canonicalCodes assigns canonical codes to symbols given their code lengths
// (0 = unused), sorted by (length, symbol).
func canonicalCodes(lengths []uint8) []uint32 {
	var count [huffMaxCodeLen + 1]int
	for _, l := range lengths {
		if l > 0 {
			count[l]++
		}
	}
	var nextCode [huffMaxCodeLen + 1]uint32
	code := uint32(0)
	for l := 1; l <= huffMaxCodeLen; l++ {
		nextCode[l] = code
		code = (code + uint32(count[l])) << 1
	}
	codes := make([]uint32, len(lengths))
	for sym, l := range lengths {
		if l > 0 {
			codes[sym] = nextCode[l]
			nextCode[l]++
		}
	}
	return codes
}

// lengthLimitedHuffman returns optimal code lengths (each ≤ maxLen) for the
// given symbol frequencies using the boundary package-merge algorithm.
func lengthLimitedHuffman(freq []int, maxLen int) []uint8 {
	type pkg struct {
		weight int
		syms   []int
	}
	var leaves []pkg
	for s, f := range freq {
		if f > 0 {
			leaves = append(leaves, pkg{weight: f, syms: []int{s}})
		}
	}
	lengths := make([]uint8, len(freq))
	n := len(leaves)
	if n == 0 {
		return lengths
	}
	if n == 1 {
		lengths[leaves[0].syms[0]] = 1
		return lengths
	}
	// Sort leaves ascending by weight, stable on symbol for determinism.
	// Insertion sort — n ≤ 512.
	for i := 1; i < len(leaves); i++ {
		for j := i; j > 0; j-- {
			if leaves[j].weight < leaves[j-1].weight ||
				(leaves[j].weight == leaves[j-1].weight && leaves[j].syms[0] < leaves[j-1].syms[0]) {
				leaves[j], leaves[j-1] = leaves[j-1], leaves[j]
			} else {
				break
			}
		}
	}

	merge := func(a, b []pkg) []pkg {
		res := make([]pkg, 0, len(a)+len(b))
		i, j := 0, 0
		for i < len(a) && j < len(b) {
			if a[i].weight <= b[j].weight {
				res = append(res, a[i])
				i++
			} else {
				res = append(res, b[j])
				j++
			}
		}
		res = append(res, a[i:]...)
		res = append(res, b[j:]...)
		return res
	}
	packageUp := func(s []pkg) []pkg {
		res := make([]pkg, 0, len(s)/2)
		for k := 0; k+1 < len(s); k += 2 {
			syms := make([]int, 0, len(s[k].syms)+len(s[k+1].syms))
			syms = append(syms, s[k].syms...)
			syms = append(syms, s[k+1].syms...)
			res = append(res, pkg{weight: s[k].weight + s[k+1].weight, syms: syms})
		}
		return res
	}

	current := append([]pkg(nil), leaves...)
	for level := 2; level <= maxLen; level++ {
		current = merge(leaves, packageUp(current))
	}

	need := 2*n - 2
	for i := 0; i < need && i < len(current); i++ {
		for _, s := range current[i].syms {
			lengths[s]++
		}
	}
	return lengths
}

// bitLength returns the position of the highest set bit + 1 (bitLength(1)=1).
func bitLength(v int) int {
	n := 0
	for v > 0 {
		n++
		v >>= 1
	}
	return n
}
