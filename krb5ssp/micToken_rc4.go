// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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
package krb5ssp

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
)

// RFC 4757 §7.2 - GSS_GetMIC with RC4-HMAC.
// Wire layout (13-byte OID header + 24-byte MIC structure = 37 bytes):
//
//	 0..12   GSS_GETMIC_HEADER
//	13..14   TOK_ID            = 0x0101 (LE)
//	15..16   SGN_ALG           = 0x0011 (HMAC-MD5)
//	17..20   Filler            = 0xFFFFFFFF
//	21..28   SND_SEQ (8)       BE32(seqnum) || 0x00000000 (init) / 0xFFFFFFFF (accept)
//	29..36   SGN_CKSUM (8)
const (
	micRC4TokenLen = 37
	micRC4HdrLen   = 13
	rc4TokIDMIC    = 0x0101
)

// GSS-API OID-wrapped header for RC4 MIC tokens. Only byte 1 differs from the
// Wrap header (length prefix reflects the shorter MIC payload).
var gssGetMICHeaderRC4 = []byte{
	0x60, 0x23, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x12, 0x01, 0x02, 0x02,
}

// getMICRC4 implements RFC 4757 GSS_GetMIC for DCE-RPC PktIntegrity.
// sessionKey is the 16-byte RC4 subkey. data is the signed payload.
// initiator=true for client-originating tokens.
func getMICRC4(sessionKey, data []byte, seqnum uint32, initiator bool) ([]byte, error) {
	if len(sessionKey) != 16 {
		return nil, fmt.Errorf("getMICRC4: session key must be 16 bytes, got %d", len(sessionKey))
	}

	// MIC uses a 4-byte pad-of-pad rather than 8-byte.
	pad := (4 - (len(data) % 4)) & 0x3
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	// Build the 8-byte token header: TOK_ID, SGN_ALG, Filler=0xFFFFFFFF.
	hdr := make([]byte, 8)
	le.PutUint16(hdr[0:2], rc4TokIDMIC)
	le.PutUint16(hdr[2:4], rc4SgnAlgHMAC)
	hdr[4] = 0xff
	hdr[5] = 0xff
	hdr[6] = 0xff
	hdr[7] = 0xff

	// SGN_CKSUM: HMAC-MD5(Ksign, MD5(LE32(15) || hdr || padded))
	sgnCksum := rc4SgnCksum(sessionKey, 15, hdr, nil, padded)

	// SND_SEQ: BE32(seqnum) || direction filler, RC4-encrypted with Kseq.
	sndSeq := make([]byte, 8)
	binary.BigEndian.PutUint32(sndSeq[0:4], seqnum)
	var filler byte = 0x00
	if !initiator {
		filler = 0xff
	}
	for i := 4; i < 8; i++ {
		sndSeq[i] = filler
	}
	encSndSeq := encryptSndSeqRC4(sessionKey, sndSeq, sgnCksum)

	out := make([]byte, 0, micRC4TokenLen)
	out = append(out, gssGetMICHeaderRC4...)
	out = append(out, hdr...)
	out = append(out, encSndSeq...)
	out = append(out, sgnCksum...)
	return out, nil
}

// verifyMICRC4 verifies a MIC token produced by getMICRC4.
// initiator indicates the direction of the sender (false when verifying a token
// received from the acceptor).
func verifyMICRC4(sessionKey, data, token []byte, seqnum uint32, initiator bool) error {
	if len(sessionKey) != 16 {
		return fmt.Errorf("verifyMICRC4: session key must be 16 bytes, got %d", len(sessionKey))
	}
	if len(token) != micRC4TokenLen {
		return fmt.Errorf("verifyMICRC4: token must be %d bytes, got %d", micRC4TokenLen, len(token))
	}
	if !bytes.Equal(token[:micRC4HdrLen], gssGetMICHeaderRC4) {
		return fmt.Errorf("verifyMICRC4: bad GSS_GETMIC_HEADER")
	}
	tok := token[micRC4HdrLen:]
	if le.Uint16(tok[0:2]) != rc4TokIDMIC {
		return fmt.Errorf("verifyMICRC4: bad TOK_ID 0x%04x", le.Uint16(tok[0:2]))
	}
	if le.Uint16(tok[2:4]) != rc4SgnAlgHMAC {
		return fmt.Errorf("verifyMICRC4: bad SGN_ALG 0x%04x", le.Uint16(tok[2:4]))
	}

	hdr := tok[0:8]
	encSndSeq := tok[8:16]
	sgnCksum := tok[16:24]

	pad := (4 - (len(data) % 4)) & 0x3
	padded := make([]byte, len(data)+pad)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	expect := rc4SgnCksum(sessionKey, 15, hdr, nil, padded)
	if !hmac.Equal(expect, sgnCksum) {
		return fmt.Errorf("verifyMICRC4: checksum mismatch")
	}

	plainSndSeq := encryptSndSeqRC4(sessionKey, encSndSeq, sgnCksum)
	gotSeq := binary.BigEndian.Uint32(plainSndSeq[0:4])
	if gotSeq != seqnum {
		return fmt.Errorf("verifyMICRC4: sequence number mismatch: got %d, want %d", gotSeq, seqnum)
	}
	var expectFiller byte
	if initiator {
		expectFiller = 0x00
	} else {
		expectFiller = 0xff
	}
	for i := 4; i < 8; i++ {
		if plainSndSeq[i] != expectFiller {
			return fmt.Errorf("verifyMICRC4: bad direction filler at %d: 0x%02x", i, plainSndSeq[i])
		}
	}
	return nil
}

// micTokenRC4Size returns the fixed MIC token size for RC4.
func micTokenRC4Size() int { return micRC4TokenLen }
