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
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
)

// RFC 4757 §7.3 - GSS_Wrap with RC4-HMAC.
// Wire layout (13-byte OID header + 32-byte WRAP structure = 45 bytes auth_value):
//
//	 0..12   GSS_WRAP_HEADER
//	13..14   TOK_ID            = 0x0102 (LE)
//	15..16   SGN_ALG           = 0x0011 (HMAC-MD5)
//	17..18   SEAL_ALG          = 0x0010 (RC4)
//	19..20   Filler            = 0xFFFF
//	21..28   SND_SEQ (8)       BE32(seqnum) || 0x00000000 (init) / 0xFFFFFFFF (accept)
//	29..36   SGN_CKSUM (8)
//	37..44   Confounder (8)    (ARC4-encrypted with Kcrypt)
const (
	wrapRC4AuthValueLen = 45
	wrapRC4HdrLen       = 13
	wrapRC4MaxPad       = 7 // worst-case pad (blockSize - 1)

	rc4SgnAlgHMAC = 0x0011
	rc4SealAlgRC4 = 0x0010
	rc4TokIDWrap  = 0x0102
)

// GSS-API OID-wrapped header for RC4 Wrap tokens (ASN.1 prefix for Kerberos mech OID).
var gssWrapHeaderRC4 = []byte{
	0x60, 0x2b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x12, 0x01, 0x02, 0x02,
}

// wrapDCERC4 implements RFC 4757 GSS_Wrap for DCE-RPC with RC4-HMAC.
// sessionKey is the 16-byte RC4 subkey.
// plaintext is the data to seal.
// seqnum is the 32-bit per-message sequence number.
// initiator=true for client-originating tokens, false for acceptor-originating tokens.
// Returns the encrypted body (goes in PDU stub; len = len(plaintext)+pad) and the
// 45-byte auth_value.
func wrapDCERC4(sessionKey, plaintext []byte, seqnum uint32, initiator bool) (body, authValue []byte, err error) {
	if len(sessionKey) != 16 {
		return nil, nil, fmt.Errorf("wrapDCERC4: session key must be 16 bytes, got %d", len(sessionKey))
	}

	// PKCS-style pad to 8-byte boundary (pad = 0..7 bytes of value = pad count).
	pad := (8 - (len(plaintext) % 8)) & 0x7
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}

	// Random 8-byte confounder.
	confounder := make([]byte, 8)
	if _, err = rand.Read(confounder); err != nil {
		return nil, nil, fmt.Errorf("wrapDCERC4: confounder rand: %w", err)
	}

	tok := marshalRC4WrapTokenHeader(rc4TokIDWrap, rc4SgnAlgHMAC, rc4SealAlgRC4, seqnum, initiator)

	// SGN_CKSUM: HMAC-MD5(Ksign, MD5(LE32(13) || token[0:8] || confounder_plain || padded))
	// The "LE32(13)" is the MS-specific usage constant for Wrap per Impacket.
	sgnCksum := rc4SgnCksum(sessionKey, 13, tok[0:8], confounder, padded)

	// Place SGN_CKSUM and encrypted SND_SEQ.
	copy(tok[8:16], encryptSndSeqRC4(sessionKey, tok[8:16], sgnCksum))
	copy(tok[16:24], sgnCksum)

	// Encrypt confounder + padded data with a single RC4(Kcrypt) stream.
	kcrypt := deriveKcryptRC4(sessionKey, seqnum)
	stream, err := rc4.NewCipher(kcrypt)
	if err != nil {
		return nil, nil, fmt.Errorf("wrapDCERC4: rc4: %w", err)
	}
	encConfounder := make([]byte, 8)
	stream.XORKeyStream(encConfounder, confounder)
	body = make([]byte, len(padded))
	stream.XORKeyStream(body, padded)

	// auth_value = GSS_WRAP_HEADER || token_header(8) || enc_sndseq(8) || sgnCksum(8) || enc_confounder(8)
	authValue = make([]byte, 0, wrapRC4AuthValueLen)
	authValue = append(authValue, gssWrapHeaderRC4...)
	authValue = append(authValue, tok[:24]...)
	authValue = append(authValue, encConfounder...)
	return body, authValue, nil
}

// unwrapDCERC4 reverses wrapDCERC4. seqnum is the expected sequence number.
// initiator must match the sender (false when decrypting a token produced by the
// acceptor, i.e. on the client receive path).
func unwrapDCERC4(sessionKey, body, authValue []byte, seqnum uint32, initiator bool) (plaintext []byte, err error) {
	if len(sessionKey) != 16 {
		return nil, fmt.Errorf("unwrapDCERC4: session key must be 16 bytes, got %d", len(sessionKey))
	}
	if len(authValue) != wrapRC4AuthValueLen {
		return nil, fmt.Errorf("unwrapDCERC4: auth_value must be %d bytes, got %d", wrapRC4AuthValueLen, len(authValue))
	}
	if !bytes.Equal(authValue[:wrapRC4HdrLen], gssWrapHeaderRC4) {
		return nil, fmt.Errorf("unwrapDCERC4: missing or bad GSS_WRAP_HEADER")
	}
	if len(body)%8 != 0 {
		return nil, fmt.Errorf("unwrapDCERC4: body length %d not 8-aligned", len(body))
	}

	tok := authValue[wrapRC4HdrLen:]

	if le.Uint16(tok[0:2]) != rc4TokIDWrap {
		return nil, fmt.Errorf("unwrapDCERC4: bad TOK_ID 0x%04x", le.Uint16(tok[0:2]))
	}
	if le.Uint16(tok[2:4]) != rc4SgnAlgHMAC {
		return nil, fmt.Errorf("unwrapDCERC4: bad SGN_ALG 0x%04x", le.Uint16(tok[2:4]))
	}
	if le.Uint16(tok[4:6]) != rc4SealAlgRC4 {
		return nil, fmt.Errorf("unwrapDCERC4: bad SEAL_ALG 0x%04x", le.Uint16(tok[4:6]))
	}

	encSndSeq := tok[8:16]
	sgnCksum := tok[16:24]
	encConfounder := tok[24:32]

	// Decrypt SND_SEQ using Kseq derived from the (trusted-after-verify) SGN_CKSUM.
	plainSndSeq := encryptSndSeqRC4(sessionKey, encSndSeq, sgnCksum)
	gotSeq := binary.BigEndian.Uint32(plainSndSeq[0:4])
	if gotSeq != seqnum {
		return nil, fmt.Errorf("unwrapDCERC4: sequence number mismatch: got %d, want %d", gotSeq, seqnum)
	}
	var expectFiller byte
	if initiator {
		expectFiller = 0x00
	} else {
		expectFiller = 0xff
	}
	for i := 4; i < 8; i++ {
		if plainSndSeq[i] != expectFiller {
			return nil, fmt.Errorf("unwrapDCERC4: bad direction filler at %d: 0x%02x", i, plainSndSeq[i])
		}
	}

	// Decrypt confounder + body using a fresh RC4(Kcrypt) stream.
	kcrypt := deriveKcryptRC4(sessionKey, gotSeq)
	stream, err := rc4.NewCipher(kcrypt)
	if err != nil {
		return nil, fmt.Errorf("unwrapDCERC4: rc4: %w", err)
	}
	confounder := make([]byte, 8)
	stream.XORKeyStream(confounder, encConfounder)
	decoded := make([]byte, len(body))
	stream.XORKeyStream(decoded, body)

	// Verify SGN_CKSUM over the plaintext confounder + padded data.
	hdrCopy := make([]byte, 8)
	copy(hdrCopy, tok[0:8])
	expect := rc4SgnCksum(sessionKey, 13, hdrCopy, confounder, decoded)
	if !hmac.Equal(expect, sgnCksum) {
		return nil, fmt.Errorf("unwrapDCERC4: checksum mismatch")
	}

	// Return padded plaintext. The RC4 pad (0..7 bytes) is not stripped here;
	// NDR parsing at the DCE-RPC layer uses length-prefixed structures and
	// ignores trailing pad bytes, matching Impacket's GSS_Unwrap semantics.
	return decoded, nil
}

// wrapTokenRC4Overhead returns the fixed sizes for RC4 wrap tokens.
func wrapTokenRC4Overhead() (signatureSize, encryptionOverhead int) {
	return wrapRC4AuthValueLen, wrapRC4MaxPad
}

// marshalRC4WrapTokenHeader builds a 24-byte scratch buffer holding:
//
//	[0:8]   token header (TOK_ID, SGN_ALG, SEAL_ALG, Filler) - each LE uint16
//	[8:16]  SND_SEQ plaintext
//	[16:24] zeroed (caller fills SGN_CKSUM)
//
// SEAL_ALG of 0xFFFF means "no sealing" (used by the MIC helpers).
func marshalRC4WrapTokenHeader(tokID, sgnAlg, sealAlg uint16, seqnum uint32, initiator bool) []byte {
	buf := make([]byte, 24)
	le.PutUint16(buf[0:2], tokID)
	le.PutUint16(buf[2:4], sgnAlg)
	le.PutUint16(buf[4:6], sealAlg)
	buf[6] = 0xff
	buf[7] = 0xff
	binary.BigEndian.PutUint32(buf[8:12], seqnum)
	var filler byte = 0x00
	if !initiator {
		filler = 0xff
	}
	for i := 12; i < 16; i++ {
		buf[i] = filler
	}
	return buf
}

// rc4SgnCksum computes SGN_CKSUM per RFC 4757 §7.3 (Wrap) / §7.2 (MIC).
// `msgType` is the MS-specific usage constant (13 for Wrap, 15 for MIC).
// `hdr` is the 8-byte token header (TOK_ID..Filler).
// `confounder` is 8 bytes for Wrap, empty (nil) for MIC.
// `data` is the padded data (already pad-extended for Wrap, 4-byte-pad-extended for MIC).
func rc4SgnCksum(sessionKey []byte, msgType uint32, hdr, confounder, data []byte) []byte {
	ksign := hmacMD5(sessionKey, []byte("signaturekey\x00"))

	inner := md5.New()
	var mt [4]byte
	binary.LittleEndian.PutUint32(mt[:], msgType)
	inner.Write(mt[:])
	inner.Write(hdr)
	if confounder != nil {
		inner.Write(confounder)
	}
	inner.Write(data)
	digest := inner.Sum(nil)

	full := hmacMD5(ksign, digest)
	return full[:8]
}

// encryptSndSeqRC4 applies RC4(Kseq) to 8 bytes of SND_SEQ (encrypt and decrypt
// are identical since RC4 is a stream cipher).
func encryptSndSeqRC4(sessionKey, sndSeq, sgnCksum []byte) []byte {
	kseqInner := hmacMD5(sessionKey, []byte{0, 0, 0, 0})
	kseq := hmacMD5(kseqInner, sgnCksum)
	out := make([]byte, len(sndSeq))
	stream, _ := rc4.NewCipher(kseq)
	stream.XORKeyStream(out, sndSeq)
	return out
}

// deriveKcryptRC4 returns the per-message encryption key for RC4 Wrap.
// Klocal = sessionKey XOR 0xF0; Kcrypt = HMAC_MD5(HMAC_MD5(Klocal, LE32(0)), BE32(seqnum))
func deriveKcryptRC4(sessionKey []byte, seqnum uint32) []byte {
	klocal := make([]byte, len(sessionKey))
	for i, b := range sessionKey {
		klocal[i] = b ^ 0xf0
	}
	inner := hmacMD5(klocal, []byte{0, 0, 0, 0})
	var seq [4]byte
	binary.BigEndian.PutUint32(seq[:], seqnum)
	return hmacMD5(inner, seq[:])
}

// hmacMD5 is a small convenience wrapper.
func hmacMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}
