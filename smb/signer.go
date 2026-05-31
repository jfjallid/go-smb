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
package smb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"hash"
)

// smbSigner produces the 16-byte SMB2 signature for an outgoing packet. The
// caller MUST have zeroed bytes [48:64] (the Signature field of the SMB2
// header) before calling Sign.
type smbSigner interface {
	Sign(pkt []byte) []byte
}

// smbVerifier verifies a 16-byte SMB2 signature on an incoming packet. The
// caller MUST have zeroed bytes [48:64] before calling Verify.
type smbVerifier interface {
	Verify(pkt []byte, sig []byte) bool
}

// hashSigner adapts a keyed hash (HMAC-SHA256 or AES-CMAC) to smbSigner.
// SMB2 signatures are the leftmost 16 bytes of the MAC; AES-CMAC already
// produces 16 bytes (no-op truncation), HMAC-SHA256 produces 32.
type hashSigner struct{ h hash.Hash }

func (s *hashSigner) Sign(pkt []byte) []byte {
	s.h.Reset()
	s.h.Write(pkt)
	return s.h.Sum(nil)[:16]
}

type hashVerifier struct{ h hash.Hash }

func (v *hashVerifier) Verify(pkt, sig []byte) bool {
	v.h.Reset()
	v.h.Write(pkt)
	return bytes.Equal(v.h.Sum(nil)[:16], sig)
}

// gmacSigner / gmacVerifier implement AES-GMAC signing (MS-SMB2 §3.1.4.1 /
// §3.1.5.1). The 12-byte nonce is constructed as:
//
//	bytes 0..7  : MessageId (little-endian, from the SMB2 header @ offset 24)
//	byte  8     : flag byte
//	             bit 0 = direction (0 = client, 1 = server)
//	             bit 1 = SMB2 CANCEL (1 if request is a CANCEL, else 0)
//	             bits 2..7 = 0
//	bytes 9..11 : 0
type gmacSigner struct{ gcm cipher.AEAD }

func (s *gmacSigner) Sign(pkt []byte) []byte {
	nonce := gmacNonce(pkt, false /* client */)
	// gcm.Seal with nil plaintext returns just the 16-byte auth tag.
	return s.gcm.Seal(nil, nonce, nil, pkt)
}

type gmacVerifier struct{ gcm cipher.AEAD }

func (v *gmacVerifier) Verify(pkt, sig []byte) bool {
	if len(sig) != 16 {
		return false
	}
	nonce := gmacNonce(pkt, true /* server */)
	// gcm.Open over an empty ciphertext (just the tag) verifies the
	// additional data (the packet) under the given nonce.
	_, err := v.gcm.Open(nil, nonce, sig, pkt)
	return err == nil
}

func gmacNonce(pkt []byte, isServer bool) []byte {
	nonce := make([]byte, 12)
	if len(pkt) < 32 {
		return nonce
	}
	// MessageId lives at offset 24..32 of the SMB2 header, little-endian.
	copy(nonce[:8], pkt[24:32])
	var flag byte
	if isServer {
		flag |= 0x01
	}
	// Command field is at offset 12..14 of the SMB2 header, little-endian.
	if binary.LittleEndian.Uint16(pkt[12:14]) == CommandCancel {
		flag |= 0x02
	}
	nonce[8] = flag
	return nonce
}

func newHashSigner(h hash.Hash) smbSigner       { return &hashSigner{h: h} }
func newHashVerifier(h hash.Hash) smbVerifier   { return &hashVerifier{h: h} }
func newGmacSigner(g cipher.AEAD) smbSigner     { return &gmacSigner{gcm: g} }
func newGmacVerifier(g cipher.AEAD) smbVerifier { return &gmacVerifier{gcm: g} }

// newAESGMAC constructs a cipher.AEAD configured for AES-GMAC with a 12-byte
// nonce. signingKey must be 16 bytes (AES-128).
func newAESGMAC(signingKey []byte) (cipher.AEAD, error) {
	ciph, err := aes.NewCipher(signingKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(ciph)
}

// GMACSignForTest exercises the client's gmacSigner.Sign path with the given
// key (AES-128, 16 bytes) over the supplied PDU. The caller must have zeroed
// pkt[48:64] and set the desired FLAGS_SIGNED / SERVER_TO_REDIR bits.
// Test-only — exported so cross-package tests in smb/server can confirm the
// client and server produce identical signatures.
func GMACSignForTest(key, pkt []byte) ([]byte, error) {
	gcm, err := newAESGMAC(key)
	if err != nil {
		return nil, err
	}
	return (&gmacSigner{gcm: gcm}).Sign(pkt), nil
}

// GMACVerifyForTest exercises the client's gmacVerifier.Verify path. Caller
// must have zeroed pkt[48:64]. Returns the same boolean the client receiver
// uses to accept or drop the PDU. Test-only.
func GMACVerifyForTest(key, pkt, sig []byte) (bool, error) {
	gcm, err := newAESGMAC(key)
	if err != nil {
		return false, err
	}
	return (&gmacVerifier{gcm: gcm}).Verify(pkt, sig), nil
}
