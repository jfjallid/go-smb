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

package server

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/crypto/ccm"
)

// deriveEncryptionKeys initializes session.encrypter / decrypter when the
// negotiated dialect is SMB 3.x, the negotiated CipherID is non-zero, and
// the server config either supports or requires encryption. The keys are
// always derived (so a tree with EncryptData=TRUE can be served), but
// SessionFlagEncryptData is only set when the server config requires
// session-level encryption AND the client offered GlobalCapEncryption. For
// SMB 2.x or when no cipher was negotiated this is a no-op.
//
// Must be called after deriveKeys (which fills SessionKey-derived signing
// state) and before the SessionSetup2Res reply is queued.
func (c *Conn) deriveEncryptionKeys(s *Session) error {
	cfg := c.Server.Config
	if !cfg.encryptionSupported() {
		return nil
	}
	if c.CipherID == 0 || c.Dialect < smb.DialectSmb_3_0 {
		// RequireEncryption with a 2.x dialect or no cipher selected is
		// a misconfiguration that surfaces as: client gets an unsigned
		// post-auth reply. Caller's SessionSetup path rejects later.
		return nil
	}
	if !c.ClientWantsEncrypt {
		// Client did not advertise GlobalCapEncryption. We won't be able
		// to engage encryption with this client. If the server requires
		// it, fail the session.
		if cfg.RequireEncryption {
			return fmt.Errorf("client did not offer GlobalCapEncryption but server requires encryption")
		}
		return nil
	}
	if len(s.SessionKey) < 16 {
		return fmt.Errorf("deriveEncryptionKeys: session key too short (%d bytes)", len(s.SessionKey))
	}
	sessionKey := s.SessionKey[:16]

	var keyLenBits uint32
	switch c.CipherID {
	case smb.AES128CCM, smb.AES128GCM:
		keyLenBits = 128
	case smb.AES256CCM, smb.AES256GCM:
		keyLenBits = 256
	default:
		return fmt.Errorf("deriveEncryptionKeys: unsupported cipher 0x%04x", c.CipherID)
	}

	// MS-SMB2 §3.1.4.2: server's encryption key encrypts S2C traffic;
	// server's decryption key decrypts inbound C2S traffic.
	var encKey, decKey []byte
	switch c.Dialect {
	case smb.DialectSmb_3_0, smb.DialectSmb_3_0_2:
		// 3.0/3.0.2 encryption label is constant "SMB2AESCCM\0"
		// regardless of cipher (CCM is the only allowed cipher;
		// see MS-SMB2 §3.3.5.4 and §3.1.4.2). Context strings are
		// "ServerOut\0" (S2C) and "ServerIn \0" (C2S, note space).
		encKey = kdfHmacSha256(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"), keyLenBits)
		decKey = kdfHmacSha256(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"), keyLenBits)
	case smb.DialectSmb_3_1_1:
		encKey = kdfHmacSha256(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthChain[:], keyLenBits)
		decKey = kdfHmacSha256(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthChain[:], keyLenBits)
	default:
		return fmt.Errorf("deriveEncryptionKeys: unsupported dialect 0x%04x", c.Dialect)
	}

	enc, err := buildAEAD(c.CipherID, encKey)
	if err != nil {
		return formatErr("deriveEncryptionKeys: encrypter", err)
	}
	dec, err := buildAEAD(c.CipherID, decKey)
	if err != nil {
		return formatErr("deriveEncryptionKeys: decrypter", err)
	}
	s.encrypter = enc
	s.decrypter = dec
	// MS-SMB2 §3.3.5.5.3: enable session-level encryption only when the
	// server actually requires it. Even with keys derived, sessions whose
	// config is "encryption supported" stay in plaintext+sign mode at the
	// session level; per-tree enforcement (Share.EncryptData) is applied
	// per-PDU in dispatchSMB2Inner.
	if cfg.RequireEncryption {
		s.Flags |= smb.SessionFlagEncryptData
	}
	return nil
}

// buildAEAD wraps an AES key in the AEAD chosen by cipherID, mirroring the
// nonce/tag conventions used by smb.Session.encrypt/decrypt.
func buildAEAD(cipherID uint16, key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch cipherID {
	case smb.AES128GCM, smb.AES256GCM:
		// GCM uses a 12-byte nonce (MS-SMB2 §3.1.4.3).
		return cipher.NewGCMWithNonceSize(block, 12)
	case smb.AES128CCM, smb.AES256CCM:
		// CCM uses an 11-byte nonce, 16-byte tag.
		return ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	default:
		return nil, fmt.Errorf("unsupported cipher 0x%04x", cipherID)
	}
}

// encryptOutbound wraps an SMB2 PDU in a TransformHeader and AEAD-encrypts
// the payload using the session's S2C encrypter. Returns the framed bytes
// ready for NetBIOS transmission. AssociatedData is the 32-byte slice from
// offset 20..52 of the TransformHeader (MS-SMB2 §3.1.4.3).
func encryptOutbound(s *Session, plaintext []byte) ([]byte, error) {
	if s == nil || s.encrypter == nil {
		return nil, fmt.Errorf("encryptOutbound: session has no encrypter")
	}
	nonce := make([]byte, s.encrypter.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	tHdr := smb.NewTransformHeader()
	copy(tHdr.Nonce, nonce)
	tHdr.OriginalMessageSize = uint32(len(plaintext))
	tHdr.SessionId = s.ID
	tHdrBytes, err := tHdr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(tHdrBytes) != 52 {
		return nil, fmt.Errorf("encryptOutbound: TransformHeader marshal produced %d bytes (want 52)", len(tHdrBytes))
	}
	// AAD is bytes 20..52 of the header (Nonce..SessionId, all post-Signature
	// fixed fields). Seal returns ciphertext+tag; copy the trailing 16-byte
	// tag back into the header's Signature field.
	sealed := s.encrypter.Seal(nil, nonce, plaintext, tHdrBytes[20:52])
	if len(sealed) < 16 {
		return nil, fmt.Errorf("encryptOutbound: AEAD output too short (%d)", len(sealed))
	}
	copy(tHdrBytes[4:20], sealed[len(sealed)-16:])
	out := make([]byte, 0, 52+len(sealed)-16)
	out = append(out, tHdrBytes...)
	out = append(out, sealed[:len(sealed)-16]...)
	return out, nil
}

// decryptInbound peels a TransformHeader off raw and AEAD-decrypts the
// payload with the session's C2S decrypter. Returns the decrypted SMB2 PDU.
// The transform header's SessionId is checked against an explicit set of
// known sessions on the connection.
func (c *Conn) decryptInbound(raw []byte) ([]byte, *Session, error) {
	if len(raw) < 52 {
		return nil, nil, fmt.Errorf("decryptInbound: packet too short (%d)", len(raw))
	}
	if string(raw[0:4]) != smb.ProtocolTransformHdr {
		return nil, nil, fmt.Errorf("decryptInbound: not a TransformHeader (% x)", raw[0:4])
	}
	tHdr := smb.NewTransformHeader()
	if err := tHdr.UnmarshalBinary(raw[:52]); err != nil {
		return nil, nil, formatErr("decode TransformHeader", err)
	}
	// SMB 3.x mandates the Encrypted flag (=1) on inbound transforms.
	if tHdr.Flags != 0x0001 {
		return nil, nil, fmt.Errorf("decryptInbound: unexpected Flags 0x%04x", tHdr.Flags)
	}
	sess := c.session(tHdr.SessionId)
	if sess == nil {
		return nil, nil, fmt.Errorf("decryptInbound: unknown SessionID %d", tHdr.SessionId)
	}
	if sess.decrypter == nil {
		return nil, nil, fmt.Errorf("decryptInbound: session %d has no decrypter", tHdr.SessionId)
	}
	// Reassemble ciphertext+tag for AEAD.Open: ciphertext follows the 52-byte
	// header; tag is in the Signature field of the header (bytes 4..20).
	ciphertext := make([]byte, 0, len(raw)-52+16)
	ciphertext = append(ciphertext, raw[52:]...)
	ciphertext = append(ciphertext, raw[4:20]...)
	plaintext, err := sess.decrypter.Open(ciphertext[:0], tHdr.Nonce[:sess.decrypter.NonceSize()], ciphertext, raw[20:52])
	if err != nil {
		return nil, sess, formatErr("AEAD open", err)
	}
	if uint32(len(plaintext)) != tHdr.OriginalMessageSize {
		return nil, sess, fmt.Errorf("decryptInbound: OriginalMessageSize=%d but decrypted=%d",
			tHdr.OriginalMessageSize, len(plaintext))
	}
	return plaintext, sess, nil
}
