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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/crypto/cmac"
)

// kdf is NIST SP 800-108 counter-mode KDF with HMAC-SHA256 PRF, as used by
// MS-SMB2 §3.1.4.2. Output length L is in bits; only 128 (16 bytes) is needed
// for signing, but the helper accepts 256 too for completeness with future
// encryption work.
func kdfHmacSha256(ki, label, context []byte, L uint32) []byte {
	h := hmac.New(sha256.New, ki)
	// Single-iteration form (i=1) since L is at most 256 and h=256.
	h.Write([]byte{0, 0, 0, 1})
	h.Write(label)
	h.Write([]byte{0})
	h.Write(context)
	h.Write(binary.BigEndian.AppendUint32(nil, L))
	return h.Sum(nil)[:L/8]
}

// updatePreauthChainConn folds the given PDU bytes into the connection-level
// preauth chain. Callers should only invoke this for SMB 3.1.1 Negotiate
// messages — for SessionSetup the chain lives on the Session.
func (c *Conn) updatePreauthChainConn(pkt []byte) {
	if c.Dialect != smb.DialectSmb_3_1_1 || c.PreauthHashID != smb.SHA512 {
		return
	}
	updatePreauthChain(&c.preauthChain, pkt)
}

// updatePreauthChainSession folds the given PDU bytes into the session-level
// preauth chain. The session must already have been seeded from the
// connection chain (see seedPreauthChain).
func (c *Conn) updatePreauthChainSession(s *Session, pkt []byte) {
	if c.Dialect != smb.DialectSmb_3_1_1 || c.PreauthHashID != smb.SHA512 {
		return
	}
	updatePreauthChain(&s.preauthChain, pkt)
}

// seedPreauthChain copies the connection-level chain into the session at the
// start of the SessionSetup exchange. Idempotent across legs as long as
// callers only call it once per session.
func (c *Conn) seedPreauthChain(s *Session) {
	if c.Dialect != smb.DialectSmb_3_1_1 || c.PreauthHashID != smb.SHA512 {
		return
	}
	s.preauthChain = c.preauthChain
}

func updatePreauthChain(chain *[64]byte, pkt []byte) {
	h := sha512.New()
	h.Write(chain[:])
	h.Write(pkt)
	h.Sum(chain[:0])
}

// deriveKeys initializes the signer/verifier on the session from the
// authenticated session key. For SMB 2.x the key is used directly with
// HMAC-SHA256; for SMB 3.x the SP 800-108 KDF derives a per-session signing
// key. After this call SigningActive is true and signOutbound/verifyInbound
// are wired up.
func (c *Conn) deriveKeys(s *Session) error {
	if len(s.SessionKey) < 16 {
		return fmt.Errorf("deriveKeys: session key too short (%d bytes)", len(s.SessionKey))
	}
	sessionKey := s.SessionKey[:16]

	switch c.Dialect {
	case smb.DialectSmb_2_0_2, smb.DialectSmb_2_1:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)

	case smb.DialectSmb_3_0, smb.DialectSmb_3_0_2:
		// MS-SMB2 §3.1.4.5: SigningKey = KDF(SessionKey, "SMB2AESCMAC", "SmbSign")
		signingKey := kdfHmacSha256(sessionKey,
			[]byte("SMB2AESCMAC\x00"),
			[]byte("SmbSign\x00"),
			128)
		signer, err := cmac.New(signingKey)
		if err != nil {
			return formatErr("deriveKeys: cmac signer", err)
		}
		verifier, err := cmac.New(signingKey)
		if err != nil {
			return formatErr("deriveKeys: cmac verifier", err)
		}
		s.signer, s.verifier = signer, verifier

	case smb.DialectSmb_3_1_1:
		// MS-SMB2 §3.1.4.2: SigningKey = KDF(SessionKey, "SMBSigningKey",
		// PreauthIntegrityHashValue) — derived per-session.
		signingKey := kdfHmacSha256(sessionKey,
			[]byte("SMBSigningKey\x00"),
			s.preauthChain[:],
			128)
		s.signingAlg = c.SigningID
		s.signingKey = signingKey
		// HMAC_SHA256 (0x0000) is the constant used during 2.x; SMB 3.1.1
		// uses AES_CMAC (0x0001) by default; AES_GMAC (0x0002) added in
		// later Windows builds. negotiate.go picks the highest the client
		// offered.
		switch c.SigningID {
		case smb.HMAC_SHA256:
			s.signer = hmac.New(sha256.New, signingKey)
			s.verifier = hmac.New(sha256.New, signingKey)
		case smb.AES_GMAC:
			// AES-GMAC requires a fresh nonce per message, so we don't
			// preallocate a hash.Hash. signPDU / verifyPDU build the AEAD
			// on demand using the cached signingKey and derive the nonce
			// from the MessageID. We do, however, verify the key is a
			// valid AES key here so a misconfiguration surfaces during
			// SessionSetup rather than on the first signed PDU.
			if _, err := aes.NewCipher(signingKey); err != nil {
				return formatErr("deriveKeys: gmac key check", err)
			}
		default: // smb.AES_CMAC and unknown algs fall back to CMAC.
			signer, err := cmac.New(signingKey)
			if err != nil {
				return formatErr("deriveKeys: cmac signer", err)
			}
			verifier, err := cmac.New(signingKey)
			if err != nil {
				return formatErr("deriveKeys: cmac verifier", err)
			}
			s.signer, s.verifier = signer, verifier
		}

	default:
		return fmt.Errorf("deriveKeys: unsupported dialect 0x%04x", c.Dialect)
	}

	s.SigningActive = true
	return nil
}

// gmacNonce computes the 12-byte AES-GMAC nonce for the given PDU per
// MS-SMB2 §3.1.4.1 / §3.1.5.1:
//
//	bytes 0..7  : MessageId (LE, from the SMB2 header @ offset 24)
//	byte  8     : flag byte
//	             bit 0 = direction (0 = client→server, 1 = server→client)
//	             bit 1 = SMB2 CANCEL (1 if request is a CANCEL, else 0)
//	             bits 2..7 = 0
//	bytes 9..11 : 0
//
// Direction is taken from SMB2_FLAGS_SERVER_TO_REDIR (bit 0 of pkt[16]).
// Sender side calls this on a packet whose Flags already has SERVER_TO_REDIR
// set (responses); verifier side calls it on a packet without that flag
// (incoming requests).
func gmacNonce(pkt []byte) [12]byte {
	var n [12]byte
	if len(pkt) < 32 {
		return n
	}
	copy(n[:8], pkt[24:32])
	var flag byte
	if pkt[16]&byte(smb.SMB2_FLAGS_SERVER_TO_REDIR) != 0 {
		flag |= 0x01
	}
	if binary.LittleEndian.Uint16(pkt[12:14]) == smb.CommandCancel {
		flag |= 0x02
	}
	n[8] = flag
	return n
}

// signPDU stamps pkt with FLAGS_SIGNED + 16-byte signature, dispatching to
// the algorithm selected at SessionSetup (HMAC-SHA256 / AES-CMAC / AES-GMAC).
// Used by both the per-PDU sign path in conn.go and by writeSignedReply.
func (s *Session) signPDU(pkt []byte) {
	if len(pkt) < 64 || string(pkt[0:4]) != smb.ProtocolSmb2 {
		log.Errorf("signPDU: refusing to sign non-SMB2 or short PDU (len=%d)\n", len(pkt))
		return
	}
	flags := binary.LittleEndian.Uint32(pkt[16:20])
	flags |= smb.SMB2_FLAGS_SIGNED
	binary.LittleEndian.PutUint32(pkt[16:20], flags)
	for i := 48; i < 64; i++ {
		pkt[i] = 0
	}
	if s.signingAlg == smb.AES_GMAC {
		nonce := gmacNonce(pkt)
		block, err := aes.NewCipher(s.signingKey)
		if err != nil {
			log.Errorf("signPDU: aes.NewCipher failed: %s\n", err)
			return
		}
		aead, err := cipher.NewGCMWithNonceSize(block, 12)
		if err != nil {
			log.Errorf("signPDU: NewGCMWithNonceSize failed: %s\n", err)
			return
		}
		// GMAC = GCM with empty plaintext, message as AAD. Seal returns
		// just the 16-byte authentication tag.
		tag := aead.Seal(nil, nonce[:], nil, pkt)
		if len(tag) >= 16 {
			copy(pkt[48:64], tag[:16])
		} else {
			log.Errorf("signPDU: GMAC tag short (%d bytes)\n", len(tag))
		}
		return
	}
	if s.signer == nil {
		log.Errorln("signPDU: no signer configured")
		return
	}
	s.signer.Reset()
	s.signer.Write(pkt)
	sig := s.signer.Sum(nil)
	if len(sig) >= 16 {
		copy(pkt[48:64], sig[:16])
	} else {
		copy(pkt[48:64], sig)
	}
}

// verifyPDU checks the signature on an inbound pkt. Returns true if it
// verifies. Mutates pkt transiently (zeroes the Signature for computation
// then restores it) but leaves it byte-identical on return.
func (s *Session) verifyPDU(pkt []byte) bool {
	if len(pkt) < 64 || string(pkt[0:4]) != smb.ProtocolSmb2 {
		log.Errorf("verifyPDU: refusing to verify non-SMB2 or short PDU (len=%d)\n", len(pkt))
		return false
	}
	var saved [16]byte
	copy(saved[:], pkt[48:64])
	for i := 48; i < 64; i++ {
		pkt[i] = 0
	}
	defer copy(pkt[48:64], saved[:])
	if s.signingAlg == smb.AES_GMAC {
		nonce := gmacNonce(pkt)
		block, err := aes.NewCipher(s.signingKey)
		if err != nil {
			log.Errorf("verifyPDU: aes.NewCipher failed: %s\n", err)
			return false
		}
		aead, err := cipher.NewGCMWithNonceSize(block, 12)
		if err != nil {
			log.Errorf("verifyPDU: NewGCMWithNonceSize failed: %s\n", err)
			return false
		}
		if _, err := aead.Open(nil, nonce[:], saved[:16], pkt); err != nil {
			log.Debugf("verifyPDU: GMAC tag mismatch: %s\n", err)
			return false
		}
		return true
	}
	if s.verifier == nil {
		log.Errorln("verifyPDU: no verifier configured")
		return false
	}
	s.verifier.Reset()
	s.verifier.Write(pkt)
	sig := s.verifier.Sum(nil)
	if len(sig) >= 16 {
		sig = sig[:16]
	}
	return bytes.Equal(saved[:len(sig)], sig)
}

// shouldSign reports whether the response to the currently-dispatching PDU
// must carry a signature. MS-SMB2 §3.3.4.1.1 makes the signing decision
// per-request: signed inbound → signed outbound (with the interim-async
// exception). If the inbound was not signed the server zeros the Signature
// field and skips signing, regardless of Session.SigningRequired.
//
// Returns false for guest / null sessions, sessions without derived keys,
// and any path where ctx.signed is not set (i.e. the inbound was
// plaintext-unsigned, encrypted, or there is no inbound being serviced).
func (s *Session) shouldSign(ctx pduCtx) bool {
	if !s.canSign() {
		return false
	}
	return ctx.signed
}

// canSign reports whether the session has the keys ready to sign. Used by
// the SessionSetup2 final-reply path which signs whenever it can — even
// when the inbound SessionSetup2 was not signed (the client doesn't yet
// have signing keys at send time, but expects the final reply to be
// signed per MS-SMB2 §3.3.5.5).
func (s *Session) canSign() bool {
	if s == nil || !s.SigningActive {
		return false
	}
	// AES-GMAC builds the AEAD on-demand inside signPDU using s.signingKey,
	// so s.signer is intentionally nil for that algorithm.
	if s.signer == nil && s.signingAlg != smb.AES_GMAC {
		return false
	}
	if s.Flags&(smb.SessionFlagIsGuest|smb.SessionFlagIsNull) != 0 {
		return false
	}
	return true
}

// shouldVerify reports whether the verifier is wired up and usable; the
// inbound dispatcher decides separately whether to *require* a signature
// (s.SigningRequired) versus merely verify one if present.
func (s *Session) shouldVerify() bool {
	if s == nil || !s.SigningActive {
		return false
	}
	// AES-GMAC builds the AEAD on-demand inside verifyPDU using s.signingKey,
	// so s.verifier is intentionally nil for that algorithm.
	if s.verifier == nil && s.signingAlg != smb.AES_GMAC {
		return false
	}
	if s.Flags&(smb.SessionFlagIsGuest|smb.SessionFlagIsNull) != 0 {
		return false
	}
	return true
}
