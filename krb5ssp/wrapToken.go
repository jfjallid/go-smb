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
	"fmt"

	"github.com/jfjallid/gokrb5/v9/crypto"
	"github.com/jfjallid/gokrb5/v9/types"
)

// RFC 4121 Section 4.2.6.2 Wrap Token with confidentiality, DCE-style.
//
// The Wrap Token header is 16 bytes:
//
//	Octet 0..1:  TOK_ID    (0x0504, big-endian)
//	Octet 2:     Flags     (0x02=Sealed, 0x04=AcceptorSubkey)
//	Octet 3:     Filler    (0xFF)
//	Octet 4..5:  EC        (extra count, big-endian)
//	Octet 6..7:  RRC       (right rotation count, big-endian)
//	Octet 8..15: SND_SEQ   (sequence number, big-endian)
const WrapTokenHdrLen = 16

// Wrap token flags
const (
	WrapFlagSentByAcceptor = 0x01
	WrapFlagSealed         = 0x02
	WrapFlagAcceptorSubkey = 0x04
)

// WrapToken represents an RFC 4121 Section 4.2.6.2 Wrap Token header.
type WrapToken struct {
	Flags        byte
	EC           uint16
	RRC          uint16
	SenderSeqNum uint64
}

// MarshalHeader serializes the 16-byte Wrap Token header.
func (w *WrapToken) MarshalHeader() []byte {
	buf := make([]byte, WrapTokenHdrLen)
	be.PutUint16(buf[0:2], 0x0504) // TOK_ID
	buf[2] = w.Flags
	buf[3] = 0xFF // Filler
	be.PutUint16(buf[4:6], w.EC)
	be.PutUint16(buf[6:8], w.RRC)
	be.PutUint64(buf[8:16], w.SenderSeqNum)
	return buf
}

// rotateRight performs a right rotation of data by n bytes.
// The last n bytes are moved to the front.
func rotateRight(data []byte, n int) []byte {
	l := len(data)
	if l == 0 {
		return data
	}
	n = n % l
	if n == 0 {
		return data
	}
	result := make([]byte, l)
	copy(result, data[l-n:])
	copy(result[n:], data[:l-n])
	return result
}

// rotateLeft performs a left rotation of data by n bytes (inverse of rotateRight).
// The first n bytes are moved to the end.
func rotateLeft(data []byte, n int) []byte {
	l := len(data)
	if l == 0 {
		return data
	}
	n = n % l
	if n == 0 {
		return data
	}
	result := make([]byte, l)
	copy(result, data[n:])
	copy(result[l-n:], data[:n])
	return result
}

// WrapDCE encrypts plaintext for DCE-RPC using RFC 4121 Wrap Token with
// confidentiality. Returns body (goes in PDU stub area, same length as
// plaintext) and authValue (goes in PDU auth_value field).
//
// The algorithm follows Impacket's proven implementation:
//  1. Pad plaintext to cipher block boundary with 0xFF; EC = pad count
//  2. Encrypt: padded_data + header(EC=pad, RRC=0)
//  3. Rotate ciphertext right by RRC + EC
//  4. Split rotated at WrapTokenHdrLen + RRC + EC: body = rest, tail = front
//  5. Return body, header(EC=pad, RRC=28) + tail
func WrapDCE(key types.EncryptionKey, usage uint32, plaintext []byte, seqNum uint64) (body, authValue []byte, err error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapDCE: failed to get etype: %w", err)
	}

	blockSize := etype.GetConfounderByteSize()
	hmacBytes := etype.GetHMACBitLength() / 8
	rrc := blockSize + hmacBytes // 28 for AES

	// Pad plaintext to cipher block boundary with 0xFF.
	pad := (blockSize - (len(plaintext) % blockSize)) % blockSize
	paddedData := make([]byte, len(plaintext)+pad)
	copy(paddedData, plaintext)
	for i := len(plaintext); i < len(paddedData); i++ {
		paddedData[i] = 0xFF
	}

	// Build header for encryption: EC=pad, RRC=0.
	wt := WrapToken{
		Flags:        WrapFlagSealed | WrapFlagAcceptorSubkey,
		EC:           uint16(pad),
		RRC:          0,
		SenderSeqNum: seqNum,
	}

	// Data to encrypt = padded plaintext + header(EC=pad, RRC=0)
	encInput := make([]byte, len(paddedData)+WrapTokenHdrLen)
	copy(encInput, paddedData)
	copy(encInput[len(paddedData):], wt.MarshalHeader())

	// EncryptMessage returns (iv, ciphertext+hmac, error).
	// The first return value is the AES-CTS output IV — discard it.
	_, ciphertext, err := etype.EncryptMessage(key.KeyValue, encInput, usage)
	if err != nil {
		return nil, nil, fmt.Errorf("WrapDCE: encryption failed: %w", err)
	}

	// Set RRC in transmitted header (only RRC changes after encryption).
	wt.RRC = uint16(rrc)

	// Rotate ciphertext right by RRC + EC.
	ciphertext = rotateRight(ciphertext, rrc+pad)

	// Split: first (WrapTokenHdrLen + RRC + EC) bytes go to auth tail,
	// the rest is the body. Body length equals original plaintext length.
	splitPoint := WrapTokenHdrLen + rrc + pad
	if splitPoint > len(ciphertext) {
		return nil, nil, fmt.Errorf("WrapDCE: ciphertext too short for split (len=%d, split=%d)", len(ciphertext), splitPoint)
	}
	tail := ciphertext[:splitPoint]
	body = ciphertext[splitPoint:]

	// auth_value = transmitted header(EC=pad, RRC=rrc) + tail
	authValue = make([]byte, WrapTokenHdrLen+len(tail))
	copy(authValue, wt.MarshalHeader())
	copy(authValue[WrapTokenHdrLen:], tail)

	return body, authValue, nil
}

// UnwrapDCE decrypts a DCE-RPC sealed PDU using RFC 4121 Wrap Token.
// body is the encrypted data from the PDU stub area.
// authValue is the auth_value field (wrap header + tail).
// expectedSeqNum is the expected sequence number for replay/reorder detection.
//
// The process (reverse of WrapDCE):
//  1. Parse EC and RRC from the wrap header in authValue
//  2. Reconstruct rotated ciphertext: tail + body
//  3. Unrotate (rotate left) by RRC + EC to recover original ciphertext
//  4. DecryptMessage → plaintext = padded_data + header
//  5. Verify SND_SEQ in decrypted header matches expectedSeqNum
//  6. Strip EC + WrapTokenHdrLen bytes from end (padding + header)
func UnwrapDCE(key types.EncryptionKey, usage uint32, body, authValue []byte, expectedSeqNum uint64) (plaintext []byte, err error) {
	if len(authValue) < WrapTokenHdrLen {
		return nil, fmt.Errorf("UnwrapDCE: authValue too short (%d bytes)", len(authValue))
	}

	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("UnwrapDCE: failed to get etype: %w", err)
	}
	// Parse EC and RRC from the transmitted wrap header.
	ec := int(be.Uint16(authValue[4:6]))
	rrc := int(be.Uint16(authValue[6:8]))

	// Extract tail from authValue (after the 16-byte wrap header).
	tail := authValue[WrapTokenHdrLen:]

	// Reconstruct the rotated ciphertext: tail + body
	rotated := make([]byte, len(tail)+len(body))
	copy(rotated, tail)
	copy(rotated[len(tail):], body)

	// Unrotate (rotate left) by RRC + EC to recover original ciphertext.
	ciphertext := rotateLeft(rotated, rrc+ec)

	// Decrypt and verify integrity. DecryptMessage internally strips the
	// confounder and returns: padded_data + header.
	decrypted, err := etype.DecryptMessage(key.KeyValue, ciphertext, usage)
	if err != nil {
		return nil, fmt.Errorf("UnwrapDCE: decryption failed: %w", err)
	}

	// Strip EC (padding) + WrapTokenHdrLen (header) bytes from the end.
	stripLen := ec + WrapTokenHdrLen
	if len(decrypted) < stripLen {
		return nil, fmt.Errorf("UnwrapDCE: decrypted data too short (%d bytes, need %d)", len(decrypted), stripLen)
	}

	// Verify SND_SEQ from the decrypted header for replay/reorder detection.
	// The encrypted header is at the end of the decrypted data.
	encHdr := decrypted[len(decrypted)-WrapTokenHdrLen:]
	gotSeqNum := be.Uint64(encHdr[8:16])
	if gotSeqNum != expectedSeqNum {
		return nil, fmt.Errorf("UnwrapDCE: sequence number mismatch: got %d, want %d", gotSeqNum, expectedSeqNum)
	}

	plaintext = decrypted[:len(decrypted)-stripLen]
	return plaintext, nil
}

// WrapTokenOverhead computes the signature size (auth_value length) and
// encryption overhead (extra body bytes beyond plaintext) for a given key type.
// The signature size is the worst-case (maximum padding).
func WrapTokenOverhead(keyType int32) (signatureSize, encryptionOverhead int, err error) {
	etype, err := crypto.GetEtype(keyType)
	if err != nil {
		return 0, 0, fmt.Errorf("WrapTokenOverhead: failed to get etype: %w", err)
	}

	blockSize := etype.GetConfounderByteSize()
	hmacBytes := etype.GetHMACBitLength() / 8
	rrc := blockSize + hmacBytes
	maxPad := blockSize - 1

	// auth_value = wrap header(16) + tail(16 + rrc + pad)
	// Maximum when pad = blockSize - 1
	signatureSize = WrapTokenHdrLen + WrapTokenHdrLen + rrc + maxPad

	// Body length equals plaintext length (rotation makes it exact),
	// so there is no encryption overhead in the body.
	encryptionOverhead = 0

	return signatureSize, encryptionOverhead, nil
}
