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

package msdrsr

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"unicode/utf16"
)

// DecryptSecret decrypts an ENCRYPTED_PAYLOAD blob (MS-DRSR 4.1.10.6.12)
// using the session key from the RPC bind.
func DecryptSecret(sessionKey, encryptedPayload []byte) ([]byte, error) {
	if len(encryptedPayload) < 20 {
		return nil, fmt.Errorf("encrypted payload too short: %d bytes", len(encryptedPayload))
	}

	// Check if this is an AES-encrypted payload (Windows 2012+)
	// AES payloads start with a 4-byte version field == 1
	if len(encryptedPayload) > 24 {
		version := le.Uint32(encryptedPayload[:4])
		if version == 1 {
			return decryptSecretAES(sessionKey, encryptedPayload)
		}
	}

	return decryptSecretRC4(sessionKey, encryptedPayload)
}

// decryptSecretRC4 implements the RC4 ENCRYPTED_PAYLOAD decryption path.
// Layout: Salt(16) + RC4(Checksum(4) + Data(N))
// The checksum and data are encrypted together under a single RC4 stream.
// The checksum algorithm is undocumented so we skip it without verification.
func decryptSecretRC4(sessionKey, payload []byte) ([]byte, error) {
	if len(payload) < 24 {
		return nil, fmt.Errorf("RC4 payload too short: %d bytes", len(payload))
	}

	salt := payload[:16]
	encryptedBody := payload[16:] // checksum(4) + data, both encrypted

	// Derive key: MD5(sessionKey + salt)
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	derivedKey := h.Sum(nil)

	// RC4 decrypt checksum + data together
	rc4cipher, err := rc4.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create RC4 cipher: %w", err)
	}

	decrypted := make([]byte, len(encryptedBody))
	rc4cipher.XORKeyStream(decrypted, encryptedBody)

	// First 4 bytes are an encrypted checksum; skip it and return the data
	// as the algorithm is undocumented.
	return decrypted[4:], nil
}

// decryptSecretAES implements the AES-256-CBC ENCRYPTED_PAYLOAD decryption path.
// Layout: version(4) + unused(4) + algorithm(4) + flags(4) + salt(16) + checksum(16) + ciphertext(N)
func decryptSecretAES(sessionKey, payload []byte) ([]byte, error) {
	if len(payload) < 48 {
		return nil, fmt.Errorf("AES payload too short: %d bytes", len(payload))
	}

	// version := le.Uint32(payload[0:4])  // Already checked == 1
	// unused := le.Uint32(payload[4:8])
	// algorithm := le.Uint32(payload[8:12])
	// flags := le.Uint32(payload[12:16])
	salt := payload[16:32]
	expectedChecksum := payload[32:48]
	ciphertext := payload[48:]

	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("AES payload has no ciphertext")
	}

	// Derive AES key using SP800-108 CTR KDF with HMAC-SHA256
	derivedKey := sp800108KDFHMACSHA256(sessionKey, salt, 256)

	// AES-256-CBC decrypt with salt as IV
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("AES ciphertext not block-aligned: %d bytes", len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, salt[:aes.BlockSize])
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove PKCS7 padding
	if len(plaintext) > 0 {
		padLen := int(plaintext[len(plaintext)-1])
		if padLen > 0 && padLen <= aes.BlockSize && padLen <= len(plaintext) {
			valid := true
			for i := len(plaintext) - padLen; i < len(plaintext); i++ {
				if plaintext[i] != byte(padLen) {
					valid = false
					break
				}
			}
			if valid {
				plaintext = plaintext[:len(plaintext)-padLen]
			}
		}
	}

	// Verify checksum (HMAC-SHA256 truncated to 16 bytes)
	checksumKey := sp800108KDFHMACSHA256(sessionKey, salt, 256)
	h := hmacSHA256(checksumKey, plaintext)
	if !bytes.Equal(h[:16], expectedChecksum) {
		// Some implementations use MD5 checksum instead
		h2 := md5.New()
		h2.Write(sessionKey)
		h2.Write(plaintext)
		if !bytes.Equal(h2.Sum(nil), expectedChecksum) {
			log.Warningf("AES checksum verification failed, proceeding anyway")
		}
	}

	return plaintext, nil
}

// sp800108KDFHMACSHA256 derives a key using SP800-108 CTR mode with HMAC-SHA256.
func sp800108KDFHMACSHA256(key, label []byte, bitLen int) []byte {
	// SP800-108 in counter mode:
	// K(i) = PRF(KI, [i] || Label || 0x00 || Context || [L])
	// For MS-DRSR: Label = salt, Context = empty, L = bitLen
	iterCount := (bitLen + 255) / 256
	var result []byte

	for i := 1; i <= iterCount; i++ {
		buf := make([]byte, 0, 4+len(label)+1+4)
		// [i] as big-endian uint32
		iBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(iBuf, uint32(i))
		buf = append(buf, iBuf...)
		buf = append(buf, label...)
		buf = append(buf, 0x00)
		// [L] as big-endian uint32
		lBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(lBuf, uint32(bitLen))
		buf = append(buf, lBuf...)

		h := hmacSHA256(key, buf)
		result = append(result, h...)
	}

	return result[:bitLen/8]
}

// hmacSHA256 computes HMAC-SHA256.
func hmacSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	return mac.Sum(nil)
}

// RemoveRIDEncryption removes the RID-based DES layer from a decrypted
// unicodePwd or dBCSPwd hash. The hash is 16 bytes (NT or LM hash) encrypted
// with two DES keys derived from the user's RID.
func RemoveRIDEncryption(encrypted []byte, rid uint32, isLM bool) []byte {
	if len(encrypted) != 16 {
		return encrypted
	}

	key1, key2 := ridToDesKeys(rid)

	result := make([]byte, 16)

	// DES-ECB decrypt first 8 bytes with key1
	block1, err := des.NewCipher(key1)
	if err != nil {
		return encrypted
	}
	block1.Decrypt(result[:8], encrypted[:8])

	// DES-ECB decrypt last 8 bytes with key2
	block2, err := des.NewCipher(key2)
	if err != nil {
		return encrypted
	}
	block2.Decrypt(result[8:], encrypted[8:])

	return result
}

// ridToDesKeys derives two 8-byte DES keys from a RID value.
// This follows the standard SYSKEY/RID DES key derivation used in SAM
// and NTDS secret decryption.
func ridToDesKeys(rid uint32) ([]byte, []byte) {
	ridBytes := make([]byte, 4)
	le.PutUint32(ridBytes, rid)

	// Key1 derived from: rid[0], rid[1], rid[2], rid[3], rid[0], rid[1], rid[2]
	s1 := []byte{
		ridBytes[0], ridBytes[1], ridBytes[2], ridBytes[3],
		ridBytes[0], ridBytes[1], ridBytes[2],
	}
	// Key2 derived from: rid[3], rid[0], rid[1], rid[2], rid[3], rid[0], rid[1]
	s2 := []byte{
		ridBytes[3], ridBytes[0], ridBytes[1], ridBytes[2],
		ridBytes[3], ridBytes[0], ridBytes[1],
	}

	return strToKey(s1), strToKey(s2)
}

// strToKey converts a 7-byte string to an 8-byte DES key with parity bits.
func strToKey(s []byte) []byte {
	key := make([]byte, 8)
	key[0] = s[0] >> 1
	key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
	key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
	key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
	key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
	key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
	key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
	key[7] = s[6] & 0x7F

	for i := range key {
		key[i] = key[i] << 1
		// Set odd parity
		key[i] = setOddParity(key[i])
	}

	return key
}

func setOddParity(b byte) byte {
	bits := 0
	for i := 0; i < 8; i++ {
		if b&(1<<uint(i)) != 0 {
			bits++
		}
	}
	if bits%2 == 0 {
		b ^= 1
	}
	return b
}

// SupplementalCredentials holds parsed Kerberos keys, cleartext passwords,
// and WDigest hashes from the supplementalCredentials attribute.
type SupplementalCredentials struct {
	KerberosKeys      []KerberosKey
	ClearTextPassword string
	WDigestHashes     [][]byte
}

// Kerberos encryption type constants (RFC 3961 / RFC 3962 / MS-KILE)
const (
	ETypeDesCbcCrc              uint32 = 1
	ETypeDesCbcMd5              uint32 = 3
	ETypeRc4Hmac                uint32 = 23
	ETypeAes128CtsHmacSha196    uint32 = 17
	ETypeAes256CtsHmacSha196    uint32 = 18
	ETypeAes128CtsHmacSha256128 uint32 = 19
	ETypeAes256CtsHmacSha384192 uint32 = 20
)

var etypeNames = map[uint32]string{
	ETypeDesCbcCrc:              "des-cbc-crc",
	ETypeDesCbcMd5:              "des-cbc-md5",
	ETypeRc4Hmac:                "rc4-hmac",
	ETypeAes128CtsHmacSha196:    "aes128-cts-hmac-sha1-96",
	ETypeAes256CtsHmacSha196:    "aes256-cts-hmac-sha1-96",
	ETypeAes128CtsHmacSha256128: "aes128-cts-hmac-sha256-128",
	ETypeAes256CtsHmacSha384192: "aes256-cts-hmac-sha384-192",
}

// KerberosKey holds a single Kerberos encryption key extracted from
// supplementalCredentials.
type KerberosKey struct {
	KeyType     uint32
	KeyTypeName string
	KeyValue    []byte
}

// ParseSupplementalCredentials parses the USER_PROPERTIES structure from
// a decrypted supplementalCredentials attribute value (MS-SAMR 2.2.10.1).
func ParseSupplementalCredentials(data []byte) (*SupplementalCredentials, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("supplementalCredentials too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	// Reserved1 (4 bytes)
	var reserved1 uint32
	binary.Read(r, le, &reserved1)

	// Length (4 bytes) - total length of the USER_PROPERTIES
	var length uint32
	binary.Read(r, le, &length)

	// Reserved2 (2 bytes)
	var reserved2 uint16
	binary.Read(r, le, &reserved2)

	// Reserved3 (2 bytes)
	var reserved3 uint16
	binary.Read(r, le, &reserved3)

	// Reserved4 (96 bytes)
	reserved4 := make([]byte, 96)
	r.Read(reserved4)

	// PropertySignature (2 bytes, must be 0x50)
	var propSig uint16
	binary.Read(r, le, &propSig)
	if propSig != 0x50 {
		return nil, fmt.Errorf("invalid PropertySignature: 0x%x (expected 0x50)", propSig)
	}

	// PropertyCount (2 bytes)
	var propCount uint16
	binary.Read(r, le, &propCount)

	sc := &SupplementalCredentials{}

	for i := uint16(0); i < propCount; i++ {
		// NameLength (2 bytes) - in bytes
		var nameLen uint16
		if err := binary.Read(r, le, &nameLen); err != nil {
			break
		}

		// ValueLength (2 bytes) - in bytes
		var valueLen uint16
		binary.Read(r, le, &valueLen)

		// Reserved (2 bytes)
		var propReserved uint16
		binary.Read(r, le, &propReserved)

		// PropertyName (NameLength bytes, UTF-16LE)
		nameBytes := make([]byte, nameLen)
		r.Read(nameBytes)
		propName := decodeUTF16LE(nameBytes)

		// PropertyValue (ValueLength bytes, hex-encoded ASCII)
		valueBytes := make([]byte, valueLen)
		r.Read(valueBytes)

		// Decode hex-encoded value
		hexStr := string(valueBytes)
		decodedValue, err := hex.DecodeString(hexStr)
		if err != nil {
			log.Warningf("Failed to hex-decode property %q value: %v", propName, err)
			continue
		}

		switch propName {
		case "Primary:Kerberos-Newer-Keys":
			keys, err := parseKerberosNewerKeys(decodedValue)
			if err != nil {
				log.Warningf("Failed to parse Kerberos-Newer-Keys: %v", err)
			} else {
				sc.KerberosKeys = append(sc.KerberosKeys, keys...)
			}

		case "Primary:Kerberos":
			keys, err := parseKerberosKeys(decodedValue)
			if err != nil {
				log.Warningf("Failed to parse Kerberos: %v", err)
			} else {
				// Only add if we don't already have newer keys
				if len(sc.KerberosKeys) == 0 {
					sc.KerberosKeys = keys
				}
			}

		case "Primary:CLEARTEXT":
			sc.ClearTextPassword = decodeUTF16LE(decodedValue)

		case "Primary:WDigest":
			hashes, err := parseWDigest(decodedValue)
			if err != nil {
				log.Warningf("Failed to parse WDigest: %v", err)
			} else {
				sc.WDigestHashes = hashes
			}
		}
	}

	return sc, nil
}

// parseKerberosNewerKeys parses KERB_STORED_CREDENTIAL_NEW (MS-SAMR 2.2.10.6).
func parseKerberosNewerKeys(data []byte) ([]KerberosKey, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("Kerberos-Newer-Keys data too short")
	}

	r := bytes.NewReader(data)

	var revision uint16
	binary.Read(r, le, &revision)

	var flags uint16
	binary.Read(r, le, &flags)

	var credentialCount uint16
	binary.Read(r, le, &credentialCount)

	var serviceCredentialCount uint16
	binary.Read(r, le, &serviceCredentialCount)

	var oldCredentialCount uint16
	binary.Read(r, le, &oldCredentialCount)

	var olderCredentialCount uint16
	binary.Read(r, le, &olderCredentialCount)

	var defaultSaltLength uint16
	binary.Read(r, le, &defaultSaltLength)

	var defaultSaltMaximumLength uint16
	binary.Read(r, le, &defaultSaltMaximumLength)

	var defaultSaltOffset uint32
	binary.Read(r, le, &defaultSaltOffset)

	// DefaultIterationCount (unique to KERB_STORED_CREDENTIAL_NEW)
	var defaultIterationCount uint32
	binary.Read(r, le, &defaultIterationCount)

	totalKeys := credentialCount + serviceCredentialCount + oldCredentialCount + olderCredentialCount

	// KERB_KEY_DATA_NEW (MS-SAMR 2.2.10.7): 24 bytes per entry
	type keyEntry struct {
		Reserved1      uint16
		Reserved2      uint16
		Reserved3      uint32
		IterationCount uint32
		KeyType        uint32
		KeyLength      uint32
		KeyOffset      uint32
	}

	entries := make([]keyEntry, totalKeys)
	for i := uint16(0); i < totalKeys; i++ {
		binary.Read(r, le, &entries[i].Reserved1)
		binary.Read(r, le, &entries[i].Reserved2)
		binary.Read(r, le, &entries[i].Reserved3)
		binary.Read(r, le, &entries[i].IterationCount)
		binary.Read(r, le, &entries[i].KeyType)
		binary.Read(r, le, &entries[i].KeyLength)
		binary.Read(r, le, &entries[i].KeyOffset)
	}

	// Extract current keys (first credentialCount entries)
	// KeyOffset is from the start of the structure (MS-SAMR 2.2.10.7)
	var keys []KerberosKey
	for i := uint16(0); i < credentialCount; i++ {
		e := entries[i]
		if int(e.KeyOffset+e.KeyLength) > len(data) {
			continue
		}
		name := etypeNames[e.KeyType]
		if name == "" {
			name = fmt.Sprintf("etype-%d", e.KeyType)
		}
		keys = append(keys, KerberosKey{
			KeyType:     e.KeyType,
			KeyTypeName: name,
			KeyValue:    append([]byte(nil), data[e.KeyOffset:e.KeyOffset+e.KeyLength]...),
		})
	}

	return keys, nil
}

// parseKerberosKeys parses KERB_STORED_CREDENTIAL (MS-SAMR 2.2.10.5).
func parseKerberosKeys(data []byte) ([]KerberosKey, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("Kerberos data too short")
	}

	r := bytes.NewReader(data)

	var revision uint16
	binary.Read(r, le, &revision)

	var flags uint16
	binary.Read(r, le, &flags)

	var credentialCount uint16
	binary.Read(r, le, &credentialCount)

	var oldCredentialCount uint16
	binary.Read(r, le, &oldCredentialCount)

	var defaultSaltLength uint16
	binary.Read(r, le, &defaultSaltLength)

	var defaultSaltMaximumLength uint16
	binary.Read(r, le, &defaultSaltMaximumLength)

	var defaultSaltOffset uint32
	binary.Read(r, le, &defaultSaltOffset)

	totalKeys := credentialCount + oldCredentialCount

	// KERB_KEY_DATA (MS-SAMR 2.2.10.4): 20 bytes per entry
	type keyEntry struct {
		Reserved1 uint16
		Reserved2 uint16
		Reserved3 uint32
		KeyType   uint32
		KeyLength uint32
		KeyOffset uint32
	}

	entries := make([]keyEntry, totalKeys)
	for i := uint16(0); i < totalKeys; i++ {
		binary.Read(r, le, &entries[i].Reserved1)
		binary.Read(r, le, &entries[i].Reserved2)
		binary.Read(r, le, &entries[i].Reserved3)
		binary.Read(r, le, &entries[i].KeyType)
		binary.Read(r, le, &entries[i].KeyLength)
		binary.Read(r, le, &entries[i].KeyOffset)
	}

	// KeyOffset is from the start of the structure
	var keys []KerberosKey
	for i := uint16(0); i < credentialCount; i++ {
		e := entries[i]
		if int(e.KeyOffset+e.KeyLength) > len(data) {
			continue
		}
		name := etypeNames[e.KeyType]
		if name == "" {
			name = fmt.Sprintf("etype-%d", e.KeyType)
		}
		keys = append(keys, KerberosKey{
			KeyType:     e.KeyType,
			KeyTypeName: name,
			KeyValue:    append([]byte(nil), data[e.KeyOffset:e.KeyOffset+e.KeyLength]...),
		})
	}

	return keys, nil
}

// parseWDigest parses the WDigest hash blob (29 MD5 hashes preceded by a header).
func parseWDigest(data []byte) ([][]byte, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("WDigest data too short")
	}

	r := bytes.NewReader(data)

	// WDIGEST_CREDENTIALS header (MS-SAMR 2.2.10.8):
	// Byte 0: Reserved1 (0x31)
	// Byte 1: Reserved2 (0x00)
	// Byte 2: Version (0x01)
	// Byte 3: NumberOfHashes (0x1d = 29)
	// Bytes 4-15: Reserved3 (12 bytes)
	var reserved1 uint8
	binary.Read(r, le, &reserved1)
	var reserved2 uint8
	binary.Read(r, le, &reserved2)
	var version uint8
	binary.Read(r, le, &version)
	var numHashes uint8
	binary.Read(r, le, &numHashes)
	// Skip Reserved3 (12 bytes)
	r.Seek(12, io.SeekCurrent)

	if numHashes == 0 {
		return nil, fmt.Errorf("WDigest numHashes is 0")
	}
	if numHashes > 100 {
		return nil, fmt.Errorf("WDigest numHashes too large: %d", numHashes)
	}

	expectedSize := 16 + uint32(numHashes)*16
	if uint32(len(data)) < expectedSize {
		return nil, fmt.Errorf("WDigest data too short for %d hashes", numHashes)
	}

	hashes := make([][]byte, numHashes)
	for i := uint8(0); i < numHashes; i++ {
		hash := make([]byte, 16)
		r.Read(hash)
		hashes[i] = hash
	}

	return hashes, nil
}

// decodeUTF16LE decodes a UTF-16LE byte slice to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = le.Uint16(b[i*2:])
	}
	// Remove null terminator if present
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
