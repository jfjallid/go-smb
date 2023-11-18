// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
package ccm

/* AES in CCM mode algorithm from
NIST Special Publication SP 800-38c
implemented with the help from a nice illustration provided at
https://xilinx.github.io/Vitis_Libraries/security/2020.1/_images/CCM_encryption.png
*/

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"

	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/crypto/ccm")

type ccm struct {
	c         cipher.Block
	mac       *mac
	nonceSize int
	tagSize   int
}

// NewCCMWithNonceAndTagSizes takes a 128-bit block cipher, a nonce size and a tag size
// as input and wraps them in Counter mode with CBC-MAC.
// The nonceSize must be one of {7, 8, 9, 10, 11, 12, 13} bytes
// The tagSize must be one of {4, 6, 8, 10, 12, 14, 16} bytes
// The maximum payload size is based on the size of the nonce using a formula of
// max payload size = 2^((15 - nonceSize)*8) - 1
// If the payload exceeds the max size on Seal, nil is returned as there is no error in the
// return values defined by the AEAD interface.
// For Seal, the max payload is the size of the plaintext. For Open, the max payload size is
// defined as the size of the cipertext - the tagSize
func NewCCMWithNonceAndTagSizes(c cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {

	// Check length requirements from A.1
	if c.BlockSize() != 16 {
		err := fmt.Errorf("CCM mode requires a 16 byte (128-bit) block cipher but got a %d byte", c.BlockSize())
		log.Errorln(err.Error())
		return nil, err
	}

	if (nonceSize < 7) || (nonceSize > 13) {
		err := fmt.Errorf("CCM: invalid size of nonce. Accepted values are: {7, 8, 9, 10, 11, 12, 13} but received (%d)", nonceSize)
		log.Errorln(err.Error())
		return nil, err
	}

	if ((tagSize < 4) || (tagSize > 16)) || ((tagSize % 2) != 0) {
		err := fmt.Errorf("CCM: invalid tag size. Accepted values are: {4, 6, 8, 10, 12, 14, 16} but received (%d)", tagSize)
		log.Errorln(err.Error())
		return nil, err
	}

	return &ccm{
		c:         c,
		mac:       newMAC(c),
		nonceSize: nonceSize,
		tagSize:   tagSize,
	}, nil
}

func (ccm *ccm) NonceSize() int {
	return ccm.nonceSize
}

func (ccm *ccm) Overhead() int {
	return ccm.tagSize
}

func (ccm *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	/* In generation-encryption, cipher block chaining is applied to the payload, the associated data, and the nonce to
	   generate a message authentication code (MAC) then, counter mode encryption is applied to the MAC and the payload
	   to transform them into an unreadable form, called the ciphertext.

	   The algorithm for encryption:
	   1. Format a 16 byte block containing some flags, the nonce, and size of plaintext
	   2. Encrypt the first block using the AES cipher in CBC mode with an IV of 0
	   3. Format the additional data into more blocks and encrypt them with the CBC cipher
	   4. Continue to encrypt the plaintext blocks using the CBC cipher.
	   5. Save the last block of the output from the cipheroutput for later
	   6. Format a 16 byte Ctr block and encrypt it using the AES cipher and save the output for later
	   7. Initialize AES in CTR mode with cipher.NewCTR on the initial Ctr block
	   8. XOR the entire plaintext with the output from the CTR stream to produce the ciphertext
	   9. XOR the output from 5 with the output from 6 to produce the authentication tag.
	*/

	if len(nonce) != ccm.nonceSize {
		err := fmt.Sprintf("Seal: Incorrect size of nonce for AES CCM. Got %d and expected %d", len(nonce), ccm.nonceSize)
		log.Criticalln(err)
		panic(err)
	}

	/*
	   P: The payload
	   Plen: The bit length of the payload
	   Q: Bit string representation of the octet length of P
	   q: The octet length of the binary representation of the octet length of the payload
	   n: The octet length of the nonce
	   So if the payload length is say 4 bytes
	   Plen would be 4*8 = 32
	   Q would be 0b00100000
	   q would be 1

	   From A.1
	   n + q = 15
	   q = 15 - n
	   [q-1] = 15 - n - 1

	   15 - ccm.nonceSize would be max bytes for q
	   so if the nonce size is 11 bytes, the max number of octets to represent the payload bitstring is 4 bytes
	   so we have to check the greatest uint64 value that can fit in 4 bytes as we must encode the length

	*/
	// Check if max size of plaintext exceeds the bytes left to store the octet length of the binary
	// representation of the octet length of the plaintext e.g., do we have enough bytes left to store
	// the q value?
	if maxUint64ValueInBytes(15-ccm.nonceSize) < uint64(len(plaintext)) {
		log.Errorln("Supplied plaintext was too large to encrypt with the given size of nonce")
		return nil
	}

	// The AEAD interface Seal function states that the ciphertext and tag should
	// be appended to the dst variable, so need to make some extra room
	result, ciphertext := extendSliceForAppend(dst, len(plaintext)+ccm.mac.Size())

	// Apply the formatting function to (N, A, P) to produce the blocks B_0, B_1, ..., B_r
	b0 := ccm.formatFirstInputBlock(nonce, plaintext, additionalData)

	// Set Y_0 = CIPH_k(B_0)
	y0 := make([]byte, 16)
	ccm.c.Encrypt(y0, b0)

	// Get AdditionalData and Payload blocks and for each block,
	// encrypt it using AES-CBC e.g., XOR B_i with previously encrypted block (y_i-1) and then encrypt it to get y_i
	// e.g., using ccm.mac.Write() with each block
	// For i = 1 to r, do Y_i = CIPH_k(B_i xor Y_i-1)
	// Set T=MSB_Tlen(Y_r)
	mac := ccm.calculateMAC(nonce, plaintext, additionalData)

	// 5. Apply the counter generation function to generate the counter blocks Ctr_0, Ctr_1, ..., Ctr_m where m = [Plen/128]
	Ctr := make([]byte, 16)
	Ctr[0] = byte(15 - ccm.nonceSize - 1)
	copy(Ctr[1:], nonce)

	s0 := ciphertext[len(plaintext):]
	ccm.c.Encrypt(s0, Ctr)
	// The last part of Ctr_i is the index i
	// The ctr should be represented as q blocks where q = 15 - nonceSize
	putUvarintAsBigEndian(Ctr[1+ccm.nonceSize:], 1) // [i]8q stored in octet number 16-q ... 15
	ctr := cipher.NewCTR(ccm.c, Ctr)
	ctr.XORKeyStream(ciphertext, plaintext)

	// Return C=(P xor MSB_Plen(s)) || (T xor MSB_Tlen(S_0))
	subtle.XORBytes(s0, s0, mac)

	return result[:len(plaintext)+ccm.tagSize]
}

func (self *ccm) Open(dst, nonce, ciphertext, additionalData []byte) (result []byte, err error) {

	/*
	   The algorithm for decryption:
	   1. Format a 16 byte Ctr block and encrypt it using the AES cipher and save the output for later
	   2. Initialize AES in CTR mode with cipher.NewCTR on the initial Ctr block
	   3. XOR the entire ciphertext with the output from the CTR stream to produce the plaintext
	   4. Format a 16 byte block containing some flags, the nonce, and size of ciphertext?
	   5. Encrypt the first block using the AES cipher in CBC mode with an IV of 0
	   6. Format the additional data into more blocks and encrypt them with the CBC cipher
	   7. Encrypt the entire plaintext with the AES-CBC cipher
	   8. XOR the output from step 1 with the last output block from step 7 to produce the authentication tag.
	*/

	if self.tagSize > len(ciphertext) {
		err = fmt.Errorf("The ciphertext must be of a greater length than the tag size")
		log.Errorln(err)
		return
	}

	if self.nonceSize > len(nonce) {
		err = fmt.Errorf("Incorrect nonce size. Must match size specified at initialization")
		log.Errorln(err)
		return
	}

	// From A.1
	// n + q = 15
	// q = 15 - n
	// Check if the ciphertext is too large for the specified tagSize as the size of the
	// plaintext must be encoded within the bytes left by 15 - nonceSize
	if maxUint64ValueInBytes(15-self.nonceSize) < uint64(len(ciphertext)-self.tagSize) {
		err = fmt.Errorf("The size of the ciphertext is too large for the given size of nonce")
		log.Errorln(err.Error())
		return
	}

	// The AEAD interface Open function states that the plaintext should be appended
	// to the dst variable, so need to make some extra room
	result, plaintext := extendSliceForAppend(dst, len(ciphertext)-self.mac.Size())

	// From A.1
	// n + q = 15
	// q = 15 - n
	// [q-1] = 15 - n - 1
	Ctr := make([]byte, 16)
	Ctr[0] = byte(15 - self.nonceSize - 1) // [q-1]3
	copy(Ctr[1:], nonce)

	s0 := make([]byte, 16)
	self.c.Encrypt(s0, Ctr)
	// The last part of Ctr_i is the index i
	// The ctr should be represented as q blocks where q = 15 - nonceSize
	putUvarintAsBigEndian(Ctr[1+self.nonceSize:], 1) // [i]8q stored in octet number 16-q ... 15
	ctr := cipher.NewCTR(self.c, Ctr)
	ctr.XORKeyStream(plaintext, ciphertext[:len(plaintext)])

	// Format B0
	b0 := self.formatFirstInputBlock(nonce, plaintext, additionalData)

	// Set Y_0 = CIPH_k(B_0)
	y0 := make([]byte, 16)
	self.c.Encrypt(y0, b0)

	mac := self.calculateMAC(nonce, plaintext, additionalData)

	subtle.XORBytes(mac, mac, s0)

	// Check if calculated tag matches provided tag
	if bytes.Compare(mac, ciphertext[len(plaintext):]) != 0 {
		err := fmt.Errorf("Invalid authentication tag on ciphertext")
		log.Errorln(err)
		return nil, err
	}

	return
}

func (ccm *ccm) formatFirstInputBlock(nonce, plaintext, additionalData []byte) []byte {
	// Formatting of nonce and control information (Section A.2.1)
	// First octet of B0 is structured as: 1 bit reserved, 1 bit Adata, 3 bits T, 3 bits Q
	// Adata is 0 if len(additionalData) == 0
	// T is the size of the MAC in bytes in [(t-2)/2] so 8 bytes MAC is (8-2)/2 = 3 (in bitnotation 011)
	// Q is determines the size of the Nonce based on the Field of the Size of the Length Field (L)

	ccm.mac.Reset()
	b := make([]byte, 16)
	// the first three bits of B0 are [q-1] can be calculated based on the size of the nonce
	b[0] = byte(15 - ccm.nonceSize - 1) // [q-1]
	// the next 3 bits are the size of the MAC
	b[0] |= byte(((ccm.tagSize - 2) / 2) << 3) // [(t-2)/2]
	// Set bit 6 to 1 if there is additionalData
	if len(additionalData) > 0 {
		b[0] |= byte(1 << 6)
	}

	// The rest of the 16 bytes are used for the Nonce
	copy(b[1:], nonce)

	// Q is appended to the last bytes and is a bit string representation of the octet length of the plaintext (P)
	putUvarintAsBigEndian(b[1+ccm.nonceSize:], uint64(len(plaintext)))

	return b
}

func (ccm *ccm) calculateMAC(nonce, plaintext, additionalData []byte) []byte {
	ccm.mac.Reset()

	b := make([]byte, 16)
	// the first three bits of B0 are [q-1] can be calculated based on the size of the nonce
	b[0] = byte(15 - ccm.nonceSize - 1) // [q-1]
	// the next 3 bits are the size of the MAC
	b[0] |= byte(((ccm.tagSize - 2) / 2) << 3) // [(t-2)/2]
	// Set bit 6 to 1 if there is additionalData
	if len(additionalData) > 0 {
		b[0] |= byte(1 << 6)
	}

	// The rest of the 16 bytes are used for the Nonce
	copy(b[1:], nonce)

	// Q is appended to the last bytes and is a bit string representation of the octet length of the plaintext (P)
	putUvarintAsBigEndian(b[1+ccm.nonceSize:], uint64(len(plaintext)))
	ccm.mac.Write(b)

	b = make([]byte, 16)
	a := uint64(len(additionalData))
	if a > 0 {
		// If 0 < 2^16 - 2^8, then a is encoded as [a]_16 i.e.., two octets
		// if 2^16 - 2^8 <= a <= 2^32, then a is encoded as 0xff || 0xfe || [a]_32, i.e., size octets
		// if 2^32 <= a < 2^64, then a is encoded as 0xff || 0xff || [a]_64, i.e., ten octets
		// go-smb2 uses weird limits of 1<<15 - 1<<7 instead of 2^16 - 2^8 which produces other limit values
		// Will attempt to use the ordinary limits instead and hope that it works
		ccm.c.BlockSize()
		if a < 0xff00 {
			// Two octets
			putUvarintAsBigEndian(b[:2], uint64(len(additionalData)))
			ccm.mac.Write(b[:2])
		} else if a < (1 << 32) {
			// Six octets
			b[0] = 0xff
			b[1] = 0xfe
			putUvarintAsBigEndian(b[2:6], uint64(len(additionalData)))
			ccm.mac.Write(b[:6])
		} else if a < ((1 << 64) - 1) {
			// Ten octets
			b[0] = 0xff
			b[1] = 0xff
			putUvarintAsBigEndian(b[2:10], uint64(len(additionalData)))
			ccm.mac.Write(b[:10])
		}
		ccm.mac.Write(additionalData)
		ccm.mac.PadZero()
	} else {
		ccm.mac.Write(b)
	}

	ccm.mac.Write(plaintext)
	ccm.mac.PadZero()

	return ccm.mac.Sum(nil)
}

func maxUint64ValueInBytes(n int) uint64 {
	if n > 8 {
		n = 8
	}
	return (1 << (n * 8)) - 1
}

func putUvarintAsBigEndian(buf []byte, value uint64) {
	sliceLen := len(buf)
	for i := 0; i < sliceLen; i++ {
		bytePos := (sliceLen - i) - 1
		bitshift := uint(8 * bytePos)
		buf[i] = byte(value >> bitshift)
	}
}

// extendSliceForAppend takes a slice and prepares it for appending data
// It takes two arguments: a slice of bytes and an int specifying a size as input
// and returns two slices head and tail such that head is a ptr to the beginning
// of the slice and tail is a ptr to the start of the unused part of the slice.
// If the input slice had enough free space to add the number of bytes specified
// by the second argument, it is returned with a second ptr (tail) to where the free
// space begins. Otherwise a new slice is allocated with the old content and with
// extra space for the new bytes to be added.
func extendSliceForAppend(s []byte, n int) (head, tail []byte) {
	currentSize := len(s)
	requiredSize := currentSize + n
	if cap(s) > requiredSize {
		// Trim extra size if the input slice is bigger than specified
		head = s[:requiredSize]
	} else {
		head = make([]byte, requiredSize)
		copy(head[:currentSize], s[:currentSize])
	}
	tail = head[currentSize:]
	return
}
