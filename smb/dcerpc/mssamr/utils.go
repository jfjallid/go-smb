// MIT License
//
// # Copyright (c) 2025 Jimmy Fjällid
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

package mssamr

import (
	"crypto/des"
	"fmt"
	"math/bits"
)

// MS-SAMR Section 2.2.11.1.2
func plusOddParity(input []byte) []byte {
	output := make([]byte, 8)
	output[0] = input[0] >> 0x01
	output[1] = ((input[0] & 0x01) << 6) | (input[1] >> 2)
	output[2] = ((input[1] & 0x03) << 5) | (input[2] >> 3)
	output[3] = ((input[2] & 0x07) << 4) | (input[3] >> 4)
	output[4] = ((input[3] & 0x0f) << 3) | (input[4] >> 5)
	output[5] = ((input[4] & 0x1f) << 2) | (input[5] >> 6)
	output[6] = ((input[5] & 0x3f) << 1) | (input[6] >> 7)
	output[7] = input[6] & 0x7f
	for i := 0; i < 8; i++ {
		if (bits.OnesCount(uint(output[i])) % 2) == 0 {
			output[i] = (output[i] << 1) | 0x1
		} else {
			output[i] = (output[i] << 1) & 0xfe
		}
	}
	return output
}

func decryptNTHash(encHash, ridBytes []byte) (hash []byte, err error) {
	nt1 := make([]byte, 8)
	nt2 := make([]byte, 8)
	desSrc1 := make([]byte, 7)
	desSrc2 := make([]byte, 7)
	shift1 := []int{0, 1, 2, 3, 0, 1, 2}
	shift2 := []int{3, 0, 1, 2, 3, 0, 1}
	for i := 0; i < 7; i++ {
		desSrc1[i] = ridBytes[shift1[i]]
		desSrc2[i] = ridBytes[shift2[i]]
	}
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	dc1, err := des.NewCipher(deskey1)
	if err != nil {
		log.Errorf("Failed to initialize first DES cipher with error: %v\n", err)
		return
	}
	dc2, err := des.NewCipher(deskey2)
	if err != nil {
		log.Errorf("Failed to initialize second DES cipher with error: %v\n", err)
		return
	}
	dc1.Decrypt(nt1, encHash[:8])
	dc2.Decrypt(nt2, encHash[8:])
	hash = append(hash, nt1...)
	hash = append(hash, nt2...)
	return
}

func encryptHashWithHash(key, hash []byte) (res []byte, err error) {
	if (len(key) != 16) || (len(hash) != 16) {
		err = fmt.Errorf("Input key and hash must both be 16 bytes length!")
		return
	}
	part1 := make([]byte, 8)
	part2 := make([]byte, 8)
	// Derive key
	desSrc1 := key[:7]
	desSrc2 := key[7:14]
	deskey1 := plusOddParity(desSrc1)
	deskey2 := plusOddParity(desSrc2)
	dc1, err := des.NewCipher(deskey1)
	if err != nil {
		log.Errorf("Failed to initialize first DES cipher with error: %v\n", err)
		return
	}
	dc2, err := des.NewCipher(deskey2)
	if err != nil {
		log.Errorf("Failed to initialize second DES cipher with error: %v\n", err)
		return
	}
	// Encrypt hash
	dc1.Encrypt(part1, hash[:8])
	dc2.Encrypt(part2, hash[8:])
	res = append(res, part1...)
	res = append(res, part2...)

	return
}
