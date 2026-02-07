// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
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

package dcerpc

import (
	"crypto/des"
	"encoding/binary"
	"fmt"
	"math/bits"
)

// A couple of helper functions defined in MS-LSAD 5.1.2 for Secret Encryption

func advanceKey(fullKey, subkey []byte) []byte {
	// AdvanceKey function simplified as we don't care about keeping track of the key position
	newKey := subkey[7:]
	if len(newKey) < 7 {
		newKey = fullKey[len(newKey):]
	}
	return newKey
}

// plusOddParity function
func transformKey(input []byte) []byte {
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

// MS-LSAD 5.1.2 and 5.1.3 combined
func EncryptSecretDes(key, input []byte) (ciphertext []byte, err error) {
	if len(key) != 16 {
		err = fmt.Errorf("Invalid key size for MS-LSAD secret encryption. Expected a 16 byte key!")
		log.Errorln(err)
		return
	}
	/*
	   DECLARE Version as ULONG
	   SET Version to 1
	   SET buffer to input->length
	   SET (buffer + 4) to Version
	*/
	input0 := []byte{}
	input0 = binary.LittleEndian.AppendUint32(input0, uint32(len(input)))
	input0 = binary.LittleEndian.AppendUint32(input0, 1)

	// CALL des_ecb_lm_enc(buffer, sessionkey[keyindex], output->buffer)
	key0 := key
	tmpKey := transformKey(key0[:7])
	block, err := des.NewCipher(tmpKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	tmpBuf := make([]byte, 8)
	block.Encrypt(tmpBuf, input0[:8])
	// INCREMENT output->buffer by blocklen
	// INCREMENT output->length by blocklen
	ciphertext = append(ciphertext, tmpBuf...)

	// SET keyindex to AdvanceKey(keyindex)
	key0 = advanceKey(key, key0)

	// LET remaining be input->length
	limit := len(input)
	// WHILE remaining > blocklen
	for i := 0; i < limit; i += 8 {
		if len(input) < 8 {
			// Zero padd
			input = append(input, make([]byte, 8-len(input))...)
		}

		tmpBuf := make([]byte, 8)
		tmpKey := transformKey(key0[:7])
		block, err = des.NewCipher(tmpKey)
		if err != nil {
			log.Errorln(err)
			return
		}
		block.Encrypt(tmpBuf, input[:8])
		// INCREMENT input->buffer by blocklen
		input = input[8:]
		// INCREMENT output->buffer by blocklen
		// INCREMENT output->length by blocklen
		ciphertext = append(ciphertext, tmpBuf...)
		// SET keyindex to AdvanceKey(keyindex)
		key0 = advanceKey(key, key0)
	}
	return
}
