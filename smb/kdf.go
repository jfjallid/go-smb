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
package smb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

/*
Code taken from NIST SP 800-108 Section 5.1
KDF in counter mode.

MS-SMB2 Section 3.1.4.2:
r = 32
If Connection.CipherId is AES-128-CCM or AES-128-GCM, 'L' value is initialized to 128. If
Connection.CipherId is AES-256-CCM or AES-256-GCM, ‘L’ value is initialized to 256.
The PRF used in the key derivation MUST be HMAC-SHA256
which means that h = 256.

From NIST SP 800-108:
Parameters
h: length of output in bits
r: Length of binary representation of counter i
Input
Ki, Label, Context, and L

Process:
1. n := L/h.
2. If n > 2r−1, then output an error indicator and stop (i.e., skip steps 3, 4, and 5).
3. result:= ∅.
4. For i = 1 to n, do
    a. K(i) := PRF (KI, [i]2 || Label || 0x00 || Context || [L]2),
    b. result = result || K(i).
5. KO := the leftmost L bits of result.
*/

func kdf(ki, label, context []byte, L uint32) []byte {

	h := hmac.New(sha256.New, ki)
	if L != 128 && L != 256 {
		panic("Unsupported L value. Only support 128 or 256.")
	}

	// Since L/h is either 128/256 = 0.5 or 256/256 = 1
	// there is only going to be one lap in the loop so we can flatten it.
	// i will be a byte array of length R with the value of 1 since there is only a single lap.
	i := append(make([]byte, 3), byte(0x01))

	//K(i) := PRF (KI, [i] || Label || 0x00 || Context || [L]),
	h.Write(i)
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(context)
	h.Write(binary.BigEndian.AppendUint32(nil, L))

	// MS-SMB2 only want 16 bytes output
	return h.Sum(nil)[:L/8]
}
