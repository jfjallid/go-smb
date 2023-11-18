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

import "crypto/cipher"

/*
CBC-MAC follows a simple algorithm of:
1. Divide the message into with a length chunks of blocksize
2. XOR the first block with 0 and then encrypt the result using the AES-CBC cipher block.
3. XOR the next block with the result from the previous step and then encrypt the resulting block
4. Repeat step 3 for the rest of the blocks
*/
type mac struct {
	c   cipher.Block
	ptr int    // current position in block i
	ci  []byte // block i where c0 is the IV of 0
}

func newMAC(c cipher.Block) *mac {
	return &mac{
		c:  c,
		ci: make([]byte, c.BlockSize()),
	}
}

func (self *mac) Reset() {
	for i, _ := range self.ci {
		self.ci[i] = 0
	}
	self.ptr = 0
}

func (self *mac) Write(p []byte) (n int, err error) {
	for _, b := range p {
		if self.ptr >= len(self.ci) {
			self.c.Encrypt(self.ci, self.ci)
			self.ptr = 0
		}
		self.ci[self.ptr] ^= b
		self.ptr++
	}
	return len(p), nil
}

func (self *mac) Sum(b []byte) []byte {
	return append(b, self.ci...)
}

func (self *mac) Size() int {
	return len(self.ci)
}

func (self *mac) BlockSize() int {
	return 16 // Always 128 bit block size for AES
}

func (self *mac) PadZero() {
	if self.ptr != 0 {
		self.c.Encrypt(self.ci, self.ci)
		self.ptr = 0
	}
}
