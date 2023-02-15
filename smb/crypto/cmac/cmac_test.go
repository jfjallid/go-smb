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
package cmac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestCmac(t *testing.T) {
	/*
	   --------------------------------------------------
	     Subkey Generation
	     K              2b7e1516 28aed2a6 abf71588 09cf4f3c
	     AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
	     K1             fbeed618 35713366 7c85e08f 7236a8de
	     K2             f7ddac30 6ae266cc f90bc11e e46d513b
	     --------------------------------------------------

	     --------------------------------------------------
	     Example 1: len = 0
	     M              <empty string>
	     AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
	     --------------------------------------------------

	     Example 2: len = 16
	     M              6bc1bee2 2e409f96 e93d7e11 7393172a
	     AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
	     --------------------------------------------------

	     Example 3: len = 40
	     M              6bc1bee2 2e409f96 e93d7e11 7393172a
	                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
	                    30c81c46 a35ce411
	     AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
	     --------------------------------------------------

	     Example 4: len = 64
	     M              6bc1bee2 2e409f96 e93d7e11 7393172a
	                    ae2d8a57 1e03ac9c 9eb76fac 45af8e51
	                    30c81c46 a35ce411 e5fbc119 1a0a52ef
	                    f69f2445 df4f9b17 ad2b417b e66c3710
	     AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
	*/

	K := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	K1, _ := hex.DecodeString("fbeed618357133667c85e08f7236a8de")
	K2, _ := hex.DecodeString("f7ddac306ae266ccf90bc11ee46d513b")

	k1, k2, err := generateSubkeys(K)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, K1) {
		t.Fatal("Failed subkey generation for k1")
	}

	if !bytes.Equal(k2, K2) {
		t.Fatal("Failed subkey generation for k2")
	}

	c, err := New(K)
	if err != nil {
		t.Fatal(err)
	}

	// Message to calc cmac of
	M, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")

	// Test original AES_CMAC function
	mac, err := aesCmac(K, M, len(M))
	if err != nil {
		t.Fatal(err)
	}

	MAC, _ := hex.DecodeString("51f0bebf7e3b9d92fc49741779363cfe")
	if !bytes.Equal(mac, MAC) {
		t.Error("Fail")
	}

	// Test implementation of hash interface
	m1, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	m2, _ := hex.DecodeString("ae2d8a571e03ac9c9eb76fac45af8e51")
	m3, _ := hex.DecodeString("30c81c46a35ce411e5fbc1191a0a52ef")
	m4, _ := hex.DecodeString("f69f2445df4f9b17ad2b417be66c3710")
	c.Reset()
	c.Write(m1)
	c.Write(m2)
	c.Write(m3)
	c.Write(m4)
	mac2 := c.Sum(nil)
	if !bytes.Equal(mac2, MAC) {
		t.Error("Fail")
	}
}
