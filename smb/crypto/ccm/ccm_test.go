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

import (
	"bytes"
	"crypto/aes"
	//"fmt"
	"testing"
)

func TestCCM(t *testing.T) {

	// Key
	// Try encrypt a message and then decrypt it to verify the tag
	msg := []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc accumsan ante urna. Mauris dictum libero orci. Donec a enim mi.")
	key := []byte("YELLOW SUBMARINE")
	nonce := []byte("LOREM IPSUM")
	ciph, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cMAC, err := NewCCMWithNonceAndTagSizes(ciph, len(nonce), 16)
	if err != nil {
		t.Fatal(err)
	}

	//fmt.Printf("Using a msg of len %d bytes, nonce: %d bytes, and tag size: %d\n", len(msg), len(nonce), 16)
	ciphertext := make([]byte, 0, len(msg))
	ciphertext = cMAC.Seal(ciphertext, nonce, msg, nil)
	if ciphertext == nil {
		t.Fatal("Seal() function returned nil")
	}

	//fmt.Printf("Got a %d byte ciphertext: %x\n", len(ciphertext), ciphertext)

	plaintext := make([]byte, 0, len(msg))

	plaintext, err = cMAC.Open(plaintext, nonce, ciphertext, nil)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(plaintext, msg) != 0 {
		t.Fatal("Plaintext does not match original message")
	}
}
