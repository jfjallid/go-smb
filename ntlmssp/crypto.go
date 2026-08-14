// MIT License
//
// # Copyright (c) 2017 stacktitan
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
package ntlmssp

import (
	"crypto/hmac"
	"crypto/md5"
	"strings"

	"github.com/jfjallid/go-smb/smb/unicode"
	// NTLM (MS-NLMP) mandates MD4 for the NT hash (NTOWFv1 = MD4(UTF-16LE(password))).
	// MD4 is cryptographically broken, but this is a protocol-compatibility
	// requirement, not a security choice; it cannot be replaced.
	//lint:ignore SA1019 MD4 is required by MS-NLMP for the NT hash, not a security choice.
	"golang.org/x/crypto/md4"
)

func Ntowfv1(pass string) []byte {
	hash := md4.New()
	hash.Write(unicode.ToUnicode(pass))
	return hash.Sum(nil)
}

func Ntowfv2(pass, user, domain string) []byte {
	h := hmac.New(md5.New, Ntowfv1(pass))
	h.Write(unicode.ToUnicode(strings.ToUpper(user) + domain))
	return h.Sum(nil)
}

func Ntowfv2Hash(user, domain string, hash []byte) []byte {
	h := hmac.New(md5.New, hash)
	h.Write(unicode.ToUnicode(strings.ToUpper(user) + domain))
	return h.Sum(nil)
}

func Lmowfv2(pass, user, domain string) []byte {
	return Ntowfv2(pass, user, domain)
}

func ComputeResponseNTLMv2(nthash, lmhash, clientChallenge, serverChallenge, timestamp, avpairs []byte) []byte {

	temp := []byte{1, 1}
	temp = append(temp, 0, 0, 0, 0, 0, 0)
	temp = append(temp, timestamp...)
	temp = append(temp, clientChallenge...)
	temp = append(temp, 0, 0, 0, 0)
	temp = append(temp, avpairs...) // Encoded AV_Pairs
	temp = append(temp, 0, 0, 0, 0) // Simulated AV_Pair MsvAvEOL

	h := hmac.New(md5.New, nthash)
	h.Write(append(serverChallenge, temp...))
	ntproof := h.Sum(nil)
	return append(ntproof, temp...)
}
