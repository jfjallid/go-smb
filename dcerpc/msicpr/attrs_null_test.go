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
package msicpr

import (
	"encoding/binary"
	"testing"
)

// TestDCOMEmptyAttributesAreNull pins the fix for the DCOM/ICPR disagreement on
// empty request attributes: over DCOM, "no attributes" (a nil *string) must
// marshal as a NULL referent pointer, NOT a pointer to an empty wide string
// L"". The CA rejects the latter on the retrieve-pending path with
// 0x80070057 (ERROR_INVALID_PARAMETER).
//
// Layout for authority "CA": DwFlags(4) + authority[refid(4)+max(4)+off(4)+
// actual(4)+"CA\0"=6→pad8] = 24 + PdwRequestId(4) → the pwszAttributes pointer
// referent-id sits at byte offset 32.
func TestDCOMEmptyAttributesAreNull(t *testing.T) {
	const attrsPtrOff = 32

	// nil attributes → NULL pointer (referent id 0), no referent bytes follow.
	bNull, err := (&CertServerRequestDReq{
		PwszAuthority: "CA",
		PdwRequestId:  7,
		PctbRequest:   newBlob([]byte{0xAA, 0xBB}),
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal nil attrs: %v", err)
	}
	if got := binary.LittleEndian.Uint32(bNull[attrsPtrOff:]); got != 0 {
		t.Fatalf("nil attributes must marshal as a NULL pointer, got referent id 0x%08x", got)
	}

	// A pointer to "" is the WRONG encoding this fix avoids: non-null pointer
	// plus an L"" referent. It must differ from, and be longer than, NULL.
	empty := ""
	bEmpty, err := (&CertServerRequestDReq{
		PwszAuthority:  "CA",
		PdwRequestId:   7,
		PwszAttributes: &empty,
		PctbRequest:    newBlob([]byte{0xAA, 0xBB}),
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal empty-string attrs: %v", err)
	}
	if got := binary.LittleEndian.Uint32(bEmpty[attrsPtrOff:]); got == 0 {
		t.Fatal("a pointer to \"\" should be non-null (this is the encoding the CA rejects)")
	}
	if len(bNull) >= len(bEmpty) {
		t.Fatalf("NULL stub (%d B) should be shorter than the L\"\" stub (%d B)", len(bNull), len(bEmpty))
	}
}
