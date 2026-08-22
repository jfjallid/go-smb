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
	"bytes"
	"strings"
	"testing"
)

// authorityPrefix is the marshalled form of a [unique] pwszAuthority of "CA":
// referent id, conformant-varying header (max=3, offset=0, actual=3), the
// UTF-16LE characters plus NUL, then padding back to a 4-byte boundary.
var authorityPrefix = []byte{
	0x00, 0x00, 0x02, 0x00, // referent id
	0x03, 0x00, 0x00, 0x00, // max_count = 3 ("CA" + NUL)
	0x00, 0x00, 0x00, 0x00, // offset
	0x03, 0x00, 0x00, 0x00, // actual_count = 3
	0x43, 0x00, 0x41, 0x00, 0x00, 0x00, // "C","A",NUL
	0x00, 0x00, // pad to 4
}

func withAuthority(tail ...byte) []byte {
	return append(append([]byte{}, authorityPrefix...), tail...)
}

func TestResubmitRequestMarshal(t *testing.T) {
	b, err := encodeStub(&ResubmitRequestReq{PwszAuthority: "CA", DwRequestId: 7})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := withAuthority(0x07, 0x00, 0x00, 0x00) // dwRequestId = 7
	if !bytes.Equal(b, want) {
		t.Errorf("ResubmitRequest layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestDenyRequestMarshal(t *testing.T) {
	b, err := encodeStub(&DenyRequestReq{PwszAuthority: "CA", DwRequestId: 9})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := withAuthority(0x09, 0x00, 0x00, 0x00)
	if !bytes.Equal(b, want) {
		t.Errorf("DenyRequest layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestGetCAPropertyMarshal(t *testing.T) {
	b, err := encodeStub(&GetCAPropertyReq{
		PwszAuthority: "CA",
		PropId:        CRPropTemplates,
		PropIndex:     0,
		PropType:      PropTypeString,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := withAuthority(
		0x1d, 0x00, 0x00, 0x00, // PropId = CR_PROP_TEMPLATES
		0x00, 0x00, 0x00, 0x00, // PropIndex
		0x04, 0x00, 0x00, 0x00, // PropType = PROPTYPE_STRING
	)
	if !bytes.Equal(b, want) {
		t.Errorf("GetCAProperty layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestSetCAPropertyMarshal(t *testing.T) {
	b, err := encodeStub(&SetCAPropertyReq{
		PwszAuthority:     "CA",
		PropId:            CRPropTemplates,
		PropType:          PropTypeString,
		PctbPropertyValue: newBlob(encodeUTF16Raw("A\nB")),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := withAuthority(
		0x1d, 0x00, 0x00, 0x00, // PropId
		0x00, 0x00, 0x00, 0x00, // PropIndex
		0x04, 0x00, 0x00, 0x00, // PropType
		0x06, 0x00, 0x00, 0x00, // blob Cb = 6 bytes
		0x04, 0x00, 0x02, 0x00, // blob referent id
		0x06, 0x00, 0x00, 0x00, // blob max_count
		0x41, 0x00, 0x0a, 0x00, 0x42, 0x00, // "A\nB" UTF-16LE, no NUL
	)
	if !bytes.Equal(b, want) {
		t.Errorf("SetCAProperty layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestGetCASecurityMarshal(t *testing.T) {
	b, err := encodeStub(&GetCASecurityReq{PwszAuthority: "CA"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Sole parameter: no trailing pad after the string.
	want := authorityPrefix[:len(authorityPrefix)-2]
	if !bytes.Equal(b, want) {
		t.Errorf("GetCASecurity layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestSetCASecurityMarshal(t *testing.T) {
	b, err := encodeStub(&SetCASecurityReq{PwszAuthority: "CA", PctbSD: newBlob([]byte{1, 2, 3, 4, 5})})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := withAuthority(
		0x05, 0x00, 0x00, 0x00, // Cb = 5
		0x04, 0x00, 0x02, 0x00, // referent id
		0x05, 0x00, 0x00, 0x00, // max_count = 5
		0x01, 0x02, 0x03, 0x04, 0x05,
	)
	if !bytes.Equal(b, want) {
		t.Errorf("SetCASecurity layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

// TestResubmitResponseDecode checks the [out] disposition and the trailing
// HRESULT are recovered from a server-shaped stub.
func TestResubmitResponseDecode(t *testing.T) {
	stub := []byte{
		0x03, 0x00, 0x00, 0x00, // pdwDisposition = 3 (issued)
		0x00, 0x00, 0x00, 0x00, // HRESULT = S_OK
	}
	res := ResubmitRequestRes{}
	if err := decodeStub(stub, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.PdwDisposition != DispIssued || res.ReturnValue != 0 {
		t.Errorf("got disposition %d rv 0x%x, want 3 / 0", res.PdwDisposition, res.ReturnValue)
	}
}

// TestTemplateListRoundTrip verifies the CA's newline-separated name/OID list
// survives a decode/encode cycle byte-for-byte, including the trailing NUL the
// CA appends — SetCAProperty writes the list back in exactly that form.
func TestTemplateListRoundTrip(t *testing.T) {
	original := encodeUTF16Raw("User\n1.2.3\nMachine\n1.2.4\n\x00")
	list := splitTemplateBlob(t, original)
	want := []string{"User", "1.2.3", "Machine", "1.2.4", "\x00"}
	if len(list) != len(want) {
		t.Fatalf("got %d entries %q, want %d", len(list), list, len(want))
	}
	for i := range want {
		if list[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, list[i], want[i])
		}
	}
	if got := encodeUTF16Raw(strings.Join(list, "\n")); !bytes.Equal(got, original) {
		t.Errorf("round trip changed bytes\n got: % x\nwant: % x", got, original)
	}
}

func splitTemplateBlob(t *testing.T, blob []byte) []string {
	t.Helper()
	return strings.Split(decodeUTF16Raw(blob), "\n")
}
