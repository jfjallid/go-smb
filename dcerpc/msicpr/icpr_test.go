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
	"testing"
)

// TestCertServerRequestMarshalLayout verifies the per-parameter referent layout
// that Windows' NDR engine requires (validated against a live CA):
// each parameter's pointer referent is written inline right after that
// parameter, not deferred to the end of the request.
func TestCertServerRequestMarshalLayout(t *testing.T) {
	req := CertServerRequestReq{
		DwFlags:       0,
		PwszAuthority: "CA",
		PdwRequestId:  0,
		PctbAttribs:   newBlob([]byte{0x41, 0x42}),       // "AB"
		PctbRequest:   newBlob([]byte{0xDE, 0xAD, 0xBE}), // 3 bytes
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// dwFlags(0) | auth[refid, max=3,off=0,act=3, "C","A",NUL] pad |
	// pdwRequestId(0) | attribs[Cb=2, refid, max=2, "AB"] pad | request[Cb=3, refid, max=3, DEADBE]
	want := []byte{
		0x00, 0x00, 0x00, 0x00, // dwFlags
		0x00, 0x00, 0x02, 0x00, // auth refid
		0x03, 0x00, 0x00, 0x00, // max_count = 3 (CA + NUL)
		0x00, 0x00, 0x00, 0x00, // offset
		0x03, 0x00, 0x00, 0x00, // actual_count = 3
		0x43, 0x00, 0x41, 0x00, 0x00, 0x00, // "C","A",NUL (UTF-16LE)
		0x00, 0x00, // pad to 4
		0x00, 0x00, 0x00, 0x00, // pdwRequestId
		0x02, 0x00, 0x00, 0x00, // attribs.Cb = 2
		0x04, 0x00, 0x02, 0x00, // attribs.Pb refid
		0x02, 0x00, 0x00, 0x00, // attribs.Pb max_count = 2
		0x41, 0x42, // "AB"
		0x00, 0x00, // pad to 4
		0x03, 0x00, 0x00, 0x00, // request.Cb = 3
		0x08, 0x00, 0x02, 0x00, // request.Pb refid
		0x03, 0x00, 0x00, 0x00, // request.Pb max_count = 3
		0xDE, 0xAD, 0xBE, // 3 bytes, no trailing pad (final parameter)
	}
	if !bytes.Equal(b, want) {
		t.Errorf("marshal layout mismatch\n got: % x\nwant: % x", b, want)
	}
}

func TestCertServerRequestMarshalNullBlob(t *testing.T) {
	// The download/retrieve path sends a request with no CSR and empty attribs.
	req := CertServerRequestReq{PwszAuthority: "CA", PdwRequestId: 7}
	b, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Both blobs are NULL unique pointers: Cb=0, refid=0.
	// Tail: pdwRequestId(7) | attribs[Cb=0, refid=0] pad | request[Cb=0, refid=0]
	tail := b[len(b)-20:]
	want := []byte{
		0x07, 0x00, 0x00, 0x00, // pdwRequestId = 7
		0x00, 0x00, 0x00, 0x00, // attribs.Cb = 0
		0x00, 0x00, 0x00, 0x00, // attribs NULL ptr
		0x00, 0x00, 0x00, 0x00, // request.Cb = 0
		0x00, 0x00, 0x00, 0x00, // request NULL ptr
	}
	if !bytes.Equal(tail, want) {
		t.Errorf("null-blob tail mismatch\n got: % x\nwant: % x", tail, want)
	}
}

// TestResponseRoundTrip encodes a response the way the server does (per-parameter
// inline referents) and checks Unmarshal recovers every field.
func TestResponseRoundTrip(t *testing.T) {
	buf := new(bytes.Buffer)
	binWrite := func(v uint32) {
		buf.Write([]byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)})
	}
	binWrite(42) // pdwRequestId
	binWrite(3)  // pdwDisposition (issued)
	// pctbCertChain: NULL
	binWrite(0) // Cb
	binWrite(0) // refid = NULL
	// pctbEncodedCert: 5 bytes
	cert := []byte{0x30, 0x82, 0x00, 0x01, 0x02}
	binWrite(uint32(len(cert)))
	binWrite(0x00020000) // refid
	binWrite(uint32(len(cert)))
	buf.Write(cert)
	buf.WriteByte(0) // pad to 4 (5 -> 8)
	buf.WriteByte(0)
	buf.WriteByte(0)
	// pctbDispositionMessage: "Hi\0" UTF-16LE = 6 bytes
	msg := []byte{'H', 0, 'i', 0, 0, 0}
	binWrite(uint32(len(msg)))
	binWrite(0x00020004)
	binWrite(uint32(len(msg)))
	buf.Write(msg)
	buf.WriteByte(0) // pad to 4 (6 -> 8) before ReturnValue
	buf.WriteByte(0)
	binWrite(0) // ReturnValue = 0

	var res CertServerRequestRes
	if err := res.Unmarshal(buf.Bytes()); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.PdwRequestId != 42 {
		t.Errorf("RequestId = %d", res.PdwRequestId)
	}
	if res.PdwDisposition != DispIssued {
		t.Errorf("Disposition = %d", res.PdwDisposition)
	}
	if res.PctbCertChain.Pb != nil {
		t.Errorf("CertChain should be nil, got % x", res.PctbCertChain.Pb)
	}
	if !bytes.Equal(res.PctbEncodedCert.Pb, cert) {
		t.Errorf("EncodedCert = % x, want % x", res.PctbEncodedCert.Pb, cert)
	}
	if got := decodeUTF16(res.PctbDispositionMessage.Pb); got != "Hi" {
		t.Errorf("disposition message = %q, want Hi", got)
	}
	if res.ReturnValue != 0 {
		t.Errorf("ReturnValue = %d", res.ReturnValue)
	}
}

func TestEncodeDecodeUTF16(t *testing.T) {
	s := "CertificateTemplate:User\nSAN:upn=admin@corp.local"
	if got := decodeUTF16(encodeUTF16Attribs(s)); got != s {
		t.Errorf("round trip = %q, want %q", got, s)
	}
}

// TestCertServerRequestDMarshalLayout locks the per-parameter NDR layout of the
// DCOM ICertRequestD::Request stub. It mirrors the ICPR layout test but the
// attributes are a [unique] wide string (pwszAttributes) instead of a
// CERTTRANSBLOB.
func TestCertServerRequestDMarshalLayout(t *testing.T) {
	attrsT := "T"
	req := CertServerRequestDReq{
		DwFlags:        0,
		PwszAuthority:  "CA",
		PdwRequestId:   0,
		PwszAttributes: &attrsT,
		PctbRequest:    newBlob([]byte{0xDE, 0xAD}),
	}
	b, err := req.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := []byte{
		0x00, 0x00, 0x00, 0x00, // dwFlags
		0x00, 0x00, 0x02, 0x00, // pwszAuthority refid
		0x03, 0x00, 0x00, 0x00, // max_count = 3 (CA + NUL)
		0x00, 0x00, 0x00, 0x00, // offset
		0x03, 0x00, 0x00, 0x00, // actual_count = 3
		0x43, 0x00, 0x41, 0x00, 0x00, 0x00, // "C","A",NUL
		0x00, 0x00, // pad to 4
		0x00, 0x00, 0x00, 0x00, // pdwRequestId
		0x04, 0x00, 0x02, 0x00, // pwszAttributes refid
		0x02, 0x00, 0x00, 0x00, // max_count = 2 (T + NUL)
		0x00, 0x00, 0x00, 0x00, // offset
		0x02, 0x00, 0x00, 0x00, // actual_count = 2
		0x54, 0x00, 0x00, 0x00, // "T",NUL
		0x02, 0x00, 0x00, 0x00, // pctbRequest.Cb = 2
		0x08, 0x00, 0x02, 0x00, // pctbRequest.Pb refid
		0x02, 0x00, 0x00, 0x00, // pctbRequest.Pb max_count = 2
		0xDE, 0xAD, // 2 bytes, no trailing pad (final parameter)
	}
	if !bytes.Equal(b, want) {
		t.Errorf("DCOM marshal layout mismatch\n got: % x\nwant: % x", b, want)
	}
}
