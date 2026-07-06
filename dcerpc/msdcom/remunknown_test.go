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
package msdcom

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestMarshalRemQueryInterfaceRequest(t *testing.T) {
	cid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	ripid := [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0}
	iid := IID_IUnknown

	buf := marshalRemQueryInterfaceRequest(cid, ripid, [][16]byte{iid})

	// ORPCTHIS (32) + IPID (16) + cRefs (4) + cIids (2) + pad (2) + maxCount (4) + IID (16) = 76
	if len(buf) != 76 {
		t.Fatalf("expected 76 bytes, got %d", len(buf))
	}

	// Check ORPCTHIS version
	if le.Uint16(buf[0:2]) != 5 || le.Uint16(buf[2:4]) != 7 {
		t.Fatalf("ORPCTHIS version mismatch")
	}

	// Check causality ID
	if !bytes.Equal(buf[12:28], cid[:]) {
		t.Fatal("causality ID mismatch")
	}

	// Check IPID ripid at offset 32
	if !bytes.Equal(buf[32:48], ripid[:]) {
		t.Fatal("ripid mismatch")
	}

	// Check cRefs at offset 48
	if le.Uint32(buf[48:52]) != 5 {
		t.Fatalf("expected cRefs 5, got %d", le.Uint32(buf[48:52]))
	}

	// Check cIids at offset 52
	if le.Uint16(buf[52:54]) != 1 {
		t.Fatalf("expected cIids 1, got %d", le.Uint16(buf[52:54]))
	}

	// Check maxCount at offset 56
	if le.Uint32(buf[56:60]) != 1 {
		t.Fatalf("expected maxCount 1, got %d", le.Uint32(buf[56:60]))
	}

	// Check IID at offset 60
	if !bytes.Equal(buf[60:76], iid[:]) {
		t.Fatal("IID mismatch")
	}
}

func TestMarshalRemQueryInterfaceRequestMultipleIIDs(t *testing.T) {
	cid := [16]byte{}
	ripid := [16]byte{}
	iid1 := IID_IUnknown
	iid2 := mustGUID("00020400-0000-0000-c000-000000000046") // IDispatch

	buf := marshalRemQueryInterfaceRequest(cid, ripid, [][16]byte{iid1, iid2})

	// 32 + 16 + 4 + 2 + 2 + 4 + 2*16 = 92
	if len(buf) != 92 {
		t.Fatalf("expected 92 bytes, got %d", len(buf))
	}

	// Check cIids = 2
	if le.Uint16(buf[52:54]) != 2 {
		t.Fatalf("expected cIids 2, got %d", le.Uint16(buf[52:54]))
	}

	// Check maxCount = 2
	if le.Uint32(buf[56:60]) != 2 {
		t.Fatalf("expected maxCount 2, got %d", le.Uint32(buf[56:60]))
	}

	// Check IID[0]
	if !bytes.Equal(buf[60:76], iid1[:]) {
		t.Fatal("IID[0] mismatch")
	}

	// Check IID[1]
	if !bytes.Equal(buf[76:92], iid2[:]) {
		t.Fatal("IID[1] mismatch")
	}
}

func TestUnmarshalRemQueryInterfaceResponse(t *testing.T) {
	ipid := [16]byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0}

	// Build a synthetic response
	resp := make([]byte, 0, 100)

	// ORPCTHAT (null extensions)
	resp = binary.LittleEndian.AppendUint32(resp, 0) // flags
	resp = binary.LittleEndian.AppendUint32(resp, 0) // extensions = NULL

	// ppQIResults referent ID
	resp = binary.LittleEndian.AppendUint32(resp, 0x00020000)

	// Conformant array of REMQIRESULT: maxCount + elements
	resp = binary.LittleEndian.AppendUint32(resp, 1) // maxCount

	// REMQIRESULT[0]: hResult(4) + STDOBJREF(40)
	resp = binary.LittleEndian.AppendUint32(resp, 0) // hResult = S_OK
	std := STDOBJREF{
		Flags:       0,
		CPublicRefs: 5,
		OXID:        0x1111222233334444,
		OID:         0x5555666677778888,
		IPID:        ipid,
	}
	resp = append(resp, std.MarshalBinary()...)

	// HRESULT at end
	resp = binary.LittleEndian.AppendUint32(resp, 0) // S_OK

	results, err := unmarshalRemQueryInterfaceResponse(resp, 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}

	if results[0].HResult != 0 {
		t.Fatalf("expected HResult 0, got 0x%08x", results[0].HResult)
	}

	if results[0].Std.IPID != ipid {
		t.Fatal("IPID mismatch")
	}

	if results[0].Std.OXID != 0x1111222233334444 {
		t.Fatalf("OXID mismatch: 0x%x", results[0].Std.OXID)
	}

	if results[0].Std.CPublicRefs != 5 {
		t.Fatalf("CPublicRefs mismatch: %d", results[0].Std.CPublicRefs)
	}
}

func TestUnmarshalRemQueryInterfaceResponseError(t *testing.T) {
	resp := make([]byte, 0, 20)

	// ORPCTHAT
	resp = binary.LittleEndian.AppendUint32(resp, 0)
	resp = binary.LittleEndian.AppendUint32(resp, 0)

	// ppQIResults = NULL
	resp = binary.LittleEndian.AppendUint32(resp, 0)

	// HRESULT = error
	resp = binary.LittleEndian.AppendUint32(resp, 0x80000001)

	_, err := unmarshalRemQueryInterfaceResponse(resp, 0)
	if err == nil {
		t.Fatal("expected error for non-zero HRESULT")
	}
}

func TestMarshalRemReleaseRequest(t *testing.T) {
	cid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	ipid := [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0}

	refs := []REMINTERFACEREF{
		{
			IPID:         ipid,
			CPublicRefs:  5,
			CPrivateRefs: 0,
		},
	}

	buf := marshalRemReleaseRequest(cid, refs)

	// ORPCTHIS (32) + cInterfaceRefs (2) + pad (2) + maxCount (4) + REMINTERFACEREF (24) = 64
	if len(buf) != 64 {
		t.Fatalf("expected 64 bytes, got %d", len(buf))
	}

	// Check cInterfaceRefs at offset 32
	if le.Uint16(buf[32:34]) != 1 {
		t.Fatalf("expected cInterfaceRefs 1, got %d", le.Uint16(buf[32:34]))
	}

	// Check maxCount at offset 36
	if le.Uint32(buf[36:40]) != 1 {
		t.Fatalf("expected maxCount 1, got %d", le.Uint32(buf[36:40]))
	}

	// Check IPID at offset 40
	if !bytes.Equal(buf[40:56], ipid[:]) {
		t.Fatal("IPID mismatch")
	}

	// Check CPublicRefs at offset 56
	if le.Uint32(buf[56:60]) != 5 {
		t.Fatalf("expected CPublicRefs 5, got %d", le.Uint32(buf[56:60]))
	}

	// Check CPrivateRefs at offset 60
	if le.Uint32(buf[60:64]) != 0 {
		t.Fatalf("expected CPrivateRefs 0, got %d", le.Uint32(buf[60:64]))
	}
}

func TestUnmarshalRemReleaseResponse(t *testing.T) {
	// Success response
	resp := make([]byte, 0, 12)
	resp = binary.LittleEndian.AppendUint32(resp, 0) // ORPCTHAT flags
	resp = binary.LittleEndian.AppendUint32(resp, 0) // ORPCTHAT extensions = NULL
	resp = binary.LittleEndian.AppendUint32(resp, 0) // HRESULT = S_OK

	err := unmarshalRemReleaseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnmarshalRemReleaseResponseError(t *testing.T) {
	resp := make([]byte, 0, 12)
	resp = binary.LittleEndian.AppendUint32(resp, 0)
	resp = binary.LittleEndian.AppendUint32(resp, 0)
	resp = binary.LittleEndian.AppendUint32(resp, 0x80070005) // E_ACCESSDENIED

	err := unmarshalRemReleaseResponse(resp)
	if err == nil {
		t.Fatal("expected error for non-zero HRESULT")
	}
}
