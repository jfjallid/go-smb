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

func TestORPCTHISMarshal(t *testing.T) {
	cid := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	orpcThis := &ORPCTHIS{
		Version:     COMVERSION{MajorVersion: 5, MinorVersion: 7},
		Flags:       0,
		Reserved1:   0,
		CausalityId: cid,
	}

	buf := orpcThis.MarshalBinary()

	if len(buf) != ORPCTHISSize {
		t.Fatalf("expected %d bytes, got %d", ORPCTHISSize, len(buf))
	}

	// Check version
	if le.Uint16(buf[0:2]) != 5 {
		t.Fatalf("expected major version 5, got %d", le.Uint16(buf[0:2]))
	}
	if le.Uint16(buf[2:4]) != 7 {
		t.Fatalf("expected minor version 7, got %d", le.Uint16(buf[2:4]))
	}

	// Check flags and reserved
	if le.Uint32(buf[4:8]) != 0 {
		t.Fatalf("expected flags 0, got %d", le.Uint32(buf[4:8]))
	}
	if le.Uint32(buf[8:12]) != 0 {
		t.Fatalf("expected reserved1 0, got %d", le.Uint32(buf[8:12]))
	}

	// Check causality ID
	if !bytes.Equal(buf[12:28], cid[:]) {
		t.Fatalf("causality ID mismatch\n got:  %x\n want: %x", buf[12:28], cid[:])
	}

	// Check extensions pointer is NULL
	if le.Uint32(buf[28:32]) != 0 {
		t.Fatalf("expected NULL extensions pointer, got %d", le.Uint32(buf[28:32]))
	}
}

func TestORPCTHATUnmarshalNullExtensions(t *testing.T) {
	// 4 bytes flags + 4 bytes NULL extensions pointer
	buf := make([]byte, 8)
	le.PutUint32(buf[0:4], 0x00000001) // flags
	le.PutUint32(buf[4:8], 0x00000000) // NULL extensions pointer

	result, consumed, err := UnmarshalORPCTHAT(buf)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != 8 {
		t.Fatalf("expected 8 bytes consumed, got %d", consumed)
	}
	if result.Flags != 1 {
		t.Fatalf("expected flags 1, got %d", result.Flags)
	}
	if result.Extensions != nil {
		t.Fatalf("expected nil extensions, got %v", result.Extensions)
	}
}

func TestSTDOBJREFRoundTrip(t *testing.T) {
	ipid := [16]byte{
		0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
		0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
	}
	original := STDOBJREF{
		Flags:       0x00000000,
		CPublicRefs: 5,
		OXID:        0x1234567890abcdef,
		OID:         0xfedcba0987654321,
		IPID:        ipid,
	}

	buf := original.MarshalBinary()
	if len(buf) != STDOBJREFSize {
		t.Fatalf("expected %d bytes, got %d", STDOBJREFSize, len(buf))
	}

	parsed, err := UnmarshalSTDOBJREF(buf)
	if err != nil {
		t.Fatal(err)
	}

	if parsed.Flags != original.Flags {
		t.Fatalf("Flags mismatch: %d vs %d", parsed.Flags, original.Flags)
	}
	if parsed.CPublicRefs != original.CPublicRefs {
		t.Fatalf("CPublicRefs mismatch: %d vs %d", parsed.CPublicRefs, original.CPublicRefs)
	}
	if parsed.OXID != original.OXID {
		t.Fatalf("OXID mismatch: 0x%x vs 0x%x", parsed.OXID, original.OXID)
	}
	if parsed.OID != original.OID {
		t.Fatalf("OID mismatch: 0x%x vs 0x%x", parsed.OID, original.OID)
	}
	if parsed.IPID != original.IPID {
		t.Fatalf("IPID mismatch: %x vs %x", parsed.IPID, original.IPID)
	}
}

func TestDUALSTRINGARRAYParse(t *testing.T) {
	// Build a DUALSTRINGARRAY with one TCP string binding "10.0.0.1"
	// and one security binding
	//
	// String bindings section:
	//   TowerId=7 (TCP), "10.0.0.1", null, null-terminator(0)
	// Security bindings section:
	//   AuthnSvc=10, AuthzSvc=0xffff, "", null-terminator(0)
	// Final null terminator for security section: 0

	strBindings := []uint16{
		7,                                         // TowerId for TCP
		'1', '0', '.', '0', '.', '0', '.', '1', 0, // "10.0.0.1" + null
		0, // end of string bindings
	}
	secBindings := []uint16{
		10,     // AuthnSvc
		0xffff, // AuthzSvc
		0,      // empty principal + null terminator
		0,      // end of security bindings
	}

	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	buf := make([]byte, 4+len(allEntries)*2)
	le.PutUint16(buf[0:2], uint16(len(allEntries)))
	le.PutUint16(buf[2:4], secOffset)
	for i, v := range allEntries {
		le.PutUint16(buf[4+i*2:4+i*2+2], v)
	}

	dsa, consumed, err := UnmarshalDUALSTRINGARRAY(buf)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(buf) {
		t.Fatalf("expected %d bytes consumed, got %d", len(buf), consumed)
	}

	bindings := dsa.ParseStringBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 string binding, got %d", len(bindings))
	}
	if bindings[0].TowerId != TowerIDTCP {
		t.Fatalf("expected TowerId %d, got %d", TowerIDTCP, bindings[0].TowerId)
	}
	if bindings[0].Address != "10.0.0.1" {
		t.Fatalf("expected address '10.0.0.1', got '%s'", bindings[0].Address)
	}

	securityBindings := dsa.ParseSecurityBindings()
	if len(securityBindings) != 1 {
		t.Fatalf("expected 1 security binding, got %d", len(securityBindings))
	}
	if securityBindings[0].AuthnSvc != 10 {
		t.Fatalf("expected AuthnSvc 10, got %d", securityBindings[0].AuthnSvc)
	}
}

func TestDUALSTRINGARRAYRoundTrip(t *testing.T) {
	original := DUALSTRINGARRAY{
		NumEntries:     6,
		SecurityOffset: 4,
		StringArray:    []uint16{7, 'A', 0, 0, 10, 0},
	}

	buf := original.MarshalBinary()
	parsed, consumed, err := UnmarshalDUALSTRINGARRAY(buf)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(buf) {
		t.Fatalf("expected %d bytes consumed, got %d", len(buf), consumed)
	}
	if parsed.NumEntries != original.NumEntries {
		t.Fatalf("NumEntries mismatch: %d vs %d", parsed.NumEntries, original.NumEntries)
	}
	if parsed.SecurityOffset != original.SecurityOffset {
		t.Fatalf("SecurityOffset mismatch: %d vs %d", parsed.SecurityOffset, original.SecurityOffset)
	}
	for i := range original.StringArray {
		if parsed.StringArray[i] != original.StringArray[i] {
			t.Fatalf("StringArray[%d] mismatch: %d vs %d", i, parsed.StringArray[i], original.StringArray[i])
		}
	}
}

func TestOBJREFStandardUnmarshal(t *testing.T) {
	// Build an OBJREF_STANDARD wire blob
	ipid := [16]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	iid := [16]byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}

	std := STDOBJREF{
		Flags:       0,
		CPublicRefs: 5,
		OXID:        0x1111111122222222,
		OID:         0x3333333344444444,
		IPID:        ipid,
	}

	// Minimal DUALSTRINGARRAY: 2 entries, secOffset=1, {0, 0}
	dsa := DUALSTRINGARRAY{
		NumEntries:     2,
		SecurityOffset: 1,
		StringArray:    []uint16{0, 0},
	}

	buf := make([]byte, 0, 200)
	// Signature
	buf = binary.LittleEndian.AppendUint32(buf, OBJREFSignature)
	// Flags
	buf = binary.LittleEndian.AppendUint32(buf, OBJREFStandard)
	// IID
	buf = append(buf, iid[:]...)
	// STDOBJREF
	buf = append(buf, std.MarshalBinary()...)
	// DUALSTRINGARRAY
	buf = append(buf, dsa.MarshalBinary()...)

	obj, consumed, err := UnmarshalOBJREF(buf)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(buf) {
		t.Fatalf("expected %d bytes consumed, got %d", len(buf), consumed)
	}
	if obj.Signature != OBJREFSignature {
		t.Fatalf("bad signature: 0x%08x", obj.Signature)
	}
	if obj.Flags != OBJREFStandard {
		t.Fatalf("bad flags: 0x%08x", obj.Flags)
	}
	if obj.IID != iid {
		t.Fatalf("IID mismatch")
	}
	if obj.Std == nil {
		t.Fatal("expected non-nil Std")
	}
	if obj.Std.IPID != ipid {
		t.Fatalf("IPID mismatch")
	}
	if obj.Std.OXID != 0x1111111122222222 {
		t.Fatalf("OXID mismatch: 0x%x", obj.Std.OXID)
	}
	if obj.StdDSA == nil {
		t.Fatal("expected non-nil StdDSA")
	}
}

func TestMInterfacePointerRoundTrip(t *testing.T) {
	data := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04}

	buf := MarshalMInterfacePointer(data)
	if len(buf) != 8+len(data) {
		t.Fatalf("expected %d bytes, got %d", 8+len(data), len(buf))
	}

	parsed, consumed, err := UnmarshalMInterfacePointer(buf)
	if err != nil {
		t.Fatal(err)
	}
	if consumed != len(buf) {
		t.Fatalf("expected %d bytes consumed, got %d", len(buf), consumed)
	}
	if !bytes.Equal(parsed.Data, data) {
		t.Fatalf("data mismatch\n got:  %x\n want: %x", parsed.Data, data)
	}
}

func TestGUIDFromString(t *testing.T) {
	guid, err := GUIDFromString("000001a0-0000-0000-c000-000000000046")
	if err != nil {
		t.Fatal(err)
	}
	// Data1 = 0x000001a0, little-endian: a0 01 00 00
	expected := []byte{
		0xa0, 0x01, 0x00, 0x00,
		0x00, 0x00,
		0x00, 0x00,
		0xc0, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}
	if !bytes.Equal(guid[:], expected) {
		t.Fatalf("GUID mismatch\n got:  %x\n want: %x", guid[:], expected)
	}
}

func TestCOMVERSIONRoundTrip(t *testing.T) {
	v := COMVERSION{MajorVersion: 5, MinorVersion: 7}
	buf := v.MarshalBinary()
	if len(buf) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(buf))
	}

	parsed, err := UnmarshalCOMVERSION(buf)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.MajorVersion != 5 || parsed.MinorVersion != 7 {
		t.Fatalf("version mismatch: %d.%d", parsed.MajorVersion, parsed.MinorVersion)
	}
}

func TestREMINTERFACEREFMarshal(t *testing.T) {
	ipid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	ref := REMINTERFACEREF{
		IPID:         ipid,
		CPublicRefs:  5,
		CPrivateRefs: 0,
	}
	buf := ref.MarshalBinary()
	if len(buf) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(buf))
	}
	if !bytes.Equal(buf[0:16], ipid[:]) {
		t.Fatalf("IPID mismatch")
	}
	if le.Uint32(buf[16:20]) != 5 {
		t.Fatalf("CPublicRefs mismatch")
	}
	if le.Uint32(buf[20:24]) != 0 {
		t.Fatalf("CPrivateRefs mismatch")
	}
}
