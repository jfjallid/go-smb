// MIT License
//
// # Copyright (c) 2025 Jimmy Fjällid
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
package msdtyp

import (
	"bytes"
	"testing"
)

// resetPasswordGUID is the extended-right GUID for User-Force-Change-Password.
const resetPasswordGUID = "00299570-246d-11d0-a768-00aa006e0529"

func mustSID(t *testing.T, s string) SID {
	t.Helper()
	sid, err := ConvertStrToSID(s)
	if err != nil {
		t.Fatalf("ConvertStrToSID(%q): %v", s, err)
	}
	return *sid
}

func TestGuidStringRoundTrip(t *testing.T) {
	b, err := GuidFromString(resetPasswordGUID)
	if err != nil {
		t.Fatalf("GuidFromString: %v", err)
	}
	// Verify the documented little-endian wire layout for the first 3 groups.
	want := []byte{0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11,
		0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29}
	if !bytes.Equal(b[:], want) {
		t.Fatalf("GuidFromString wire bytes = %x, want %x", b[:], want)
	}
	if got := GuidToString(b); got != resetPasswordGUID {
		t.Fatalf("GuidToString = %q, want %q", got, resetPasswordGUID)
	}
	// Braces and uppercase should be tolerated and normalised.
	if _, err := GuidFromString("{" + resetPasswordGUID + "}"); err != nil {
		t.Fatalf("GuidFromString with braces: %v", err)
	}
	if _, err := GuidFromString("not-a-guid"); err == nil {
		t.Fatalf("GuidFromString accepted an invalid GUID")
	}
}

func aceRoundTrip(t *testing.T, in ACE) ACE {
	t.Helper()
	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("ACE.MarshalBinary: %v", err)
	}
	if int(in.Header.Size) != len(buf) {
		t.Fatalf("Header.Size %d != marshalled length %d", in.Header.Size, len(buf))
	}
	var out ACE
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatalf("ACE.UnmarshalBinary: %v", err)
	}
	return out
}

func TestBasicACERoundTrip(t *testing.T) {
	sid := mustSID(t, "S-1-5-21-1004336348-1177238915-682003330-512")
	size := 4 + 4 + 8 + 4*len(sid.SubAuthorities) // header+mask+sid
	in := ACE{
		Header: ACEHeader{Type: AccessAllowedAceType, Flags: ContainerInheritAce, Size: uint16(size)},
		Mask:   0x000F01FF,
		Sid:    sid,
	}
	out := aceRoundTrip(t, in)
	if out.Header.Type != AccessAllowedAceType || out.Mask != 0x000F01FF {
		t.Fatalf("basic ACE header/mask mismatch: %+v", out)
	}
	if out.Sid.ToString() != sid.ToString() {
		t.Fatalf("basic ACE SID = %s, want %s", out.Sid.ToString(), sid.ToString())
	}
	// A basic ACE must not consume/emit any object fields.
	if out.ObjectFlags != 0 || out.ObjectType != ([16]byte{}) {
		t.Fatalf("basic ACE leaked object fields: %+v", out)
	}
}

func TestObjectACERoundTripObjectTypeOnly(t *testing.T) {
	sid := mustSID(t, "S-1-5-21-1004336348-1177238915-682003330-1104")
	guid, _ := GuidFromString(resetPasswordGUID)
	sidLen := 8 + 4*len(sid.SubAuthorities)
	size := 4 + 4 + 4 + 16 + sidLen // header+mask+objflags+1guid+sid
	in := ACE{
		Header:      ACEHeader{Type: AccessAllowedObjectAceType, Size: uint16(size)},
		Mask:        0x00000100, // ADS_RIGHT_DS_CONTROL_ACCESS
		ObjectFlags: AceObjectTypePresent,
		ObjectType:  guid,
		Sid:         sid,
	}
	out := aceRoundTrip(t, in)
	if out.ObjectFlags != AceObjectTypePresent {
		t.Fatalf("ObjectFlags = %#x, want %#x", out.ObjectFlags, AceObjectTypePresent)
	}
	if out.ObjectType != guid {
		t.Fatalf("ObjectType = %x, want %x", out.ObjectType, guid)
	}
	if out.InheritedObjectType != ([16]byte{}) {
		t.Fatalf("InheritedObjectType should be zero, got %x", out.InheritedObjectType)
	}
	if out.Sid.ToString() != sid.ToString() {
		t.Fatalf("object ACE SID = %s, want %s", out.Sid.ToString(), sid.ToString())
	}
	p := out.Permissions()
	if p.ObjectType != resetPasswordGUID {
		t.Fatalf("Permissions().ObjectType = %q, want %q", p.ObjectType, resetPasswordGUID)
	}
}

func TestObjectACERoundTripBothGUIDs(t *testing.T) {
	sid := mustSID(t, "S-1-5-11")
	ot, _ := GuidFromString(resetPasswordGUID)
	iot, _ := GuidFromString("bf967aba-0de6-11d0-a285-00aa003049e2") // user class
	sidLen := 8 + 4*len(sid.SubAuthorities)
	size := 4 + 4 + 4 + 16 + 16 + sidLen
	in := ACE{
		Header:              ACEHeader{Type: AccessAllowedObjectAceType, Flags: ContainerInheritAce, Size: uint16(size)},
		Mask:                0x00000010,
		ObjectFlags:         AceObjectTypePresent | AceInheritedObjectTypePresent,
		ObjectType:          ot,
		InheritedObjectType: iot,
		Sid:                 sid,
	}
	out := aceRoundTrip(t, in)
	if out.ObjectType != ot || out.InheritedObjectType != iot {
		t.Fatalf("GUID mismatch: ot=%x iot=%x", out.ObjectType, out.InheritedObjectType)
	}
}

// TestSecurityDescriptorWithObjectACE exercises the full SD marshal/unmarshal
// path with a DACL containing both a basic and an object ACE.
func TestSecurityDescriptorWithObjectACE(t *testing.T) {
	owner := mustSID(t, "S-1-5-32-544")
	basicSID := mustSID(t, "S-1-5-18")
	objSID := mustSID(t, "S-1-5-21-1004336348-1177238915-682003330-1104")
	guid, _ := GuidFromString(resetPasswordGUID)

	basic := ACE{
		Header: ACEHeader{Type: AccessAllowedAceType, Size: uint16(8 + 8 + 4*len(basicSID.SubAuthorities))},
		Mask:   0x000F01FF,
		Sid:    basicSID,
	}
	obj := ACE{
		Header:      ACEHeader{Type: AccessAllowedObjectAceType, Size: uint16(4 + 4 + 4 + 16 + 8 + 4*len(objSID.SubAuthorities))},
		Mask:        0x00000100,
		ObjectFlags: AceObjectTypePresent,
		ObjectType:  guid,
		Sid:         objSID,
	}
	basicBuf, _ := basic.MarshalBinary()
	objBuf, _ := obj.MarshalBinary()
	aclSize := 8 + len(basicBuf) + len(objBuf)
	dacl := &PACL{
		AclRevision: 4, // ACL_REVISION_DS
		AclSize:     uint16(aclSize),
		ACLS:        []ACE{basic, obj},
	}
	sd := &SecurityDescriptor{
		Revision: 1,
		Control:  SecurityDescriptorFlagSR,
		OwnerSid: &owner,
		Dacl:     dacl,
	}
	buf, err := sd.MarshalBinary()
	if err != nil {
		t.Fatalf("SecurityDescriptor.MarshalBinary: %v", err)
	}
	var out SecurityDescriptor
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatalf("SecurityDescriptor.UnmarshalBinary: %v", err)
	}
	if out.OwnerSid == nil || out.OwnerSid.ToString() != owner.ToString() {
		t.Fatalf("owner mismatch: %+v", out.OwnerSid)
	}
	if out.Dacl == nil || len(out.Dacl.ACLS) != 2 {
		t.Fatalf("expected 2 DACL ACEs, got %+v", out.Dacl)
	}
	if out.Dacl.ACLS[0].Sid.ToString() != basicSID.ToString() {
		t.Fatalf("basic ACE SID mismatch: %s", out.Dacl.ACLS[0].Sid.ToString())
	}
	got := out.Dacl.ACLS[1]
	if got.Header.Type != AccessAllowedObjectAceType ||
		got.ObjectType != guid ||
		got.Sid.ToString() != objSID.ToString() {
		t.Fatalf("object ACE mismatch: %+v", got)
	}
}
