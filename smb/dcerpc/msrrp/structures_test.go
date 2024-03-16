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
package msrrp

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestSID(t *testing.T) {
	correctSidBytes, err := hex.DecodeString("01020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}

	sid := SID{
		Revision:       0x1,
		NumAuth:        2,
		Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
		SubAuthorities: []uint32{32, 544},
	}

	sidBytes, err := sid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(sidBytes, correctSidBytes) != 0 {
		t.Fatal("Marshalled bytes of sid structure does not match correct serialization")
	}

	sid2 := SID{}

	err = sid2.UnmarshalBinary(correctSidBytes)
	if err != nil {
		t.Fatal(err)
	}

	if sid2.Revision != 0x1 {
		t.Fail()
	}
	if sid2.NumAuth != 2 {
		t.Fail()
	}
	if bytes.Compare(sid2.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) != 0 {
		t.Fail()
	}
	if sid2.SubAuthorities[0] != 32 {
		t.Fail()
	}
	if sid2.SubAuthorities[1] != 544 {
		t.Fail()
	}
}

func TestACE(t *testing.T) {
	correctAceBytes, err := hex.DecodeString("000218000900060001020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}
	sid := SID{
		Revision:       0x1,
		NumAuth:        2,
		Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
		SubAuthorities: []uint32{32, 544},
	}
	ace := ACE{
		Header: ACEHeader{
			Type:  0,
			Flags: 0x2,
			Size:  24,
		},
		Mask: 0x00060009,
		Sid:  sid,
	}
	aceBytes, err := ace.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(aceBytes, correctAceBytes) != 0 {
		t.Fail()
	}

	ace2 := ACE{}

	err = ace2.UnmarshalBinary(correctAceBytes)
	if err != nil {
		t.Fatal(err)
	}

	if ace2.Header.Type != 0 {
		t.Fail()
	}
	if ace2.Header.Flags != 0x2 {
		t.Fail()
	}
	if ace2.Header.Size != 24 {
		t.Fail()
	}
	if ace2.Mask != 0x00060009 {
		t.Fail()
	}

	if ace2.Sid.Revision != 0x1 {
		t.Fail()
	}
	if ace2.Sid.NumAuth != 2 {
		t.Fail()
	}
	if bytes.Compare(ace2.Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) != 0 {
		t.Fail()
	}
	if ace2.Sid.SubAuthorities[0] != 32 {
		t.Fail()
	}
	if ace2.Sid.SubAuthorities[1] != 544 {
		t.Fail()
	}

	otherAceCorrectBytes, err := hex.DecodeString("001218000000060001020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}

	otherAce := ACE{
		Header: ACEHeader{
			Type:  0,
			Flags: 0x12,
			Size:  24,
		},
		Mask: 0x00060000,
		Sid: SID{
			Revision:       0x1,
			NumAuth:        2,
			Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
			SubAuthorities: []uint32{32, 544},
		},
	}

	otherAceBytes, err := otherAce.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(otherAceBytes, otherAceCorrectBytes) != 0 {
		t.Fail()
	}

	ace3 := ACE{}
	err = ace3.UnmarshalBinary(otherAceCorrectBytes)
	if err != nil {
		t.Fatal(err)
	}

	if ace3.Header.Type != 0 {
		t.Fail()
	}
	if ace3.Header.Flags != 0x12 {
		t.Fail()
	}
	if ace3.Header.Size != 24 {
		t.Fail()
	}
	if ace3.Mask != 0x00060000 {
		t.Fail()
	}

	if ace3.Sid.Revision != 0x1 {
		t.Fail()
	}
	if ace3.Sid.NumAuth != 2 {
		t.Fail()
	}
	if bytes.Compare(ace3.Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) != 0 {
		t.Fail()
	}
	if ace3.Sid.SubAuthorities[0] != 32 {
		t.Fail()
	}
	if ace3.Sid.SubAuthorities[1] != 544 {
		t.Fail()
	}

	otherAceCorrectBytes2, err := hex.DecodeString("001214003f000f00010100000000000512000000")
	if err != nil {
		t.Fatal(err)
	}

	otherAce2 := ACE{
		Header: ACEHeader{
			Type:  0,
			Flags: 0x12,
			Size:  20,
		},
		Mask: 0x000f003f,
		Sid: SID{
			Revision:       0x1,
			NumAuth:        1,
			Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
			SubAuthorities: []uint32{18},
		},
	}

	otherAceBytes2, err := otherAce2.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(otherAceBytes2, otherAceCorrectBytes2) != 0 {
		t.Fail()
	}

	ace3 = ACE{}
	err = ace3.UnmarshalBinary(otherAceCorrectBytes2)
	if err != nil {
		t.Fatal(err)
	}

	if ace3.Header.Type != 0 {
		t.Fail()
	}
	if ace3.Header.Flags != 0x12 {
		t.Fail()
	}
	if ace3.Header.Size != 20 {
		t.Fail()
	}
	if ace3.Mask != 0x000f003f {
		t.Fail()
	}

	if ace3.Sid.Revision != 0x1 {
		t.Fail()
	}
	if ace3.Sid.NumAuth != 1 {
		t.Fail()
	}
	if bytes.Compare(ace3.Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) != 0 {
		t.Fail()
	}
	if ace3.Sid.SubAuthorities[0] != 18 {
		t.Fail()
	}
}

func TestPACL(t *testing.T) {
	correctPaclBytes, err := hex.DecodeString("0200c40008000000000218000900060001020000000000052000000020020000000218000900060001020000000000052000000020020000000218000900060001020000000000052000000020020000000218000900060001020000000000052000000020020000000218000900060001020000000000052000000020020000000218000900060001020000000000052000000020020000001218000000060001020000000000052000000020020000001214003f000f00010100000000000512000000")
	if err != nil {
		t.Fatal(err)
	}
	standardAce := ACE{
		Header: ACEHeader{
			Type:  0,
			Flags: 0x2,
			Size:  24,
		},
		Mask: 0x00060009,
		Sid: SID{
			Revision:       0x1,
			NumAuth:        2,
			Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
			SubAuthorities: []uint32{32, 544},
		},
	}

	pacl := PACL{
		AclRevision: 2,
		AclSize:     196,
		AceCount:    8,
		ACLS: []ACE{
			standardAce,
			standardAce,
			standardAce,
			standardAce,
			standardAce,
			standardAce,
			ACE{
				Header: ACEHeader{
					Type:  0,
					Flags: 0x12,
					Size:  24,
				},
				Mask: 0x00060000,
				Sid:  standardAce.Sid,
			},
			ACE{
				Header: ACEHeader{
					Type:  0,
					Flags: 0x12,
					Size:  20,
				},
				Mask: 0x000f003f,
				Sid: SID{
					Revision:       1,
					NumAuth:        1,
					Authority:      []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5},
					SubAuthorities: []uint32{18},
				},
			},
		},
	}

	paclBytes, err := pacl.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(paclBytes, correctPaclBytes) != 0 {
		t.Fatal("Marshalled bytes did not match correct serialization")
	}

	pacl2 := PACL{}
	err = pacl2.UnmarshalBinary(correctPaclBytes)
	if err != nil {
		t.Fatal(err)
	}

	if pacl2.AclRevision != 2 {
		t.Fail()
	}
	if pacl2.AclSize != 196 {
		t.Fail()
	}
	if pacl2.AceCount != 8 {
		t.Fail()
	}
}
