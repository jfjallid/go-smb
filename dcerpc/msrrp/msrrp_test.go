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
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
)

// Possible to define an init function that is run before all tests?

func TestEnumKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000d2f002b5b16cf04baf78ccd08d590a03010000000000000401000000000200000000000000000000020000000000000403000000000200000000000000000000040000000100000002000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("00000000d2f002b5b16cf04baf78ccd08d590a03")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegEnumKeyReq{
		HKey:  hKey,
		Index: 1,
		NameIn: RRPUnicodeStr{
			MaxLength: 512,
		},
		ClassIn: RRPUnicodeStr{
			MaxLength: 512,
		},
		LastWriteTime: &msdtyp.PFiletime{LowDateTime: 1, HighDateTime: 2},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		fmt.Printf("%x\n", pkt)
		fmt.Printf("%x\n", buf)
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestEnumKeyRes(t *testing.T) {
	resPkt, err := hex.DecodeString("12000004000002000002000000000000090000003000300030003000300031004600340000000000040002000200000408000200000200000000000001000000000000000c000200197aca0a703cd90100000000")
	if err != nil {
		t.Fatal(err)
	}
	var res BaseRegEnumKeyRes
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.NameOut.S != "000001F4" {
		t.Fatal("fail")
	}
	if res.LastWriteTime.LowDateTime != binary.LittleEndian.Uint32([]byte{0x19, 0x7a, 0xca, 0x0a}) {
		t.Errorf("expected res.LastWriteTime.LowDateTime==binary.LittleEndian.Uint32([]byte{0x19, 0x7a, 0xca, 0x0a}), got %v", res.LastWriteTime.LowDateTime)
	}
	if res.LastWriteTime.HighDateTime != binary.LittleEndian.Uint32([]byte{0x70, 0x3c, 0xd9, 0x01}) {
		t.Errorf("expected res.LastWriteTime.HighDateTime==binary.LittleEndian.Uint32([]byte{0x70, 0x3c, 0xd9, 0x01}), got %v", res.LastWriteTime.HighDateTime)
	}
	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestEnumValueReq(t *testing.T) {
	//TODO, once working, generate a new example instead of this one which was manually edited to change the RefId ptrs (hopefully)
	pkt, err := hex.DecodeString("0000000048f6df66ec21ad4aba9f16a6038d393f00000000000000040100000000020000000000000000000002000000000400000300000000040000000000000000000004000000000400000500000000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("0000000048f6df66ec21ad4aba9f16a6038d393f")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegEnumValueReq{
		HKey:  hKey,
		Index: 0,
		NameIn: RRPUnicodeStr{
			//MaxLength:  1024,
			MaxLength: 512,
		},
		Type:    1024,
		MaxLen:  1024,
		DataLen: 0,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestEnumValueRes(t *testing.T) {
	pkt, err := hex.DecodeString("0a000004000002000002000000000000050000004e004c002400310000000000040002000300000008000200a800000000000000a80000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000200a800000010000200a800000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var res BaseRegEnumValueRes

	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if res.NameOut.S != "NL$1\x00" {
		t.Fatal("fail")
	}
	if res.Type != 3 {
		t.Errorf("expected res.Type==3, got %v", res.Type)
	}
	nl1 := make([]byte, 168)
	nl1[40] = 4
	nl1[42] = 1
	if !bytes.Equal(res.Data, nl1) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", nl1, res.Data)
	}
	if res.DataLen != 168 {
		t.Errorf("expected res.DataLen==168, got %v", res.DataLen)
	}
	if res.MaxLen != 168 {
		t.Errorf("expected res.MaxLen==168, got %v", res.MaxLen)
	}
	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestSetKeySecurityReq(t *testing.T) {
	pkt, err := hex.DecodeString("000000008c77795a6df29c48bd0d2948540acbab0400000001000000480000004800000048000000000000004800000001000480000000000000000000000000140000000200340002000000001214003f000f00010100000000000512000000001218000000060001020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("000000008c77795a6df29c48bd0d2948540acbab")
	if err != nil {
		t.Fatal(err)
	}
	systemSIDStr := "S-1-5-18"
	adminSIDStr := "S-1-5-32-544"
	systemMask := PermWriteOwner |
		PermWriteDacl |
		PermReadControl |
		PermDelete |
		PermKeyCreateLink |
		PermKeyNotify |
		PermKeyEnumerateSubKeys |
		PermKeyCreateSubKey |
		PermKeySetValue |
		PermKeyQueryValue

	sAce, err := NewAce(systemSIDStr, systemMask, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce|msdtyp.InheritedAce)
	if err != nil {
		t.Fatal(err)
	}

	adminMask := PermWriteDacl | PermReadControl
	aAce, err := NewAce(adminSIDStr, adminMask, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce|msdtyp.InheritedAce)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := NewSecurityDescriptor(msdtyp.SecurityDescriptorFlagSR, nil, nil, NewACL([]msdtyp.ACE{*sAce, *aAce}), nil)

	req := BaseRegSetKeySecurityReq{
		HKey:                hKey,
		SecurityInformation: DACLSecurityInformation,
		SecurityDescriptorIn: RpcSecurityDescriptor{
			SecurityDescriptor: sd,
		},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestSetKeySecurityRes(t *testing.T) {
	pkt, err := hex.DecodeString("00000000")
	if err != nil {
		t.Fatal(err)
	}

	var res msdtyp.ReturnCode

	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.Value() != 0 {
		t.Errorf("expected res.Value()==0, got %v", res.Value())
	}
}

func TestGetKeySecurityReq(t *testing.T) {
	pkt, err := hex.DecodeString("00000000fafe60b8553cac44952b32d33453d14007000000000000000010000000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("00000000fafe60b8553cac44952b32d33453d140")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegGetKeySecurityReq{
		HKey:                hKey,
		SecurityInformation: OwnerSecurityInformation | GroupSecurityInformation | DACLSecurityInformation,
		SecurityDescriptorIn: RpcSecurityDescriptor{
			InSecurityDescriptor: 4096,
		},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestGetKeySecurityRes(t *testing.T) {
	pkt, err := hex.DecodeString("00000200001000006400000000100000000000006400000001000480480000005800000000000000140000000200340002000000001214003f000f000101000000000005120000000012180000000600010200000000000520000000200200000102000000000005200000002002000001010000000000051200000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var res BaseRegGetKeySecurityRes

	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.SecurityDescriptorOut.OutSecurityDescriptor != 100 {
		t.Error("fail")
	}
	if res.SecurityDescriptorOut.InSecurityDescriptor != 4096 {
		t.Error("fail")
	}

	sd := *res.SecurityDescriptorOut.SecurityDescriptor

	if sd.Control != msdtyp.SecurityDescriptorFlagSR|msdtyp.SecurityDescriptorFlagDP {
		t.Errorf("expected sd.Control==msdtyp.SecurityDescriptorFlagSR|msdtyp.SecurityDescriptorFlagDP, got %v", sd.Control)
	}
	if !bytes.Equal(sd.OwnerSid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}
	if sd.OwnerSid.SubAuthorities[0] != 32 {
		t.Errorf("expected sd.OwnerSid.SubAuthorities[0]==32, got %v", sd.OwnerSid.SubAuthorities[0])
	}
	if sd.OwnerSid.SubAuthorities[1] != 544 {
		t.Errorf("expected sd.OwnerSid.SubAuthorities[1]==544, got %v", sd.OwnerSid.SubAuthorities[1])
	}

	if !bytes.Equal(sd.GroupSid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}
	if sd.GroupSid.SubAuthorities[0] != 18 {
		t.Errorf("expected sd.GroupSid.SubAuthorities[0]==18, got %v", sd.GroupSid.SubAuthorities[0])
	}

	if sd.Dacl.AclSize != 52 {
		t.Errorf("expected sd.Dacl.AclSize==52, got %v", sd.Dacl.AclSize)
	}

	if sd.Dacl.AceCount != 2 {
		t.Errorf("expected sd.Dacl.AceCount==2, got %v", sd.Dacl.AceCount)
	}
	acls := sd.Dacl.ACLS

	if acls[0].Mask != binary.LittleEndian.Uint32([]byte{0x3f, 0x00, 0x0f, 0x00}) {
		t.Errorf("expected acls[0].Mask==binary.LittleEndian.Uint32([]byte{0x3f, 0x00, 0x0f, 0x00}), got %v", acls[0].Mask)
	}
	if acls[0].Header.Flags != 0x12 {
		t.Errorf("expected acls[0].Header.Flags==0x12, got %v", acls[0].Header.Flags)
	}
	if !bytes.Equal(acls[0].Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}

	if acls[0].Sid.SubAuthorities[0] != 18 {
		t.Errorf("expected acls[0].Sid.SubAuthorities[0]==18, got %v", acls[0].Sid.SubAuthorities[0])
	}

	if acls[1].Mask != PermWriteDacl|PermReadControl {
		t.Errorf("expected acls[1].Mask==PermWriteDacl|PermReadControl, got %v", acls[1].Mask)
	}
	if acls[1].Header.Flags != 0x12 {
		t.Errorf("expected acls[1].Header.Flags==0x12, got %v", acls[1].Header.Flags)
	}
	if !bytes.Equal(acls[1].Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}

	if acls[1].Sid.SubAuthorities[0] != 32 {
		t.Errorf("expected acls[1].Sid.SubAuthorities[0]==32, got %v", acls[1].Sid.SubAuthorities[0])
	}

	if acls[1].Sid.SubAuthorities[1] != 544 {
		t.Errorf("expected acls[1].Sid.SubAuthorities[1]==544, got %v", acls[1].Sid.SubAuthorities[1])
	}

	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestOpenKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000007660be608d829f419adebc8ce25585701000100001000000080000000000000008000000530041004d005c00530041004d0000000000000000000002")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("000000007660be608d829f419adebc8ce2558570")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegOpenKeyReq{
		HKey: hKey,
		SubKey: RRPUnicodeStr{
			MaxLength: 8,
			S:         "SAM\\SAM",
		},
		Options:       0,
		DesiredAccess: 0x02000000,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestOpenKeyRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("000000003faff080d6ef374da4be978119becfdc00000000")
	if err != nil {
		t.Fatal(err)
	}
	handle, err := hex.DecodeString("000000003faff080d6ef374da4be978119becfdc")
	if err != nil {
		t.Fatal(err)
	}

	var res OpenKeyRes
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.HKey, handle) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", handle, res.HKey)
	}

	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestQueryInfoKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000007754caee7222f944bb09a95f160dc8520000240000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("000000007754caee7222f944bb09a95f160dc852")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegQueryInfoKeyReq{
		HKey: hKey,
		ClassIn: RRPUnicodeStr{
			MaxLength: 18,
		},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestQueryInfoKeyRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("12001200000002000900000000000000090000003000310034003800330032003200630000000000000000000000000000000000010000000c00000006000000f00000007d5ca5a29bcdd80100000000")
	if err != nil {
		t.Fatal(err)
	}

	var res BaseRegQueryInfoKeyRes
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ClassOut.S != "0148322c\x00" {
		t.Errorf("expected res.ClassOut.S==0148322c\x00, got %v", res.ClassOut.S)
	}

	if res.SubKeys != 0 {
		t.Errorf("expected res.SubKeys==0, got %v", res.SubKeys)
	}
	if res.MaxSubKeyLen != 0 {
		t.Errorf("expected res.MaxSubKeyLen==0, got %v", res.MaxSubKeyLen)
	}
	if res.MaxClassLen != 0 {
		t.Errorf("expected res.MaxClassLen==0, got %v", res.MaxClassLen)
	}
	if res.Values != 1 {
		t.Errorf("expected res.Values==1, got %v", res.Values)
	}
	if res.MaxValueNameLen != 12 {
		t.Errorf("expected res.MaxValueNameLen==12, got %v", res.MaxValueNameLen)
	}
	if res.MaxValueLen != 6 {
		t.Errorf("expected res.MaxValueLen==6, got %v", res.MaxValueLen)
	}
	if res.SecurityDescriptor != 240 {
		t.Errorf("expected res.SecurityDescriptor==240, got %v", res.SecurityDescriptor)
	}
	if res.LastWriteTime.LowDateTime != binary.LittleEndian.Uint32([]byte{0x7d, 0x5c, 0xa5, 0xa2}) {
		t.Errorf("expected res.LastWriteTime.LowDateTime==binary.LittleEndian.Uint32([]byte{0x7d, 0x5c, 0xa5, 0xa2}), got %v", res.LastWriteTime.LowDateTime)
	}
	if res.LastWriteTime.HighDateTime != binary.LittleEndian.Uint32([]byte{0x9b, 0xcd, 0xd8, 0x01}) {
		t.Errorf("expected res.LastWriteTime.HighDateTime==binary.LittleEndian.Uint32([]byte{0x9b, 0xcd, 0xd8, 0x01}), got %v", res.LastWriteTime.HighDateTime)
	}
	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestQueryValueReq(t *testing.T) {
	pkt, err := hex.DecodeString("0000000091678d52af1f934fb0445307e96a52d11a001a00010000000d000000000000000d000000430075007200720065006e0074004200750069006c0064000000000002000000000400000300000000040000000000000000000004000000000400000500000000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("0000000091678d52af1f934fb0445307e96a52d1")
	if err != nil {
		t.Fatal(err)
	}
	name := "CurrentBuild\x00"

	req := BaseRegQueryValueReq{
		HKey: hKey,
		ValueName: RRPUnicodeStr{
			MaxLength: uint16(len(name)),
			S:         name,
		},
		Type:    1024,
		Data:    nil,
		MaxLen:  1024,
		DataLen: 0,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestQueryValueRes(t *testing.T) {
	pkt, err := hex.DecodeString("0000020001000000040002002000000000000000200000002e005c00410064006d0069006e006900730074007200610074006f007200000008000200200000000c0002002000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var res BaseRegQueryValueRes

	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.Type != 1 {
		t.Errorf("expected res.Type==1, got %v", res.Type)
	}

	name, err := msdtyp.FromUnicode(res.Data)
	if !bytes.Equal(name, []byte(".\\Administrator\x00")) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", name, []byte(".\\Administrator\x00"))
	}

	if res.DataLen != 32 {
		t.Errorf("expected res.DataLen==32, got %v", res.DataLen)
	}
	if res.MaxLen != 32 {
		t.Errorf("expected res.MaxLen==32, got %v", res.MaxLen)
	}
	if res.ReturnCode != 0 {
		t.Errorf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestSaveKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000139a8326558bcd48bbcc6af498ba9b2138003800010000001c000000000000001c00000043003a005c00770069006e0064006f00770073005c00740065006d0070005c007300550046006d007800790056002e006c006f00670000000200000058000000040000004400000044000000000000004400000000000000440000000100048034000000000000000000000014000000020020000100000000021800000005c00102000000000005200000002002000001020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("00000000139a8326558bcd48bbcc6af498ba9b21")
	if err != nil {
		t.Fatal(err)
	}

	name := "C:\\windows\\temp\\sUFmxyV.log"
	adminSIDStr := "S-1-5-32-544"
	adminMask := PermGenericRead | PermGenericWrite | PermWriteDacl | PermDelete
	aAce, err := NewAce(adminSIDStr, adminMask, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce)
	if err != nil {
		t.Fatal(err)
	}
	ownerSid, err := msdtyp.ConvertStrToSID(adminSIDStr)
	if err != nil {
		t.Fatal(err)
	}
	acl := NewACL([]msdtyp.ACE{*aAce})

	sd, err := NewSecurityDescriptor(msdtyp.SecurityDescriptorFlagSR, ownerSid, nil, acl, nil)
	if err != nil {
		t.Fatal(err)
	}
	sdbuf, err := sd.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	sdbufLen := uint32(len(sdbuf))
	rd := RpcSecurityDescriptor{
		SecurityDescriptor:    sd,
		InSecurityDescriptor:  sdbufLen,
		OutSecurityDescriptor: sdbufLen,
	}

	sa := &RpcSecurityAttributes{
		SecurityDescriptor: rd,
		Length:             sdbufLen + 12 + 8, // Includes the size of the length parameters
		InheritHandle:      0,
	}

	req := BaseRegSaveKeyReq{
		HKey: hKey,
		FileName: RRPUnicodeStr{
			MaxLength: 11,
			S:         name,
		},
		SecurityAttributes: *sa,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Errorf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestSaveKeyRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("00000000")
	if err != nil {
		t.Fatal(err)
	}

	var res msdtyp.ReturnCode
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.Value() != 0 {
		t.Errorf("expected res.Value()==0, got %v", res.Value())
	}
}
