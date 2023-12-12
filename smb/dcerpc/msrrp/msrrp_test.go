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

	"github.com/jfjallid/go-smb/smb/encoder"

	"testing"
)

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
		NameIn: PRRPUnicodeStr2{
			Length:    0,
			MaxLength: 512,
		},
		ClassIn: PRRPUnicodeStr2{
			Length:    0,
			MaxLength: 512,
		},
		LastWriteTime: &PFiletime{1, 2},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	name, err := encoder.FromUnicode(encoder.Utf16ToUtf8(res.NameOut.Buffer))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(name, []byte("000001F4\x00")) {
		t.Error("Fail")
	}
	if res.LastWriteTime.LowDateTime != binary.LittleEndian.Uint32([]byte{0x19, 0x7a, 0xca, 0x0a}) {
		t.Error("Fail")
	}
	if res.LastWriteTime.HighDateTime != binary.LittleEndian.Uint32([]byte{0x70, 0x3c, 0xd9, 0x01}) {
		t.Error("Fail")
	}
	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}

func TestEnumValueReq(t *testing.T) {
	pkt, err := hex.DecodeString("0000000048f6df66ec21ad4aba9f16a6038d393f00000000000000040100000000020000000000000000000002000000000400000100000000040000000000000000000004000000000400000300000000000000")
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
		NameIn: PRRPUnicodeStr2{
			Length: 0,
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
		t.Error("Fail")
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
	name, err := encoder.FromUnicode(encoder.Utf16ToUtf8(res.NameOut.Buffer))
	if !bytes.Equal(name, []byte("NL$1\x00")) {
		t.Error("Fail")
	}
	if res.Type != 3 {
		t.Error("Fail")
	}
	nl1 := make([]byte, 168)
	nl1[40] = 4
	nl1[42] = 1
	if !bytes.Equal(res.Data, nl1) {
		t.Error("Fail")
	}
	if res.DataLen != 168 {
		t.Error("Fail")
	}
	if res.MaxLen != 168 {
		t.Error("Fail")
	}
	if res.ReturnCode != 0 {
		t.Error("Fail")
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

	sAce, err := NewAce(systemSIDStr, systemMask, AccessAllowedAceType, ContainerInheritAce|InheritedAce)
	if err != nil {
		t.Fatal(err)
	}

	adminMask := PermWriteDacl | PermReadControl
	aAce, err := NewAce(adminSIDStr, adminMask, AccessAllowedAceType, ContainerInheritAce|InheritedAce)
	if err != nil {
		t.Fatal(err)
	}

	sd, err := NewSecurityDescriptor(SecurityDescriptorFlagSR, nil, nil, NewACL([]ACE{*sAce, *aAce}), nil)

	sdbuf, err := sd.MarshalBinary(nil)
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegSetKeySecurityReq{
		HKey:                hKey,
		SecurityInformation: DACLSecurityInformation,
		SecurityDescriptorIn: SecurityData{
			Size:            uint32(len(sdbuf)),
			Len:             uint32(len(sdbuf)),
			KeySecurityData: sd,
		},
	}

	buf, err := req.MarshalBinary(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestSetKeySecurityRes(t *testing.T) {
	pkt, err := hex.DecodeString("00000000")
	if err != nil {
		t.Fatal(err)
	}

	var res ReturnCode

	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.uint32 != 0 {
		t.Error("Fail")
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
		SecurityDescriptorIn: SecurityData{
			Size: 4096,
			Len:  0,
		},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	if res.SecurityDescriptorOut.Len != 100 {
		t.Error("fail")
	}
	if res.SecurityDescriptorOut.Size != 4096 {
		t.Error("fail")
	}

	sd := *res.SecurityDescriptorOut.KeySecurityData

	if sd.Control != SecurityDescriptorFlagSR|SecurityDescriptorFlagDP {
		t.Error("Fail")
	}
	if !bytes.Equal(sd.OwnerSid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}
	if sd.OwnerSid.SubAuthorities[0] != 32 {
		t.Error("Fail")
	}
	if sd.OwnerSid.SubAuthorities[1] != 544 {
		t.Error("Fail")
	}

	if !bytes.Equal(sd.GroupSid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}
	if sd.GroupSid.SubAuthorities[0] != 18 {
		t.Error("Fail")
	}

	if sd.Dacl.AclSize != 52 {
		t.Error("Fail")
	}

	if sd.Dacl.AceCount != 2 {
		t.Error("Fail")
	}
	acls := sd.Dacl.ACLS

	if acls[0].Mask != binary.LittleEndian.Uint32([]byte{0x3f, 0x00, 0x0f, 0x00}) {
		t.Error("Fail")
	}
	if acls[0].Header.Flags != 0x12 {
		t.Error("Fail")
	}
	if !bytes.Equal(acls[0].Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}

	if acls[0].Sid.SubAuthorities[0] != 18 {
		t.Error("Fail")
	}

	if acls[1].Mask != PermWriteDacl|PermReadControl {
		t.Error("Fail")
	}
	if acls[1].Header.Flags != 0x12 {
		t.Error("Fail")
	}
	if !bytes.Equal(acls[1].Sid.Authority, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x5}) {
		t.Error("Fail")
	}

	if acls[1].Sid.SubAuthorities[0] != 32 {
		t.Error("Fail")
	}

	if acls[1].Sid.SubAuthorities[1] != 544 {
		t.Error("Fail")
	}

	if res.ReturnCode.uint32 != 0 {
		t.Error("Fail")
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

	name, err := encoder.Utf8ToUtf16(encoder.ToUnicode("SAM\\SAM\x00"))
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegOpenKeyReq{
		HKey: hKey,
		SubKey: PRRPUnicodeStr2{
			Length:    8,
			MaxLength: 8,
			Buffer:    name,
		},
		Options:       0,
		DesiredAccess: 0x02000000,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}

func TestQueryInfoKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000e7f89e2120fd0d4cb4ba7d1714ee14050000120000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("00000000e7f89e2120fd0d4cb4ba7d1714ee1405")
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegQueryInfoKeyReq{
		HKey: hKey,
		ClassIn: RRPUnicodeStr3{
			Length:    0,
			MaxLength: 18,
			Buffer:    nil,
		},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	className, err := encoder.FromUnicode(encoder.Utf16ToUtf8(res.ClassOut.Buffer))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(className, []byte("0148322c\x00")) {
		t.Error("Fail")
	}

	if res.SubKeys != 0 {
		t.Error("Fail")
	}
	if res.MaxSubKeyLen != 0 {
		t.Error("Fail")
	}
	if res.MaxClassLen != 0 {
		t.Error("Fail")
	}
	if res.Values != 1 {
		t.Error("Fail")
	}
	if res.MaxValueNameLen != 12 {
		t.Error("Fail")
	}
	if res.MaxValueLen != 6 {
		t.Error("Fail")
	}
	if res.SecurityDescriptor != 240 {
		t.Error("Fail")
	}
	if res.LastWriteTime.LowDateTime != binary.LittleEndian.Uint32([]byte{0x7d, 0x5c, 0xa5, 0xa2}) {
		t.Error("Fail")
	}
	if res.LastWriteTime.HighDateTime != binary.LittleEndian.Uint32([]byte{0x9b, 0xcd, 0xd8, 0x01}) {
		t.Error("Fail")
	}
	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}

func TestQueryValueReq(t *testing.T) {
	pkt, err := hex.DecodeString("00000000942c0f11b62bbf43bf3218a4838ba62a16001600010000000b000000000000000b0000004f0062006a006500630074004e0061006d0065000000000002000000000400000100000000040000000000000000000003000000000400000400000000000000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("00000000942c0f11b62bbf43bf3218a4838ba62a")
	if err != nil {
		t.Fatal(err)
	}

	name, err := encoder.Utf8ToUtf16(encoder.ToUnicode("ObjectName\x00"))
	if err != nil {
		t.Fatal(err)
	}

	req := BaseRegQueryValueReq{
		HKey: hKey,
		ValueName: PRRPUnicodeStr2{
			Length:    uint16(len(name)),
			MaxLength: uint16(len(name)),
			Buffer:    name,
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
		t.Error("Fail")
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
		t.Error("Fail")
	}

	name, err := encoder.FromUnicode(res.Data)
	if !bytes.Equal(name, []byte(".\\Administrator\x00")) {
		t.Error("Fail")
	}

	if res.DataLen != 32 {
		t.Error("Fail")
	}
	if res.MaxLen != 32 {
		t.Error("Fail")
	}
	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}

func TestSaveKeyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000008f8aadcdeadaa44793587de60321be0d16001600010000000b000000000000000b00000043003a005c00730061006d002e0074006d007000000000000100000058000000020000004400000044000000000000004400000000000000440000000100048034000000000000000000000014000000020020000100000000021800000005c00102000000000005200000002002000001020000000000052000000020020000")
	if err != nil {
		t.Fatal(err)
	}

	hKey, err := hex.DecodeString("000000008f8aadcdeadaa44793587de60321be0d")
	if err != nil {
		t.Fatal(err)
	}

	name, err := encoder.Utf8ToUtf16(encoder.ToUnicode("C:\\sam.tmp\x00"))
	if err != nil {
		t.Fatal(err)
	}
	adminSIDStr := "S-1-5-32-544"
	adminMask := PermGenericRead | PermGenericWrite | PermWriteDacl | PermDelete
	aAce, err := NewAce(adminSIDStr, adminMask, AccessAllowedAceType, ContainerInheritAce)
	if err != nil {
		t.Fatal(err)
	}
	ownerSid, err := convertStrToSID(adminSIDStr)
	if err != nil {
		t.Fatal(err)
	}
	acl := NewACL([]ACE{*aAce})

	sd, err := NewSecurityDescriptor(SecurityDescriptorFlagSR, ownerSid, nil, acl, nil)
	if err != nil {
		t.Fatal(err)
	}
	sdbuf, err := sd.MarshalBinary(nil)
	if err != nil {
		t.Fatal(err)
		return
	}
	sdbufLen := uint32(len(sdbuf))
	rd := RpcSecurityDescriptor{
		SecurityDescriptor:    *sd,
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
		FileName: PRRPUnicodeStr2{
			Length:    11,
			MaxLength: 11,
			Buffer:    name,
		},
		SecurityAttributes: *sa,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestSaveKeyRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("00000000")
	if err != nil {
		t.Fatal(err)
	}

	var res ReturnCode
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.uint32 != 0 {
		t.Error("Fail")
	}
}
