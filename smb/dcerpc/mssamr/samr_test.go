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

package mssamr

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
)

func TestEncryptRC4(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("894321bed7e984a8990fcc776e033e4feabe1c0aa9983cfd94576617a160c4e66825bbc124f5f2da77df8010d4483f10a040e634eb88a1d36989b8a0771c122a92d8d44327251e939ba67b1bd870360828effa52180f0a3f4223da35aff1dfc3387dea176437b78e88ed42ba54a07f6a2ded5890fc76586f3915e9a6bc9709ed1d4c3740dd7f75e60139a2ee14d96bcc097f629c30f544eb5d25342ab87f0bc528e4a57ec525fd0303ca05325ecae9b8f7f19fa8ea6340b6c09d9558b28be93f24b4757bbfd41514635072c0ffdb004997ad4a323d48076af8f5a6d3c9e1f62d707747bc84b9eadade12bb2520a2bb9cd9240c7ea2e0d6aa46a5e01880fc5e1e9206520dac3a6e64b037bf0d70fe08bb997c1555cf42e361786cf02e8d5a20ec96b6d2e6cebc5383789746e0caca89c0841264f8f977d8c2a44d9edb4ff0d4d9dbdbea4795684fde7dd2267e085cafe999ab58fd4776654336eec58b241bd3d6355e52dfcbb0b43eba0855c6ec5fe47c37f99169a42414dbf9fe2f9c648e9c6c07ffa2b8166fa77ff37f47d0b227d726f94967501407a9bdee9e993b93534dda718d6425d7268ed92e936e52a07633b16b98f9e4d746c84fdf60d7a978229cb0a86a1e3c57e1ea0cde07b9ac23c7475cf83bc2dd9622b24c86a0135d71c78323a1abe2eff147a2fcd8bbfb15ecf2285595e18b3ebb08a93699c96e2a1cf0b844ff3f593a")
	passBuf, _ := hex.DecodeString("4e128429e234b7a6505b2e91503942db591b1589767513f4c26f08091dc3a3db043e653b096eccc8b20a4449335c7032c2eb112bf159087e902259bc94fc51298cb88eb5d22614b3b3f0fc255cf816b522749969ef9a4b8e8f7f4e03cb966e6bd924b56c122caaa83aa87d66091a84674127d44f3d8f17e8d5eb7f9cf279c1cab65b3502b36c0d246db118e4fb248d07ce77b0bc2cf8369ca1716b9db7e0bc6fcc0b6284cdc8f1fd301f8b980cd5bd6d2567893ab0cda1bd629a5bf843494d577e129ebd235247a160b06cf8dd35e202c3214da42da69f548f3c103ccafdbb5ce592af21e73e97b94a33c839d15e7d8116f0bb2b1abb6c9f7e9dabbe8939700e0af26be83b1c724150c154a307b7893af1eea8e06993b5cfab6144dca730e911845baca8a607f1dcae9def34b2ce7108dd17177503c4ed060b00ef891a58a733fde2f0f42d60b09415b733179e8bec28b1554a3ef8a23fe598fa3c49186fcba4d75cd7f1afa128f11f03cc2bd1075521a366eccbd941e9f83cd2a8785416d9992abfe3b69a999445a13b9ef6cb06a0a923c94f32f1ad5172d33f658025da327f6677d9fd011ac5b498918721c43a49d781ba6eeb9630a40af0f30c82f2d08bccafb8f8fe8786f9fafe5165a56d70e7de822f29d77bf014c93acf69293b3c5c3707fbe67fc7e6c878ad609862248d500061007300730077003000720064002100")
	sessionKey, _ := hex.DecodeString("9f576c446a93bac39810f376e7347d6b")

	pass := &SamprUserPassword{
		Buffer: passBuf,
		Length: 18,
	}
	var encPassword []byte
	encPassword, err := pass.EncryptRC4(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encPassword, pkt) {
		t.Fatal("Fail")
	}
}

func TestSamrConnect5Req(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000000000000201000000010000000300000000000000")

	req := SamrConnect5Req{
		ServerName:     "",
		DesiredAccess:  MaximumAllowed,
		InVersion:      1,
		InRevisionInfo: &SamprRevisionInfoV1{Revision: 3, SupportedFeatures: 0},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrConnect5Res(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0100000001000000030000000000000000000000f46a5a3de8697b4d93cb4afc153179ca00000000")
	handle, _ := hex.DecodeString("00000000f46a5a3de8697b4d93cb4afc153179ca")
	var resp SamrConnect5Res
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(resp.ServerHandle, handle) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumDomainsReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000063537d27c9f31247a57ec952454f923100000000ffff0000")
	handle, _ := hex.DecodeString("0000000063537d27c9f31247a57ec952454f9231")

	req := SamrEnumDomainsReq{
		ServerHandle:       handle,
		EnumerationContext: 0,
		PreferredMaxLength: 0xFFFF,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumDomainsRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0200000000000200020000000400020002000000000000000a000c0008000200000000000e0010000c0002000600000000000000050000004600490046005400480000000800000000000000070000004200750069006c00740069006e0000000200000000000000")
	var resp SamrEnumDomainsRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if resp.CountReturned != 2 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[0].Name != "FIFTH" {
		t.Fatal("Fail")
	}
}

func TestSamrLookupDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000f25d62c2f570cd4cba8f5909bc7eebd60e001000010000000800000000000000070000004200750069006c00740069006e00")
	handle, _ := hex.DecodeString("00000000f25d62c2f570cd4cba8f5909bc7eebd6")

	req := SamrLookupDomainReq{
		ServerHandle: handle,
		Name:         msdtyp.RPCUnicodeStr{S: "Builtin"},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrLookupDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000002000100000001010000000000052000000000000000")
	var resp SamrLookupDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.DomainId.ToString() != "S-1-5-32" {
		t.Fatal("Fail")
	}
}

func TestSamrAddMemberToGroup(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000074f7a8f9b9f26b4db8fdd6e23eaed272e903000000000000")
	handle, _ := hex.DecodeString("0000000074f7a8f9b9f26b4db8fdd6e23eaed272")

	req := SamrAddMemberToGroupReq{
		GroupHandle: handle,
		MemberId:    1001,
		Attributes:  0,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrRemoveMemberFromGroup(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000006b7d89c99f79464b819e9e36106b7b6ae9030000")
	handle, _ := hex.DecodeString("000000006b7d89c99f79464b819e9e36106b7b6a")

	req := SamrRemoveMemberFromGroupReq{
		GroupHandle: handle,
		MemberId:    1001,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrGetMembersInGroupReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000a7cc62ab49e43f459177017f95a45521")
	handle, _ := hex.DecodeString("00000000a7cc62ab49e43f459177017f95a45521")

	req := SamrGetMembersInGroupReq{
		GroupHandle: handle,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrGetMembersInGroupRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000020005000000040002000800020005000000f4010000f5010000f7010000f8010000e903000005000000070000000700000007000000070000000700000000000000")
	var res SamrGetMembersInGroupRes
	err := res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.Members.MemberCount != 5 {
		t.Fatal("Fail")
	}
	if res.Members.Members[0] != 500 {
		t.Fatal("Fail")
	}
	if res.Members.Attributes[0] != 7 {
		t.Fatal("Fail")
	}
}

func TestSamrOpenDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000001be3929e54f624593c95b7077cdbc440000000204000000010400000000000515000000c207a1ca5072fbb32ce9c7d2")
	handle, _ := hex.DecodeString("0000000001be3929e54f624593c95b7077cdbc44")
	domainId, _ := msdtyp.ConvertStrToSID("S-1-5-21-3399550914-3019600464-3536316716")

	req := SamrOpenDomainReq{
		ServerHandle:  handle,
		DesiredAccess: MaximumAllowed,
		DomainId:      domainId,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrOpenDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000003758ced4cd5af6449cbc22f1ca57069800000000")
	handle, _ := hex.DecodeString("000000003758ced4cd5af6449cbc22f1ca570698")
	var resp SamrOpenDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		return
	}

	if !bytes.Equal(resp.ServerHandle, handle) {
		t.Fatal("Fail")
	}
}

func TestSamrAddMemberToAliasReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000081444460e094954a9d85644d9c4a599805000000010500000000000515000000c207a1ca5072fbb32ce9c7d2e9030000")
	handle, _ := hex.DecodeString("0000000081444460e094954a9d85644d9c4a5998")
	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-3399550914-3019600464-3536316716-1001")
	req := SamrAddMemberToAliasReq{
		AliasHandle: handle,
		MemberId:    sid,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrRemoveMemberFromAlias(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000054058e3e85a62448ad45ab5ed0228a9c05000000010500000000000515000000c207a1ca5072fbb32ce9c7d2e9030000")
	handle, _ := hex.DecodeString("0000000054058e3e85a62448ad45ab5ed0228a9c")
	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-3399550914-3019600464-3536316716-1001")

	req := SamrRemoveMemberFromAliasReq{
		AliasHandle: handle,
		MemberId:    sid,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrLookupIdsInDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000081eafdf986dda74c831514c07839cf5101000000e80300000000000001000000e9030000")
	handle, _ := hex.DecodeString("0000000081eafdf986dda74c831514c07839cf51")
	req := SamrLookupIdsInDomainReq{
		DomainHandle: handle,
		Count:        1,
		RelativeIds:  []uint32{1001},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrLookupIdsInDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("010000000000020001000000080008000400020004000000000000000400000074006500730074000100000008000200010000000100000000000000")
	var resp SamrLookupIdsInDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.Names.Elements[0] != "test" {
		t.Fatal("Fail")
	}
	if resp.Use[0] != 1 {
		t.Fatal("Fail")
	}
}

func TestSamrOpenGroupReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000b046a8d99e6d044994b050f11fbec06a0000000201020000")
	handle, _ := hex.DecodeString("00000000b046a8d99e6d044994b050f11fbec06a")

	req := SamrOpenGroupReq{
		DomainHandle:  handle,
		DesiredAccess: MaximumAllowed,
		GroupRID:      513,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrOpenAliasReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000030534e79673c3248b0d54c5ccc3fc9890000000220020000")
	handle, _ := hex.DecodeString("0000000030534e79673c3248b0d54c5ccc3fc989")

	req := SamrOpenAliasReq{
		DomainHandle:  handle,
		DesiredAccess: MaximumAllowed,
		AliasId:       544,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrGetMembersInAliasRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("020000000000020002000000040002000800020005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2f401000005000000010500000000000515000000bdb9fa3ca34872294541fc790002000000000000")

	var resp SamrGetMembersInAliasRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.Members.Count != 2 {
		t.Fatal("Fail")
	}
	if resp.Members.Sids[0].SidPointer.ToString() != "S-1-5-21-3399550914-3019600464-3536316716-500" {
		t.Fatal("Fail")
	}
}

func TestSamrCloseHandleReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000f8bd7c9a1edf0a4aa4532dfb47d8c3b2")
	handle, _ := hex.DecodeString("00000000f8bd7c9a1edf0a4aa4532dfb47d8c3b2")

	req := SamrCloseHandleReq{
		ServerHandle: handle,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrRidToSidReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000499bb328026c2e4f9e6a060437c0dca7e9030000")
	handle, _ := hex.DecodeString("00000000499bb328026c2e4f9e6a060437c0dca7")

	req := SamrRidToSidReq{
		Handle: handle,
		Rid:    1001,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrRidToSidRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000020005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2e903000000000000")

	var resp SamrRidToSidRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.Sid.ToString() != "S-1-5-21-3399550914-3019600464-3536316716-1001" {
		t.Fatal("Fail")
	}
}

func TestSamrCreateUserInDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000c30967e83fe5a042b91c5b7030fbeea50a000c000100000006000000000000000500000074006500730074003300000000000002")
	handle, _ := hex.DecodeString("00000000c30967e83fe5a042b91c5b7030fbeea5")

	req := SamrCreateUserInDomainReq{
		DomainHandle:  handle,
		Name:          "test3",
		DesiredAccess: MaximumAllowed,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrCreateUserInDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000ace4f8f78255c149bb97f6de9efbb32e0404000000000000")
	handle, _ := hex.DecodeString("00000000ace4f8f78255c149bb97f6de9efbb32e")

	var resp SamrCreateUserInDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(resp.UserHandle, handle) {
		t.Fatal("Fail")
	}
	if resp.RelativeId != 1028 {
		t.Fatal("Fail")
	}
}

func TestSamrEnumDomainUsersReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000003758ced4cd5af6449cbc22f1ca5706980000000010000000ffff0000")
	handle, _ := hex.DecodeString("000000003758ced4cd5af6449cbc22f1ca570698")
	req := SamrEnumDomainUsersReq{
		DomainHandle:       handle,
		ResumeHandle:       0,
		AccountFlags:       0x10,
		PreferredMaxLength: 0xFFFF,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumDomainUsersRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0500000000000200050000000400020005000000f40100001a00200008000200f70100001c0020000c000200f50100000a00200010000200e90300000800200014000200f8010000240024001800020010000000000000000d000000410064006d0069006e006900730074007200610074006f007200000010000000000000000e000000440065006600610075006c0074004100630063006f0075006e007400100000000000000005000000470075006500730074000000100000000000000004000000740065007300740012000000000000001200000057004400410047005500740069006c006900740079004100630063006f0075006e0074000500000000000000")

	var resp SamrEnumDomainUsersRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.CountReturned != 5 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[0].RelativeId != 500 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[4].Name != "WDAGUtilityAccount" {
		t.Fatal("Fail")
	}
}

func TestSamrEnumerateGroupsInDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000040fe770f096e8148ad56f70ea0a2292200000000ffff0000")
	handle, _ := hex.DecodeString("0000000040fe770f096e8148ad56f70ea0a22922")

	req := SamrEnumerateGroupsInDomainReq{
		DomainHandle:       handle,
		EnumerationContext: 0,
		PreferredMaxLength: 0xFFFF,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumerateGroupsInDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("01000000000002000100000004000200010000000102000008002000080002001000000000000000040000004e006f006e0065000100000000000000")

	var resp SamrEnumerateGroupsInDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if resp.CountReturned != 1 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[0].RelativeId != 513 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[0].Name != "None" {
		t.Fatal("Fail")
	}
}

func TestSamrGetUserInfo2Req(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000001e1d87d3ab21d24daab28f93984541001500")
	handle, _ := hex.DecodeString("000000001e1d87d3ab21d24daab28f9398454100")

	req := SamrQueryInformationUser2Req{
		UserHandle:           handle,
		UserInformationClass: UserAllInformation,
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrGetUserInfo2Res(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000002001500000000000000000000000000000000000000b08de0187e99db01ffffffffffffff7fb04d4a43479adb01ffffffffffffff7f0a000a00040002000000000008000200000000000c000200000000001000020000000000140002000000000018000200000000001c0002000000000020000200000000002400020000000000280002000000000000000000000000000000000000000000000000000000000000000000040400000102000010020000ffffff00a80000002c000200000000000000000000000000050000000000000005000000740065007300740033000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ec0400000000000015000000ffffffffffffffffffffffffffffffffffffffffff00000000000000")
	var res SamrQueryInformationUser2Res
	err := res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}
	var info *SamprUserAllInformation
	info = res.Buffer.(*SamprUserAllInformation)
	if info.Username != "test3" {
		t.Fatal("Fail")
	}
	if info.UserId != 1028 {
		t.Fatal("Fail")
	}
	if info.PrimaryGroupId != 513 {
		t.Fatal("Fail")
	}
	if info.UserAccountControl != 0x210 {
		t.Fatal("Fail")
	}
}

func TestSamrSetUserInfo2Req(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000003296d64a4fc91a49b615efad07bf4f111700170000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000894321bed7e984a8990fcc776e033e4feabe1c0aa9983cfd94576617a160c4e66825bbc124f5f2da77df8010d4483f10a040e634eb88a1d36989b8a0771c122a92d8d44327251e939ba67b1bd870360828effa52180f0a3f4223da35aff1dfc3387dea176437b78e88ed42ba54a07f6a2ded5890fc76586f3915e9a6bc9709ed1d4c3740dd7f75e60139a2ee14d96bcc097f629c30f544eb5d25342ab87f0bc528e4a57ec525fd0303ca05325ecae9b8f7f19fa8ea6340b6c09d9558b28be93f24b4757bbfd41514635072c0ffdb004997ad4a323d48076af8f5a6d3c9e1f62d707747bc84b9eadade12bb2520a2bb9cd9240c7ea2e0d6aa46a5e01880fc5e1e9206520dac3a6e64b037bf0d70fe08bb997c1555cf42e361786cf02e8d5a20ec96b6d2e6cebc5383789746e0caca89c0841264f8f977d8c2a44d9edb4ff0d4d9dbdbea4795684fde7dd2267e085cafe999ab58fd4776654336eec58b241bd3d6355e52dfcbb0b43eba0855c6ec5fe47c37f99169a42414dbf9fe2f9c648e9c6c07ffa2b8166fa77ff37f47d0b227d726f94967501407a9bdee9e993b93534dda718d6425d7268ed92e936e52a07633b16b98f9e4d746c84fdf60d7a978229cb0a86a1e3c57e1ea0cde07b9ac23c7475cf83bc2dd9622b24c86a0135d71c78323a1abe2eff147a2fcd8bbfb15ecf2285595e18b3ebb08a93699c96e2a1cf0b844ff3f593a")
	passBuf, _ := hex.DecodeString("4e128429e234b7a6505b2e91503942db591b1589767513f4c26f08091dc3a3db043e653b096eccc8b20a4449335c7032c2eb112bf159087e902259bc94fc51298cb88eb5d22614b3b3f0fc255cf816b522749969ef9a4b8e8f7f4e03cb966e6bd924b56c122caaa83aa87d66091a84674127d44f3d8f17e8d5eb7f9cf279c1cab65b3502b36c0d246db118e4fb248d07ce77b0bc2cf8369ca1716b9db7e0bc6fcc0b6284cdc8f1fd301f8b980cd5bd6d2567893ab0cda1bd629a5bf843494d577e129ebd235247a160b06cf8dd35e202c3214da42da69f548f3c103ccafdbb5ce592af21e73e97b94a33c839d15e7d8116f0bb2b1abb6c9f7e9dabbe8939700e0af26be83b1c724150c154a307b7893af1eea8e06993b5cfab6144dca730e911845baca8a607f1dcae9def34b2ce7108dd17177503c4ed060b00ef891a58a733fde2f0f42d60b09415b733179e8bec28b1554a3ef8a23fe598fa3c49186fcba4d75cd7f1afa128f11f03cc2bd1075521a366eccbd941e9f83cd2a8785416d9992abfe3b69a999445a13b9ef6cb06a0a923c94f32f1ad5172d33f658025da327f6677d9fd011ac5b498918721c43a49d781ba6eeb9630a40af0f30c82f2d08bccafb8f8fe8786f9fafe5165a56d70e7de822f29d77bf014c93acf69293b3c5c3707fbe67fc7e6c878ad609862248d500061007300730077003000720064002100")
	handle, _ := hex.DecodeString("000000003296d64a4fc91a49b615efad07bf4f11")
	sessionKey, _ := hex.DecodeString("9f576c446a93bac39810f376e7347d6b")

	pass := &SamprUserPassword{
		Buffer: passBuf,
		Length: 18,
	}

	internal4 := &SamprUserInternal4Information{}
	var encPassword []byte
	encPassword, err := pass.EncryptRC4(sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	internal4.UserPassword = encPassword
	internal4.I1.WhichFields |= UserAllNtpasswordpresent | UserAllLmpasswordpresent

	req := SamrSetInformationUser2Req{
		UserHandle:           handle,
		UserInformationClass: UserInternal4Information,
		Buffer:               internal4,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumAliasesInDomainReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000078179f9aca3a8043b01d4b5c2d59954100000000ffff0000")
	handle, _ := hex.DecodeString("0000000078179f9aca3a8043b01d4b5c2d599541")
	req := SamrEnumAliasesInDomainReq{
		DomainHandle:       handle,
		EnumerationContext: 0,
		PreferredMaxLength: 0xFFFF,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrEnumAliasesInDomainRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0100000000000200010000000400020001000000e80300004200420008000200210000000000000021000000530051004c005300650072007600650072003200300030003500530051004c00420072006f007700730065007200550073006500720024004600490046005400480000000100000000000000")
	var resp SamrEnumAliasesInDomainRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if resp.CountReturned != 1 {
		t.Fatal("Fail")
	}
	if resp.Buffer.Buffer[0].Name != "SQLServer2005SQLBrowserUser$FIFTH" {
		t.Fatal("Fail")
	}
}

func TestSamrOpenUserReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000002c0c5d793c997d49ad162fd8db33960d0000000204040000")
	handle, _ := hex.DecodeString("000000002c0c5d793c997d49ad162fd8db33960d")

	req := SamrOpenUserReq{
		DomainHandle:  handle,
		DesiredAccess: MaximumAllowed,
		UserId:        1028,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestSamrOpenUserRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000001e1d87d3ab21d24daab28f939845410000000000")
	handle, _ := hex.DecodeString("000000001e1d87d3ab21d24daab28f9398454100")

	var resp SamrOpenUserRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}

	if !bytes.Equal(handle, resp.UserHandle) {
		t.Fatal("Fail")
	}
}

func TestSamrDeleteUserReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000075727d6e145d97458157e795872506e5")
	handle, _ := hex.DecodeString("0000000075727d6e145d97458157e795872506e5")
	req := SamrDeleteUserReq{
		UserHandle: handle,
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}
