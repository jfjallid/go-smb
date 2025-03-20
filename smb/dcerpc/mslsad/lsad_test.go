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
//
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package mslsad

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
)

func TestLsarCloseHandleReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000013d8cd7a32dac447a2d2e1094606f710")

	handle, _ := hex.DecodeString("0000000013d8cd7a32dac447a2d2e1094606f710")
	req := LsarCloseReq{
		ObjectHandle: handle,
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

func TestLsarQueryInformationPolicyReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000002576201d63a8614681d8eeb1380e15200300")

	policyHandle, _ := hex.DecodeString("000000002576201d63a8614681d8eeb1380e1520")

	req := LsarQueryInformationPolicyReq{
		PolicyHandle:     policyHandle,
		InformationClass: 3,
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

func TestLsarQueryInformationPolicyRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000200030000000c000e00040002000800020007000000000000000600000053004b0059004e004500540004000000010400000000000515000000bdb9fa3ca34872294541fc7900000000")

	var resp LsarQueryInformationPolicyRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	var info *LsaprPolicyPrimaryDomInfo
	info = resp.PolicyInformation.(*LsaprPolicyPrimaryDomInfo)
	if info.Name != "SKYNET" {
		t.Fatal("Fail")
	}
	if info.Sid.ToString() != "S-1-5-21-1023064509-695355555-2046574917" {
		t.Fatal("Fail")
	}
	return
}

//func TestLsarCreateAccountReq(t *testing.T) {
//	// Simple test to verify that the packet structure is valid
//	pkt, _ := hex.DecodeString("")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	req := LsarCreateAccountReq{
//		PolicyHandle:  policyHandle,
//		DesiredAccess: desiredAccess,
//	}
//
//	req.AccountSid, err = msdtyp.ConvertStrToSID(sid)
//	if err != nil {
//		t.Fatal(err)
//		return
//	}
//
//	buf, err := req.MarshalBinary()
//	if err != nil {
//		t.Fatal(err)
//		return
//	}
//
//	var resp LsarCreateAccountRes
//	err = resp.UnmarshalBinary(buffer)
//	if err != nil {
//		t.Fatal(err)
//		return
//	}
//
//	if !bytes.Equal(pkt, buf) {
//		t.Fatal("Fail")
//	}
//	return
//}

func TestLsarEnumerateAccountsReq(t *testing.T) {
	pkt, _ := hex.DecodeString("000000000f0b08773dd4954a885f252d1e3571fd0000000000100000")
	policyHandle, _ := hex.DecodeString("000000000f0b08773dd4954a885f252d1e3571fd")

	req := LsarEnumerateAccountsReq{
		PolicyHandle:       policyHandle,
		EnumerationContext: 0,
		PreferredMaxLength: 4096,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}
func TestLsarEnumerateAccountsRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("1400000014000000000002001400000004000200080002000c0002001000020014000200180002001c0002002000020024000200280002002c0002003000020034000200380002003c0002004000020044000200480002004c000200500002000200000001020000000000055a0000000000000006000000010600000000000550000000208e57230361b762f2baaf11117706f0e7956e8306000000010600000000000550000000703344e71d40b7ffb8844562a9e3c7d4fd9771d8060000000106000000000005500000006ebf1bbb45efd2b14a3b45db505b43270458d86b060000000106000000000005500000002c4559766def9a2f8e23ea83ae7c7f71254cb2cc020000000102000000000005500000000000000001000000010100000000000506000000020000000102000000000005200000002f020000020000000102000000000005200000002b02000002000000010200000000000520000000270200000200000001020000000000052000000021020000020000000102000000000005200000002002000005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2fd03000005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2f203000005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2e903000005000000010500000000000515000000c207a1ca5072fbb32ce9c7d2e803000005000000010500000000000515000000bdb9fa3ca34872294541fc795204000001000000010100000000000514000000010000000101000000000005130000000100000001010000000000010000000000000000")
	var resp LsarEnumerateAccountsRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if resp.EnumerationBuffer.Entries != 20 {
		t.Fatal("Fail")
	}
	if resp.EnumerationBuffer.Information[1].Sid.ToString() != "S-1-5-80-592940576-1656185091-296729330-4026955537-2205062631" {
		t.Fatal("Fail")
	}
}

func TestLsarOpenAccountReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000032bf6b0453c549498219e34aa230a40005000000010500000000000515000000bdb9fa3ca34872294541fc795204000000000002")
	policyHandle, _ := hex.DecodeString("0000000032bf6b0453c549498219e34aa230a400")

	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-1023064509-695355555-2046574917-1106")

	req := LsarOpenAccountReq{
		PolicyHandle:  policyHandle,
		AccountSid:    *sid,
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

func TestLsarOpenAccountRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000dcc6a0b132ead24785decd3b8a1723b500000000")
	handle, _ := hex.DecodeString("00000000dcc6a0b132ead24785decd3b8a1723b5")
	var resp LsarOpenAccountRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if !bytes.Equal(resp.AccountHandle, handle) {
		t.Fatal("Fail")
	}
}

func TestLsarGetSystemAccessAccountReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("00000000dcc6a0b132ead24785decd3b8a1723b5")
	accountHandle, _ := hex.DecodeString("00000000dcc6a0b132ead24785decd3b8a1723b5")

	req := LsarGetSystemAccessAccountReq{
		AccountHandle: accountHandle,
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

func TestLsarGetSystemAccessAccountRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0100000000000000")
	var resp LsarGetSystemAccessAccountRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if (resp.SystemAccess & SeInteractiveLogonRight) != SeInteractiveLogonRight {
		t.Fatal("Fail")
	}
}

func TestLsarSetSystemAccessAccountReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000054bd1c622f4ec44194c665bb6d9936c601000000")
	accountHandle, _ := hex.DecodeString("0000000054bd1c622f4ec44194c665bb6d9936c6")

	req := LsarSetSystemAccessAccountReq{
		AccountHandle: accountHandle,
		SystemAccess:  SeInteractiveLogonRight,
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

func TestLsarEnumerateAccountRightsReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0000000063184d5211b96540ad5e805393ffcc8105000000010500000000000515000000bdb9fa3ca34872294541fc7952040000")
	policyHandle, _ := hex.DecodeString("0000000063184d5211b96540ad5e805393ffcc81")

	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-1023064509-695355555-2046574917-1106")
	req := LsarEnumerateAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
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

func TestLsarEnumerateAccountRightsRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("0100000000000200010000002200240004000200120000000000000011000000530065004200610063006b0075007000500072006900760069006c00650067006500000000000000")
	var resp LsarEnumerateAccountRightsRes
	err := resp.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
		return
	}
	if resp.UserRights.Entries != 1 {
		t.Fatal("Fail")
	}
	if resp.UserRights.UserRights[0] != "SeBackupPrivilege" {
		t.Fatal("Fail")
	}
}

func TestLsarAddAccountRightsReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000004434e0c899f505488f125fc485ca3a8705000000010500000000000515000000bdb9fa3ca34872294541fc795204000001000000010000000100000024002600020000001300000000000000120000005300650052006500730074006f0072006500500072006900760069006c00650067006500")
	policyHandle, _ := hex.DecodeString("000000004434e0c899f505488f125fc485ca3a87")
	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-1023064509-695355555-2046574917-1106")
	req := LsarAddAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
		UserRights:   LsaprUserRightSet{UserRights: []string{"SeRestorePrivilege"}},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestLsarRemoveAccountRightsReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000008a5f943e238b5e4e89106934c5bb01de05000000010500000000000515000000bdb9fa3ca34872294541fc79520400000000000001000000010000000100000024002600020000001300000000000000120000005300650052006500730074006f0072006500500072006900760069006c00650067006500")
	policyHandle, _ := hex.DecodeString("000000008a5f943e238b5e4e89106934c5bb01de")
	sid, _ := msdtyp.ConvertStrToSID("S-1-5-21-1023064509-695355555-2046574917-1106")

	req := LsarRemoveAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
		AllRights:    false,
		UserRights:   LsaprUserRightSet{UserRights: []string{"SeRestorePrivilege"}},
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestLsarOpenPolicy2Req(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, _ := hex.DecodeString("000000001800000000000000000000000000000000000000010000000c0000000200010000000002")
	req := LsarOpenPolicy2Req{
		SystemName: "",
		ObjectAttributes: LsaprObjectAttributes{
			Length: 24,
			SecurityQualityOfService: SecurityQualityOfService{
				Length:              12,
				ImpersonationLevel:  LsaSecurityImpersonation,
				ContextTrackingMode: 1,
			},
		},
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
