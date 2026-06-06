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
package msscmr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
)

func TestOpenSCManagerReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000200060000000000000006000000440055004d004d0059000000040002000f000000000000000f000000530065007200760069006300650073004100630074006900760065000000000004000000")
	if err != nil {
		t.Fatal(err)
	}

	req := ROpenSCManagerWReq{
		MachineName:   "DUMMY",
		DatabaseName:  "ServicesActive",
		DesiredAccess: 4,
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestOpenSCManagerRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f00000000")
	if err != nil {
		t.Fatal(err)
	}
	var expectedHandle [20]byte
	handleBytes, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}
	copy(expectedHandle[:], handleBytes)

	res := ROpenSCManagerWRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ContextHandle != expectedHandle {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", res.ContextHandle, expectedHandle)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestOpenServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f0f000000000000000f000000520065006d006f0074006500520065006700690073007400720079000000000004000000")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := ROpenServiceWReq{
		SCContextHandle: handle,
		ServiceName:     "RemoteRegistry",
		DesiredAccess:   4,
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestOpenServiceRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b800000000")
	if err != nil {
		t.Fatal(err)
	}
	var expectedHandle [20]byte
	handleBytes, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}
	copy(expectedHandle[:], handleBytes)

	res := ROpenServiceWRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ContextHandle != expectedHandle {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", res.ContextHandle, expectedHandle)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestQueryServiceStatusReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RQueryServiceStatusReq{ContextHandle: handle}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestQueryServiceStatusRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("3000000004000000010000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RQueryServiceStatusRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ServiceStatus.ServiceType != ServiceWin32OwnProcess|ServiceWin32ShareProcess {
		t.Fatalf("expected res.ServiceStatus.ServiceType==ServiceWin32OwnProcess|ServiceWin32ShareProcess, got %v", res.ServiceStatus.ServiceType)
	}

	if res.ServiceStatus.CurrentState != ServiceRunning {
		t.Fatalf("expected res.ServiceStatus.CurrentState==ServiceRunning, got %v", res.ServiceStatus.CurrentState)
	}

	if res.ServiceStatus.ControlsAccepted != ServiceControlStop {
		t.Fatalf("expected res.ServiceStatus.ControlsAccepted==ServiceControlStop, got %v", res.ServiceStatus.ControlsAccepted)
	}

	if res.ServiceStatus.Win32ExitCode != 0 {
		t.Fatalf("expected res.ServiceStatus.Win32ExitCode==0, got %v", res.ServiceStatus.Win32ExitCode)
	}

	if res.ServiceStatus.ServiceSpecificExitCode != 0 {
		t.Fatalf("expected res.ServiceStatus.ServiceSpecificExitCode==0, got %v", res.ServiceStatus.ServiceSpecificExitCode)
	}

	if res.ServiceStatus.CheckPoint != 0 {
		t.Fatalf("expected res.ServiceStatus.CheckPoint==0, got %v", res.ServiceStatus.CheckPoint)
	}

	if res.ServiceStatus.WaitHint != 0 {
		t.Fatalf("expected res.ServiceStatus.WaitHint==0, got %v", res.ServiceStatus.WaitHint)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestStartServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000008ed4ec88663ec14b98044c090f02b6b00000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("000000008ed4ec88663ec14b98044c090f02b6b0")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RStartServiceWReq{
		ServiceHandle: handle,
		Argc:          0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestControlServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000e0496b495a835843af8e37808f55d3d501000000")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("00000000e0496b495a835843af8e37808f55d3d5")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RControlServiceReq{
		ServiceHandle: handle,
		Control:       ServiceControlStop,
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestControlServiceRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("3000000003000000010000002a0400000000000003000000b80b000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RControlServiceRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ServiceStatus.ServiceType != ServiceWin32OwnProcess|ServiceWin32ShareProcess {
		t.Fatalf("expected res.ServiceStatus.ServiceType==ServiceWin32OwnProcess|ServiceWin32ShareProcess, got %v", res.ServiceStatus.ServiceType)
	}

	if res.ServiceStatus.CurrentState != ServiceStopPending {
		t.Fatalf("expected res.ServiceStatus.CurrentState==ServiceStopPending, got %v", res.ServiceStatus.CurrentState)
	}

	if res.ServiceStatus.ControlsAccepted != ServiceControlStop {
		t.Fatalf("expected res.ServiceStatus.ControlsAccepted==ServiceControlStop, got %v", res.ServiceStatus.ControlsAccepted)
	}

	if res.ServiceStatus.Win32ExitCode != 0x042a {
		t.Fatalf("expected res.ServiceStatus.Win32ExitCode==0x042a, got %v", res.ServiceStatus.Win32ExitCode)
	}

	if res.ServiceStatus.ServiceSpecificExitCode != 0 {
		t.Fatalf("expected res.ServiceStatus.ServiceSpecificExitCode==0, got %v", res.ServiceStatus.ServiceSpecificExitCode)
	}

	if res.ServiceStatus.CheckPoint != 3 {
		t.Fatalf("expected res.ServiceStatus.CheckPoint==3, got %v", res.ServiceStatus.CheckPoint)
	}

	if res.ServiceStatus.WaitHint != 0x0bb8 {
		t.Fatalf("expected res.ServiceStatus.WaitHint==0x0bb8, got %v", res.ServiceStatus.WaitHint)
	}

	if res.ReturnValue != 0 {
		t.Fatalf("expected res.ReturnValue==0, got %v", res.ReturnValue)
	}
}

func TestQueryServiceConfig(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000cab639200617fa49bb641d17f510390502010000")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("00000000cab639200617fa49bb641d17f5103905")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RQueryServiceConfigWReq{
		ServiceHandle: handle,
		BufSize:       258,
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestQueryServiceConfigRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("200000000300000000000000000002000400020000000000080002000c000200100002002c000000000000002c00000043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e0065007800650020002d006b002000720064007800670072006f00750070000000010000000000000001000000000000000200000000000000020000002f0000000c000000000000000c0000004c006f00630061006c00530079007300740065006d000000140000000000000014000000520065007400610069006c002000440065006d006f002000530065007200760069006300650000000201000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RQueryServiceConfigWRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ErrorCode != 0 {
		t.Fatalf("expected res.ErrorCode==0, got %v", res.ErrorCode)
	}

	if res.BytesNeeded != 0x0102 {
		t.Fatalf("expected res.BytesNeeded==0x0102, got %v", res.BytesNeeded)
	}

	conf := &res.ServiceConfig

	if conf.ServiceType != ServiceWin32ShareProcess {
		t.Fatalf("expected res.ServiceConfig.ServiceType==ServiceWin32ShareProcess, got %v", conf.ServiceType)
	}

	if conf.StartType != ServiceDemandStart {
		t.Fatalf("expected conf.StartType==ServiceDemandStart, got %v", conf.StartType)
	}

	if conf.ErrorControl != ServiceErrorIgnore {
		t.Fatalf("expected conf.ErrorControl==ServiceErrorIgnore, got %v", conf.ErrorControl)
	}

	if conf.BinaryPathName != "C:\\Windows\\System32\\svchost.exe -k rdxgroup" {
		t.Fatalf("expected conf.BinaryPathName==C:\\Windows\\System32\\svchost.exe -k rdxgroup, got %v", conf.BinaryPathName)
	}

	if conf.LoadOrderGroup != "" {
		t.Fatalf("expected conf.LoadOrderGroup==, got %v", conf.LoadOrderGroup)
	}

	if conf.TagId != 0 {
		t.Fatalf("expected conf.TagId==0, got %v", conf.TagId)
	}

	if conf.Dependencies != "/" {
		t.Fatalf("expected conf.Dependencies==/, got %v", conf.Dependencies)
	}

	if conf.ServiceStartName != "LocalSystem" {
		t.Fatalf("expected conf.ServiceStartName==LocalSystem, got %v", conf.ServiceStartName)
	}

	if conf.DisplayName != "Retail Demo Service" {
		t.Fatalf("expected conf.DisplayName==Retail Demo Service, got %v", conf.DisplayName)
	}
}

func TestChangeServiceConfigReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	var handle [20]byte
	handleBytes, err := hex.DecodeString("000000009b8a1554f3da95418cbe3c9f6be68d0b")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	sessionKey, err := hex.DecodeString("47780a2c2a3bb5890a0b70328790829d")
	if err != nil {
		t.Fatal(err)
	}

	req := RChangeServiceConfigWReq{
		ServiceHandle:    handle,
		ServiceType:      ServiceNoChange,
		StartType:        ServiceDisabled,
		ErrorControl:     ServiceErrorIgnore,
		BinaryPathName:   strPtr("C:\\Windows\\System32\\svchost.exe -k rdxgroup"),
		ServiceStartName: strPtr(".\\administrator"),
		DisplayName:      strPtr("Retail demo service2"),
	}

	password := "secretpass"
	uncPassword := msdtyp.ToUnicode(password + "\x00")
	encPassword, err := dcerpc.EncryptSecretDes(sessionKey, uncPassword)
	if err != nil {
		t.Fatal(err)
	}
	req.Password = &encPassword
	req.PwSize = uint32(len(encPassword))

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("000000009b8a1554f3da95418cbe3c9f6be68d0bffffffff0400000000000000000002002c000000000000002c00000043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e0065007800650020002d006b002000720064007800670072006f0075007000000000000000000000000000000000000000040002001000000000000000100000002e005c00610064006d0069006e006900730074007200610074006f007200000008000200200000003e3af69cb90cdb3b983dc9c3d7042d72e1981e344d226c6789a3237e184262e5200000000c000200150000000000000015000000520065007400610069006c002000640065006d006f0020007300650072007600690063006500320000000000")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestChangeServiceConfigRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("0000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RChangeServiceConfigWRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.TagId != 0 {
		t.Fatalf("expected res.TagId==0, got %v", res.TagId)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestCloseServiceHandleReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000003465bbb8225f70429b86965ac6e618ea")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("000000003465bbb8225f70429b86965ac6e618ea")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RCloseServiceHandleReq{ServiceHandle: handle}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestCloseServiceHandleRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	res := RCloseServiceHandleRes{}
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ContextHandle != [20]byte{} {
		t.Fatal("Fail")
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestRCreateServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	var handle [20]byte
	handleBytes, err := hex.DecodeString("000000008a8940a6acf44c468919b58072337e12")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	displayName := "MiscSVC12"
	serviceStartName := `LocalSystem`
	req := RCreateServiceWReq{
		SCContextHandle:  handle,
		ServiceName:      "MiscSVC12",
		DisplayName:      &displayName,
		DesiredAccess:    0x000f01ff,
		ServiceType:      0x10,
		StartType:        3,
		ErrorControl:     0,
		BinaryPathName:   `C:\Windows\temp\onedrive.exe`,
		ServiceStartName: &serviceStartName,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("000000008a8940a6acf44c468919b58072337e120a000000000000000a0000004d00690073006300530056004300310032000000000002000a000000000000000a0000004d00690073006300530056004300310032000000ff010f001000000003000000000000001d000000000000001d00000043003a005c00570069006e0064006f00770073005c00740065006d0070005c006f006e006500640072006900760065002e006500780065000000000000000000000000000000000000000000040002000c000000000000000c0000004c006f00630061006c00530079007300740065006d0000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestCreateServiceRes(t *testing.T) {
	pkt, err := hex.DecodeString("0000000000000000e3c4f2041118194eac6a622c8bb6f66c00000000")
	// Simple test to verify that the packet structure is valid
	if err != nil {
		t.Fatal(err)
	}

	var expectedHandle [20]byte
	handleBytes, err := hex.DecodeString("00000000e3c4f2041118194eac6a622c8bb6f66c")
	if err != nil {
		t.Fatal(err)
	}
	copy(expectedHandle[:], handleBytes)

	res := RCreateServiceWRes{}
	err = res.Unmarshal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.TagId != 0 {
		t.Fatalf("expected res.TagId==0, got %v", res.TagId)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}

	if res.ContextHandle != expectedHandle {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", res.ContextHandle, expectedHandle)
	}
}

func TestDeleteServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("0000000038a391b8157fcd4198346c9d4d5d4706")
	if err != nil {
		t.Fatal(err)
	}

	var handle [20]byte
	handleBytes, err := hex.DecodeString("0000000038a391b8157fcd4198346c9d4d5d4706")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RDeleteServiceReq{
		ServiceHandle: handle,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestParseServiceDescription(t *testing.T) {
	// WOW64-format SERVICE_DESCRIPTION_WOW64 with description "Test Service"
	desc := "Test Service"
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(4)) // DescriptionOffset = 4 (right after this field)
	buf.Write(msdtyp.ToUnicode(desc))                 // UTF-16LE string data

	result, err := parseServiceDescription(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result != desc {
		t.Fatalf("expected %q, got %q", desc, result)
	}
}

func TestParseServiceDescriptionNull(t *testing.T) {
	// Empty buffer means no description
	result, err := parseServiceDescription([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestParseServiceDescriptionEmpty(t *testing.T) {
	result, err := parseServiceDescription([]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if result != "" {
		t.Fatalf("expected empty string, got %q", result)
	}
}

func TestParseDelayedAutoStartInfo(t *testing.T) {
	bufTrue := []byte{0x01, 0x00, 0x00, 0x00}
	result, err := parseDelayedAutoStartInfo(bufTrue)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true, got false")
	}

	bufFalse := []byte{0x00, 0x00, 0x00, 0x00}
	result, err = parseDelayedAutoStartInfo(bufFalse)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false, got true")
	}
}

func TestParseFailureActionsFlag(t *testing.T) {
	bufTrue := []byte{0x01, 0x00, 0x00, 0x00}
	result, err := parseFailureActionsFlag(bufTrue)
	if err != nil {
		t.Fatal(err)
	}
	if !result {
		t.Fatal("expected true, got false")
	}

	bufFalse := []byte{0x00, 0x00, 0x00, 0x00}
	result, err = parseFailureActionsFlag(bufFalse)
	if err != nil {
		t.Fatal(err)
	}
	if result {
		t.Fatal("expected false, got true")
	}
}

func TestParseServiceSIDInfo(t *testing.T) {
	buf := []byte{0x01, 0x00, 0x00, 0x00}
	result, err := parseServiceSIDInfo(buf)
	if err != nil {
		t.Fatal(err)
	}
	if result != ServiceSidTypeUnrestricted {
		t.Fatalf("expected %d, got %d", ServiceSidTypeUnrestricted, result)
	}
}

func TestParsePreshutdownInfo(t *testing.T) {
	// Timeout = 180000 ms (0x0002BF20)
	buf := []byte{0x20, 0xBF, 0x02, 0x00}
	result, err := parsePreshutdownInfo(buf)
	if err != nil {
		t.Fatal(err)
	}
	if result != 180000 {
		t.Fatalf("expected 180000, got %d", result)
	}
}

func TestParsePreferredNode(t *testing.T) {
	// PreferredNode = 3, Delete = true
	buf := []byte{0x03, 0x00, 0x01}
	result, err := parsePreferredNode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if result.PreferredNode != 3 {
		t.Fatalf("expected PreferredNode=3, got %d", result.PreferredNode)
	}
	if !result.Delete {
		t.Fatal("expected Delete=true, got false")
	}

	// PreferredNode = 0, Delete = false
	buf2 := []byte{0x00, 0x00, 0x00}
	result2, err := parsePreferredNode(buf2)
	if err != nil {
		t.Fatal(err)
	}
	if result2.PreferredNode != 0 {
		t.Fatalf("expected PreferredNode=0, got %d", result2.PreferredNode)
	}
	if result2.Delete {
		t.Fatal("expected Delete=false, got true")
	}
}

func TestParseFailureActions(t *testing.T) {
	rebootMsg := msdtyp.ToUnicode("Rebooting\x00")
	command := msdtyp.ToUnicode("cmd /c restart.bat\x00")

	// WOW64 format: header is serviceFailureActionsWOW64Buf (5 x uint32 = 20 bytes)
	// Then data at the specified offsets
	rebootMsgOffset := uint32(20)
	commandOffset := rebootMsgOffset + uint32(len(rebootMsg))
	actionsOffset := commandOffset + uint32(len(command))

	buf := &bytes.Buffer{}
	// Header (serviceFailureActionsWOW64Buf)
	binary.Write(buf, binary.LittleEndian, uint32(86400))   // ResetPeriod
	binary.Write(buf, binary.LittleEndian, rebootMsgOffset) // RebootMsgOffset
	binary.Write(buf, binary.LittleEndian, commandOffset)   // CommandOffset
	binary.Write(buf, binary.LittleEndian, uint32(2))       // CActions
	binary.Write(buf, binary.LittleEndian, actionsOffset)   // ActionsOffset

	// Data at RebootMsgOffset
	buf.Write(rebootMsg)

	// Data at CommandOffset
	buf.Write(command)

	// Data at ActionsOffset: 2 x SCAction (Type uint32, Delay uint32)
	binary.Write(buf, binary.LittleEndian, uint32(ScActionRestart))
	binary.Write(buf, binary.LittleEndian, uint32(60000))
	binary.Write(buf, binary.LittleEndian, uint32(ScActionRunCommand))
	binary.Write(buf, binary.LittleEndian, uint32(120000))

	result, err := parseFailureActions(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result.ResetPeriod != 86400 {
		t.Fatalf("expected ResetPeriod=86400, got %d", result.ResetPeriod)
	}
	if *result.RebootMsg != "Rebooting" {
		t.Fatalf("expected RebootMsg=%q, got %q", "Rebooting", *result.RebootMsg)
	}
	if *result.Command != "cmd /c restart.bat" {
		t.Fatalf("expected Command=%q, got %q", "cmd /c restart.bat", *result.Command)
	}
	if len(result.Actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(result.Actions))
	}
	if result.Actions[0].Type != ScActionRestart || result.Actions[0].Delay != 60000 {
		t.Fatalf("action[0]: expected {RESTART, 60000}, got {%d, %d}", result.Actions[0].Type, result.Actions[0].Delay)
	}
	if result.Actions[1].Type != ScActionRunCommand || result.Actions[1].Delay != 120000 {
		t.Fatalf("action[1]: expected {RUN_COMMAND, 120000}, got {%d, %d}", result.Actions[1].Type, result.Actions[1].Delay)
	}
}

func TestParseFailureActionsNullStrings(t *testing.T) {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(0)) // ResetPeriod
	binary.Write(buf, binary.LittleEndian, uint32(0)) // RebootMsgOffset = 0 (null)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // CommandOffset = 0 (null)
	binary.Write(buf, binary.LittleEndian, uint32(0)) // CActions
	binary.Write(buf, binary.LittleEndian, uint32(0)) // ActionsOffset = 0 (null)

	result, err := parseFailureActions(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if result.ResetPeriod != 0 {
		t.Fatalf("expected ResetPeriod=0, got %d", result.ResetPeriod)
	}
	if result.RebootMsg != nil {
		t.Fatalf("expected nil RebootMsg, got %q", *result.RebootMsg)
	}
	if result.Command != nil {
		t.Fatalf("expected nil Command, got %q", *result.Command)
	}
	if len(result.Actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(result.Actions))
	}
}

func TestParseRequiredPrivileges(t *testing.T) {
	// WOW64 format: RequiredPrivilegesOffset (uint32) + MULTI_SZ data at offset
	// MULTI_SZ: "SeBackupPrivilege\0SeRestorePrivilege\0\0"
	multiSz := msdtyp.ToUnicode("SeBackupPrivilege\x00SeRestorePrivilege\x00\x00")

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, uint32(4)) // RequiredPrivilegesOffset = 4 (right after this field)
	buf.Write(multiSz)

	result, err := parseRequiredPrivileges(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 privileges, got %d: %v", len(result), result)
	}
	if result[0] != "SeBackupPrivilege" {
		t.Fatalf("expected result[0]=%q, got %q", "SeBackupPrivilege", result[0])
	}
	if result[1] != "SeRestorePrivilege" {
		t.Fatalf("expected result[1]=%q, got %q", "SeRestorePrivilege", result[1])
	}
}

func TestParseRequiredPrivilegesNull(t *testing.T) {
	buf := []byte{0x00, 0x00, 0x00, 0x00}
	result, err := parseRequiredPrivileges(buf)
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Fatalf("expected nil, got %v", result)
	}
}

func strPtr(s string) *string { return &s }

func TestChangeServiceConfig2DescriptionNonEmpty(t *testing.T) {
	desc := "A"
	req := RChangeServiceConfig2WReq{
		Info: ConfigInfoW{
			InfoLevel:   ServiceConfigDescription,
			Description: &ServiceDescriptionW{Description: strPtr(desc)},
		},
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Skip 20-byte service handle
	data := buf[20:]
	// InfoLevel (4) + UnionDiscriminator (4) + ptr to ServiceDescriptionW (4) +
	// ptr to Description string (4) + MaxCount (4) + Offset (4) + ActualCount (4) +
	// "A\0" in UTF-16LE = 0x41,0x00,0x00,0x00
	expected := []byte{
		0x01, 0x00, 0x00, 0x00, // InfoLevel = 1 (ServiceConfigDescription)
		0x01, 0x00, 0x00, 0x00, // Union discriminator
		0x00, 0x00, 0x02, 0x00, // Ptr to ServiceDescriptionW (referent ID)
		0x04, 0x00, 0x02, 0x00, // Ptr to Description string (referent ID)
		0x02, 0x00, 0x00, 0x00, // MaxCount = 2 ('A' + null)
		0x00, 0x00, 0x00, 0x00, // Offset = 0
		0x02, 0x00, 0x00, 0x00, // ActualCount = 2
		0x41, 0x00, 0x00, 0x00, // 'A' + null in UTF-16LE
	}
	if !bytes.Equal(data, expected) {
		t.Fatalf("non-empty description mismatch\ngot:    %x\nexpect: %x", data, expected)
	}
}

func TestChangeServiceConfig2DescriptionEmpty(t *testing.T) {
	empty := ""
	req := RChangeServiceConfig2WReq{
		Info: ConfigInfoW{
			InfoLevel:   ServiceConfigDescription,
			Description: &ServiceDescriptionW{Description: &empty},
		},
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	data := buf[20:]
	// Empty string with null terminator: MaxCount=1, Offset=0, ActualCount=1, data=0x00,0x00 + 2 pad
	expected := []byte{
		0x01, 0x00, 0x00, 0x00, // InfoLevel = 1
		0x01, 0x00, 0x00, 0x00, // Union discriminator
		0x00, 0x00, 0x02, 0x00, // Ptr to ServiceDescriptionW
		0x04, 0x00, 0x02, 0x00, // Ptr to Description string (non-null)
		0x01, 0x00, 0x00, 0x00, // MaxCount = 1 (null terminator only)
		0x00, 0x00, 0x00, 0x00, // Offset = 0
		0x01, 0x00, 0x00, 0x00, // ActualCount = 1
		0x00, 0x00, 0x00, 0x00, // Null char in UTF-16LE + 2 pad bytes
	}
	if !bytes.Equal(data, expected) {
		t.Fatalf("empty description mismatch\ngot:    %x\nexpect: %x", data, expected)
	}
}

func TestChangeServiceConfig2DescriptionNil(t *testing.T) {
	req := RChangeServiceConfig2WReq{
		Info: ConfigInfoW{
			InfoLevel:   ServiceConfigDescription,
			Description: &ServiceDescriptionW{Description: nil},
		},
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	data := buf[20:]
	// Nil string pointer: null pointer (0x00000000), no deferred data
	expected := []byte{
		0x01, 0x00, 0x00, 0x00, // InfoLevel = 1
		0x01, 0x00, 0x00, 0x00, // Union discriminator
		0x00, 0x00, 0x02, 0x00, // Ptr to ServiceDescriptionW
		0x00, 0x00, 0x00, 0x00, // Null pointer for Description string
	}
	if !bytes.Equal(data, expected) {
		t.Fatalf("nil description mismatch\ngot:    %x\nexpect: %x", data, expected)
	}
}

func TestQueryServiceObjectSecurityReq(t *testing.T) {
	var handle [20]byte
	handleBytes, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	req := RQueryServiceObjectSecurityReq{
		ServiceHandle:       handle,
		SecurityInformation: DaclSecurityInformation,
		BufSize:             0,
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// handle(20) + SecurityInformation(0x04) + BufSize(0)
	expected, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f0400000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, expected) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, expected)
	}
}

func TestQueryServiceObjectSecurityRes(t *testing.T) {
	sd := []byte{0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00}
	// max_count(8) + SD(8, already 4-aligned) + BytesNeeded(8) + ErrorCode(0)
	resPkt, err := hex.DecodeString("08000000" + "0100048014000000" + "08000000" + "00000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RQueryServiceObjectSecurityRes{}
	if err = res.Unmarshal(resPkt); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.SecurityDescriptor, sd) {
		t.Fatalf("SecurityDescriptor mismatch\n got:  %x\n want: %x", res.SecurityDescriptor, sd)
	}
	if res.BytesNeeded != 8 {
		t.Fatalf("expected BytesNeeded==8, got %d", res.BytesNeeded)
	}
	if res.ErrorCode != ErrorSuccess {
		t.Fatalf("expected ErrorCode==0, got %d", res.ErrorCode)
	}
}

func TestSetServiceObjectSecurityReq(t *testing.T) {
	var handle [20]byte
	handleBytes, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}
	copy(handle[:], handleBytes)

	sd := []byte{0x01, 0x00, 0x04, 0x80, 0x14, 0x00, 0x00, 0x00}
	req := RSetServiceObjectSecurityReq{
		ServiceHandle:       handle,
		SecurityInformation: DaclSecurityInformation,
		SecurityDescriptor:  sd,
		BufSize:             uint32(len(sd)),
	}
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// handle(20) + SecurityInformation(0x04) + max_count(8, inline) + SD(8) + BufSize(8)
	expected, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f" + "04000000" + "08000000" + "0100048014000000" + "08000000")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, expected) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, expected)
	}
}
