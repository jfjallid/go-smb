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
	"encoding/hex"

	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/dcerpc"
)

func TestOpenSCManagerReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("01000000060000000000000006000000440055004d004d0059000000020000000f000000000000000f000000530065007200760069006300650073004100630074006900760065000000000004000000")
	if err != nil {
		t.Fatal(err)
	}

	req := ROpenSCManagerWReq{
		MachineName:   "DUMMY",
		DatabaseName:  "ServicesActive",
		DesiredAccess: 4,
	}
	buf, err := req.MarshalBinary()
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
	handle, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}

	res := ROpenSCManagerWRes{}
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle[:], handle) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", handle, res.ContextHandle[:])
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

	handle, err := hex.DecodeString("0000000062f36ea19f6ff849afa3d99d0f320b4f")
	if err != nil {
		t.Fatal(err)
	}

	req := ROpenServiceWReq{
		SCContextHandle: handle,
		ServiceName:     "RemoteRegistry",
		DesiredAccess:   4,
	}
	buf, err := req.MarshalBinary()
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
	handle, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}

	res := ROpenServiceWRes{}
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle, handle) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", handle, res.ContextHandle)
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

	handle, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}

	req := RQueryServiceStatusReq{ContextHandle: handle}
	buf, err := req.MarshalBinary()
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
	err = res.UnmarshalBinary(resPkt)
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

	handle, err := hex.DecodeString("000000008ed4ec88663ec14b98044c090f02b6b0")
	if err != nil {
		t.Fatal(err)
	}

	req := RStartServiceWReq{
		ServiceHandle: handle,
		Argc:          0,
	}

	buf, err := req.MarshalBinary()
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

	handle, err := hex.DecodeString("00000000e0496b495a835843af8e37808f55d3d5")
	if err != nil {
		t.Fatal(err)
	}

	req := RControlServiceReq{
		ServiceHandle: handle,
		Control:       ServiceControlStop,
	}
	buf, err := req.MarshalBinary()
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
	err = res.UnmarshalBinary(resPkt)
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

	handle, err := hex.DecodeString("00000000cab639200617fa49bb641d17f5103905")
	if err != nil {
		t.Fatal(err)
	}

	req := RQueryServiceConfigWReq{
		ServiceHandle: handle,
		BufSize:       258,
	}
	buf, err := req.MarshalBinary()
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
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ErrorCode != 0 {
		t.Fatalf("expected res.ErrorCode==0, got %v", res.ErrorCode)
	}

	if res.BytesNeeded != 0x0102 {
		t.Fatalf("expected res.BytesNeeded==0x0102, got %v", res.BytesNeeded)
	}

	if res.ServiceConfig.ServiceType != ServiceWin32ShareProcess {
		t.Fatalf("expected res.ServiceConfig.ServiceType==ServiceWin32ShareProcess, got %v", res.ServiceConfig.ServiceType)
	}

	if res.ServiceConfig.StartType != ServiceDemandStart {
		t.Fatalf("expected res.ServiceConfig.StartType==ServiceDemandStart, got %v", res.ServiceConfig.StartType)
	}

	if res.ServiceConfig.ErrorControl != ServiceErrorIgnore {
		t.Fatalf("expected res.ServiceConfig.ErrorControl==ServiceErrorIgnore, got %v", res.ServiceConfig.ErrorControl)
	}

	if res.ServiceConfig.BinaryPathName != "C:\\Windows\\System32\\svchost.exe -k rdxgroup" {
		t.Fatalf("expected res.ServiceConfig.BinaryPathName==C:\\Windows\\System32\\svchost.exe -k rdxgroup, got %v", res.ServiceConfig.BinaryPathName)
	}

	if res.ServiceConfig.LoadOrderGroup != "" {
		t.Fatalf("expected res.ServiceConfig.LoadOrderGroup==, got %v", res.ServiceConfig.LoadOrderGroup)
	}

	if res.ServiceConfig.TagId != 0 {
		t.Fatalf("expected res.ServiceConfig.TagId==0, got %v", res.ServiceConfig.TagId)
	}

	if res.ServiceConfig.Dependencies != "/" {
		t.Fatalf("expected res.ServiceConfig.Dependencies==/, got %v", res.ServiceConfig.Dependencies)
	}

	if res.ServiceConfig.ServiceStartName != "LocalSystem" {
		t.Fatalf("expected res.ServiceConfig.ServiceStartName==LocalSystem, got %v", res.ServiceConfig.ServiceStartName)
	}

	if res.ServiceConfig.DisplayName != "Retail Demo Service" {
		t.Fatalf("expected res.ServiceConfig.DisplayName==Retail Demo Service, got %v", res.ServiceConfig.DisplayName)
	}
}

func TestChangeServiceConfigReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000009b8a1554f3da95418cbe3c9f6be68d0bffffffff0400000000000000010000002c000000000000002c00000043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e0065007800650020002d006b002000720064007800670072006f0075007000000000000000000000000000000000000000020000001000000000000000100000002e005c00610064006d0069006e006900730074007200610074006f007200000003000000200000003e3af69cb90cdb3b983dc9c3d7042d72e1981e344d226c6789a3237e184262e52000000004000000150000000000000015000000520065007400610069006c002000640065006d006f0020007300650072007600690063006500320000000000")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("000000009b8a1554f3da95418cbe3c9f6be68d0b")
	if err != nil {
		t.Fatal(err)
	}

	sessionKey, err := hex.DecodeString("47780a2c2a3bb5890a0b70328790829d")
	if err != nil {
		t.Fatal(err)
	}

	req := RChangeServiceConfigWReq{
		ServiceHandle:    handle,
		ServiceType:      ServiceNoChange,
		StartType:        ServiceDisabled,
		ErrorControl:     ServiceErrorIgnore,
		BinaryPathName:   "C:\\Windows\\System32\\svchost.exe -k rdxgroup",
		LoadOrderGroup:   "",
		Dependencies:     "",
		DependSize:       0,
		ServiceStartName: ".\\administrator",
		DisplayName:      "Retail demo service2",
	}

	password := "secretpass"
	uncPassword := msdtyp.ToUnicode(password + "\x00")
	encPassword, err := dcerpc.EncryptSecretDes(sessionKey, uncPassword)
	if err != nil {
		t.Fatal(err)
	}
	req.Password = encPassword

	buf, err := req.MarshalBinary()
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
	err = res.UnmarshalBinary(resPkt)
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

	handle, err := hex.DecodeString("000000003465bbb8225f70429b86965ac6e618ea")
	if err != nil {
		t.Fatal(err)
	}

	req := RCloseServiceHandleReq{ServiceHandle: handle}

	buf, err := req.MarshalBinary()
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
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle, make([]byte, 20)) {
		t.Fatal("Fail")
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}
}

func TestRCreateServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000000008a8940a6acf44c468919b58072337e120a000000000000000a0000004d00690073006300530056004300310032000000010000000a000000000000000a0000004d00690073006300530056004300310032000000ff010f001000000003000000000000001d000000000000001d00000043003a005c00570069006e0064006f00770073005c00740065006d0070005c006f006e006500640072006900760065002e006500780065000000000000000000000000000000000000000000020000000c000000000000000c0000004c006f00630061006c00530079007300740065006d0000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("000000008a8940a6acf44c468919b58072337e12")
	if err != nil {
		t.Fatal(err)
	}

	req := RCreateServiceWReq{
		SCContextHandle:  handle,
		ServiceName:      "MiscSVC12",
		DisplayName:      "MiscSVC12",
		DesiredAccess:    0x000f01ff,
		ServiceType:      0x10,
		StartType:        3,
		ErrorControl:     0,
		BinaryPathName:   `C:\Windows\temp\onedrive.exe`,
		LoadOrderGroup:   "",
		TagId:            0,
		Dependencies:     "",
		DependSize:       0,
		ServiceStartName: `LocalSystem`,
		Password:         nil,
		PwSize:           0,
	}

	buf, err := req.MarshalBinary()
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

	handle, err := hex.DecodeString("00000000e3c4f2041118194eac6a622c8bb6f66c")
	if err != nil {
		t.Fatal(err)
	}

	res := RCreateServiceWRes{}
	err = res.UnmarshalBinary(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.TagId != 0 {
		t.Fatalf("expected res.TagId==0, got %v", res.TagId)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected res.ReturnCode==0, got %v", res.ReturnCode)
	}

	if !bytes.Equal(res.ContextHandle, handle) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", handle, res.ContextHandle)
	}
}

func TestDeleteServiceReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("0000000038a391b8157fcd4198346c9d4d5d4706")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("0000000038a391b8157fcd4198346c9d4d5d4706")
	if err != nil {
		t.Fatal(err)
	}

	req := RDeleteServiceReq{
		ServiceHandle: handle,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}
