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
package dcerpc

import (
	"bytes"
	"encoding/hex"

	"github.com/jfjallid/go-smb/smb/encoder"

	"testing"
)

func TestBindReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("05000b0310000000480000004204cb9ab810b81000000000010000000000010081bb7a364498f135ad3298f03800100302000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}

	req, err := NewBindReq(2596996162, "367abb81-9844-35f1-ad32-98f038001003", 2, 0, "8a885d04-1ceb-11c9-9fe8-08002b104860")
	if err != nil {
		t.Fatal(err)
	}

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestBindRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("05000c0310000000440000004204cb9ab810b810d75400000d005c706970655c6e747376637300000100000000000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}
	var res BindRes = NewBindRes()
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.MajorVersion != 5 {
		t.Error("Fail")
	}

	if res.Flags != 3 {
		t.Error("Fail")
	}

	if res.Representation != 16 {
		t.Error("Fail")
	}

	if res.FragLength != 68 {
		t.Error("Fail")
	}

	if res.CallId != 2596996162 {
		t.Error("Fail")
	}

	if res.MaxRecvFragSize != 4280 {
		t.Error("Fail")
	}

	if res.MaxSendFragSize != 4280 {
		t.Error("Fail")
	}

	if res.Association != 0x000054d7 {
		t.Error("Fail")
	}

	if res.SecAddrLen != 13 {
		t.Error("Fail")
	}

	if !bytes.Equal(res.SecAddr, []byte("\\pipe\\ntsvcs\x00")) {
		t.Error("Fail")
	}

	if res.CtxCount != 1 {
		t.Error("Fail")
	}
	var items ContextResItems = *res.Context

	if items[0].Result != 0 {
		t.Error("Fail")
	}

	ndr, err := hex.DecodeString("045d888aeb1cc9119fe808002b104860")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(items[0].TransferUUID, ndr) {
		t.Error("Fail")
	}

	if items[0].TransferVersion != 2 {
		t.Error("Fail")
	}
}

func TestNetShareEnumAllReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("000002001100000000000000110000004400450053004b0054004f0050002d0041004900470030004300310044003200000000000100000001000000020000000000000000000000ffffffff0800020000000000")
	if err != nil {
		t.Fatal(err)
	}

	req := NewNetShareEnumAllRequest("DESKTOP-AIG0C1D2")

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestNetShareEnumAllRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("01000000010000000000020005000000040002000500000008000200000000800c00020010000200000000801400020018000200030000801c00020020000200000000002400020028000200000000002c000200070000000000000007000000410044004d0049004e002400000000000d000000000000000d000000520065006d006f00740065002000410064006d0069006e000000000003000000000000000300000043002400000000000e000000000000000e000000440065006600610075006c00740020007300680061007200650000000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f00740065002000490050004300000000000900000000000000090000006d00790066006f006c0064006500720000000000010000000000000001000000000000000600000000000000060000005500730065007200730000000100000000000000010000000000000005000000300002000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	res := NetShareEnumAllResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.Level != 1 {
		t.Error("Fail")
	}

	if res.NetShareCtr.Ctr != 1 {
		t.Error("Fail")
	}

	ctr1 := res.NetShareCtr.Pointer.(*NetShareCtr1)

	if ctr1.Count != 5 {
		t.Error("Fail")
	}

	if ctr1.Info.MaxCount != 5 {
		t.Error("Fail")
	}

	if ctr1.Pointer[0].Type != StypeDisktree|StypeSpecial {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[0].Name.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "ADMIN$\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[0].Comment.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "Remote Admin\x00" {
		t.Error("Fail")
	}

	if ctr1.Pointer[1].Type != StypeDisktree|StypeSpecial {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[1].Name.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "C$\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[1].Comment.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "Default share\x00" {
		t.Error("Fail")
	}

	if ctr1.Pointer[2].Type != StypeIPC|StypeSpecial {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[2].Name.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "IPC$\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[2].Comment.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "Remote IPC\x00" {
		t.Error("Fail")
	}

	if ctr1.Pointer[3].Type != StypeDisktree {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[3].Name.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "myfolder\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[3].Comment.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "\x00" {
		t.Error("Fail")
	}

	if ctr1.Pointer[4].Type != StypeDisktree {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[4].Name.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "Users\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(ctr1.Pointer[4].Comment.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "\x00" {
		t.Error("Fail")
	}

	if res.TotalEntries != 5 {
		t.Error("Fail")
	}

	if res.ResumeHandle.Handle != 0 {
		t.Error("Fail")
	}

	if res.WindowsError != 0 {
		t.Error("Fail")
	}
}

func TestOpenSCManagerReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("01000000060000000000000006000000440055004d004d0059000000020000000f000000000000000f000000530065007200760069006300650073004100630074006900760065000000000004000000")
	if err != nil {
		t.Fatal(err)
	}

	req := ROpenSCManagerWRequest{
		MachineName:   *NewUnicodeStr(1, "DUMMY"),
		DatabaseName:  *NewUnicodeStr(2, "ServicesActive"),
		DesiredAccess: 4,
	}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	res := ROpenSCManagerWResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle, handle) {
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
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

	req := ROpenServiceWRequest{
		SCContextHandle: handle,
		ServiceName:     NewUnicodeStr(0, "RemoteRegistry"),
		DesiredAccess:   4,
	}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	res := ROpenServiceWResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle, handle) {
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}

func TestGetServiceStatusReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("00000000a970d760f2288746b4cbc8b8ea21e2b8")
	if err != nil {
		t.Fatal(err)
	}

	req := RQueryServiceStatusRequest{ContextHandle: handle}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestGetServiceStatusRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("3000000004000000010000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RQueryServiceStatusResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.ServiceType != ServiceWin32OwnProcess|ServiceWin32ShareProcess {
		t.Error("Fail")
	}

	if res.CurrentState != ServiceRunning {
		t.Error("Fail")
	}

	if res.ControlsAccepted != ServiceControlStop {
		t.Error("Fail")
	}

	if res.Win32ExitCode != 0 {
		t.Error("Fail")
	}

	if res.ServiceSpecificExitCode != 0 {
		t.Error("Fail")
	}

	if res.CheckPoint != 0 {
		t.Error("Fail")
	}

	if res.WaitHint != 0 {
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
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

	req := RStartServiceWRequest{
		ServiceHandle: handle,
		// When Argc is 0 I need to marshal 0x00000000 for Argc and same for Argv e.g., 4 bytes combined of 0s
		Argc: 0,
		Argv: make([]UnicodeStr, 0),
	}

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
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

	req := RControlServiceRequest{
		ServiceHandle: handle,
		Control:       ServiceControlStop,
	}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestControlServiceRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("3000000003000000010000002a0400000000000003000000b80b000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RControlServiceResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.ServiceType != ServiceWin32OwnProcess|ServiceWin32ShareProcess {
		t.Error("Fail")
	}

	if res.CurrentState != ServiceStopPending {
		t.Error("Fail")
	}

	if res.ControlsAccepted != ServiceControlStop {
		t.Error("Fail")
	}

	if res.Win32ExitCode != 0x042a {
		t.Error("Fail")
	}

	if res.ServiceSpecificExitCode != 0 {
		t.Error("Fail")
	}

	if res.CheckPoint != 3 {
		t.Error("Fail")
	}

	if res.WaitHint != 0x0bb8 {
		t.Error("Fail")
	}

	if res.ReturnValue != 0 {
		t.Error("Fail")
	}
}

func TestGetServiceConfig(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000cab639200617fa49bb641d17f510390502010000")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("00000000cab639200617fa49bb641d17f5103905")
	if err != nil {
		t.Fatal(err)
	}

	req := RQueryServiceConfigWRequest{
		ServiceHandle: handle,
		BufSize:       258,
	}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestGetServiceConfigRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("200000000300000000000000000002000400020000000000080002000c000200100002002c000000000000002c00000043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e0065007800650020002d006b002000720064007800670072006f00750070000000010000000000000001000000000000000200000000000000020000002f0000000c000000000000000c0000004c006f00630061006c00530079007300740065006d000000140000000000000014000000520065007400610069006c002000440065006d006f002000530065007200760069006300650000000201000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RQueryServiceConfigWResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.ErrorCode != 0 {
		t.Error("Fail")
	}

	if res.BytesNeeded != 0x0102 {
		t.Error("Fail")
	}

	if res.ServiceConfig.ServiceType != ServiceWin32ShareProcess {
		t.Error("Fail")
	}

	if res.ServiceConfig.StartType != ServiceDemandStart {
		t.Error("Fail")
	}

	if res.ServiceConfig.ErrorControl != ServiceErrorIgnore {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(res.ServiceConfig.BinaryPathName.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "C:\\Windows\\System32\\svchost.exe -k rdxgroup\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(res.ServiceConfig.LoadOrderGroup.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "\x00" {
		t.Error("Fail")
	}

	if res.ServiceConfig.TagId != 0 {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(res.ServiceConfig.Dependencies.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "/\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(res.ServiceConfig.ServiceStartName.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "LocalSystem\x00" {
		t.Error("Fail")
	}

	if val, err := encoder.FromUnicodeString(res.ServiceConfig.DisplayName.EncodedString); err != nil {
		t.Error("Fail")
	} else if val != "Retail Demo Service\x00" {
		t.Error("Fail")
	}
}

func TestChangeServiceConfigReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("00000000dafba1738895c44798b2f490119e5084ffffffff04000000ffffffff010000002c000000000000002c00000043003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0073007600630068006f00730074002e0065007800650020002d006b002000720064007800670072006f0075007000000000000000000000000000000000000000020000000c000000000000000c0000004c006f00630061006c00530079007300740065006d000000000000000000000003000000150000000000000015000000520065007400610069006c002000440065006d006f0020005300650072007600690063006500320000000000")
	if err != nil {
		t.Fatal(err)
	}

	handle, err := hex.DecodeString("00000000dafba1738895c44798b2f490119e5084")
	if err != nil {
		t.Fatal(err)
	}

	req := RChangeServiceConfigWRequest{
		ServiceHandle:    handle,
		ServiceType:      ServiceNoChange,
		StartType:        ServiceDisabled,
		ErrorControl:     ServiceNoChange,
		BinaryPathName:   NewUnicodeStr(1, "C:\\Windows\\System32\\svchost.exe -k rdxgroup"),
		LoadOrderGroup:   nil,
		Dependencies:     nil,
		DependSize:       0,
		ServiceStartName: NewUnicodeStr(2, "LocalSystem"),
		Password:         nil,
		PwSize:           0,
		DisplayName:      NewUnicodeStr(3, "Retail Demo Service2"),
	}
	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestChangeServiceConfigRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("0000000000000000")
	if err != nil {
		t.Fatal(err)
	}

	res := RChangeServiceConfigWResponse{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.TagId != 0 {
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
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

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestCloseServiceHandleRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	res := RCloseServiceHandleRes{}
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ContextHandle, make([]byte, 20)) {
		t.Error("Fail")
	}

	if res.ReturnCode != 0 {
		t.Error("Fail")
	}
}
