// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
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
package mssrvs

import (
	"encoding/hex"
	"testing"
)

func TestNetShareEnumAllReq(t *testing.T) {
	req := NewNetShareEnumAllRequest("WIN2K19")

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip test: unmarshal what we just marshaled
	var req2 NetShareEnumAllRequest
	err = req2.Unmarshal(buf)
	if err != nil {
		t.Fatal(err)
	}

	if req2.ServerName == nil || *req2.ServerName != "WIN2K19" {
		t.Fatalf("expected ServerName==WIN2K19, got %v", req2.ServerName)
	}
	if req2.InfoStruct.Level != 1 {
		t.Fatalf("expected Level==1, got %v", req2.InfoStruct.Level)
	}
	if req2.MaxBuffer != 0xffffffff {
		t.Fatalf("expected MaxBuffer==0xffffffff, got %v", req2.MaxBuffer)
	}
}

func TestNetShareEnumAllRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("01000000010000000000020005000000040002000500000008000200000000800c00020010000200000000801400020018000200030000801c00020020000200000000002400020028000200000000802c000200070000000000000007000000410044004d0049004e002400000000000d000000000000000d000000520065006d006f00740065002000410064006d0069006e000000000003000000000000000300000043002400000000000e000000000000000e000000440065006600610075006c00740020007300680061007200650000000500000000000000050000004900500043002400000000000b000000000000000b000000520065006d006f00740065002000490050004300000000000200000000000000020000005a000000010000000000000001000000000000000300000000000000030000005a002400000000000e000000000000000e000000440065006600610075006c007400200073006800610072006500000005000000300002000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	var res NetShareEnumAllResponse
	err = res.Unmarshal(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.InfoStruct.Level != 1 {
		t.Fatalf("expected res.InfoStruct.Level==1, got %v", res.InfoStruct.Level)
	}

	ctr1 := res.InfoStruct.Level1
	if ctr1 == nil {
		t.Fatal("expected non-nil Level1 container")
	}

	if ctr1.EntriesRead != 5 {
		t.Fatalf("expected ctr1.EntriesRead==5, got %v", ctr1.EntriesRead)
	}

	if ctr1.Buffer[0].Type != StypeDisktree|StypeSpecial {
		t.Fatalf("expected ctr1.Buffer[0].Type==StypeDisktree|StypeSpecial, got %v", ctr1.Buffer[0].Type)
	}

	if ctr1.Buffer[0].Name != "ADMIN$" {
		t.Fatalf("expected ctr1.Buffer[0].Name==ADMIN$, got %v", ctr1.Buffer[0].Name)
	}

	if ctr1.Buffer[0].Comment != "Remote Admin" {
		t.Fatalf("expected ctr1.Buffer[0].Comment==Remote Admin, got %v", ctr1.Buffer[0].Comment)
	}

	if ctr1.Buffer[1].Type != StypeDisktree|StypeSpecial {
		t.Fatalf("expected ctr1.Buffer[1].Type==StypeDisktree|StypeSpecial, got %v", ctr1.Buffer[1].Type)
	}

	if ctr1.Buffer[1].Name != "C$" {
		t.Fatalf("expected ctr1.Buffer[1].Name==C$, got %v", ctr1.Buffer[1].Name)
	}

	if ctr1.Buffer[1].Comment != "Default share" {
		t.Fatalf("expected ctr1.Buffer[1].Comment==Default share, got %v", ctr1.Buffer[1].Comment)
	}

	if ctr1.Buffer[2].Type != StypeIPC|StypeSpecial {
		t.Fatalf("expected ctr1.Buffer[2].Type==StypeIPC|StypeSpecial, got %v", ctr1.Buffer[2].Type)
	}

	if ctr1.Buffer[2].Name != "IPC$" {
		t.Fatalf("expected ctr1.Buffer[2].Name==IPC$, got %v", ctr1.Buffer[2].Name)
	}

	if ctr1.Buffer[2].Comment != "Remote IPC" {
		t.Fatalf("expected ctr1.Buffer[2].Comment==Remote IPC, got %v", ctr1.Buffer[2].Comment)
	}

	if ctr1.Buffer[3].Type != StypeDisktree {
		t.Fatalf("expected ctr1.Buffer[3].Type==StypeDisktree, got %v", ctr1.Buffer[3].Type)
	}

	if ctr1.Buffer[3].Name != "Z" {
		t.Fatalf("expected ctr1.Buffer[3].Name==Z, got %v", ctr1.Buffer[3].Name)
	}

	if ctr1.Buffer[3].Comment != "" {
		t.Fatalf("expected ctr1.Buffer[3].Comment==, got %v", ctr1.Buffer[3].Comment)
	}

	if ctr1.Buffer[4].Type != StypeDisktree|StypeSpecial {
		t.Fatalf("expected ctr1.Buffer[4].Type==StypeDisktree|StypeSpecial, got %v", ctr1.Buffer[4].Type)
	}

	if ctr1.Buffer[4].Name != "Z$" {
		t.Fatalf("expected ctr1.Buffer[4].Name==Z$, got %v", ctr1.Buffer[4].Name)
	}

	if ctr1.Buffer[4].Comment != "Default share" {
		t.Fatalf("expected ctr1.Buffer[4].Comment==Default share, got %v", ctr1.Buffer[4].Comment)
	}

	if res.TotalEntries != 5 {
		t.Fatalf("expected res.TotalEntries==5, got %v", res.TotalEntries)
	}

	if res.ResumeHandle == nil || *res.ResumeHandle != 0 {
		t.Fatalf("expected res.ResumeHandle==0, got %v", res.ResumeHandle)
	}

	if res.WindowsError != 0 {
		t.Fatalf("expected res.WindowsError==0, got %v", res.WindowsError)
	}
}

func TestNetServerInfoReq(t *testing.T) {
	req := NewNetServerGetInfoRequest("", 102)

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip test
	var req2 NetServerGetInfoRequest
	err = req2.Unmarshal(buf)
	if err != nil {
		t.Fatal(err)
	}

	if req2.Level != 102 {
		t.Fatalf("expected Level==102, got %v", req2.Level)
	}
}

func TestNetServerInfoRes(t *testing.T) {
	pkt, err := hex.DecodeString("6600000000000200f4010000040002000a000000000000000390000008000200000000010f000000000000003c000000b80b0000000000000c000200080000000000000008000000570049004e0032004b003100390000000100000000000000010000000000000004000000000000000400000063003a005c00000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var res NetServerGetInfoResponse
	err = res.Unmarshal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.WindowsError != 0 {
		t.Fatalf("expected res.WindowsError==0, got %v", res.WindowsError)
	}

	if res.Info.Level != 102 {
		t.Fatalf("expected res.Info.Level==102, got %v", res.Info.Level)
	}

	ptr := res.Info.Level102
	if ptr == nil {
		t.Fatal("expected non-nil Level102")
	}

	if ptr.PlatformId != 500 {
		t.Fatalf("expected ptr.PlatformId==500, got %v", ptr.PlatformId)
	}

	if ptr.VersionMajor != 10 {
		t.Fatalf("expected ptr.VersionMajor==10, got %v", ptr.VersionMajor)
	}

	if ptr.VersionMinor != 0 {
		t.Fatalf("expected ptr.VersionMinor==0, got %v", ptr.VersionMinor)
	}

	if ptr.SvType != 0x9003 {
		t.Fatalf("expected ptr.SvType==0x9003, got %v", ptr.SvType)
	}

	if ptr.Users != 16777216 {
		t.Fatalf("expected ptr.Users==16777216, got %v", ptr.Users)
	}

	if ptr.Disc != 15 {
		t.Fatalf("expected ptr.Disc==15, got %v", ptr.Disc)
	}

	if ptr.Hidden != 0 {
		t.Fatalf("expected ptr.Hidden==0, got %v", ptr.Hidden)
	}

	if ptr.Announce != 60 {
		t.Fatalf("expected ptr.Announce==60, got %v", ptr.Announce)
	}

	if ptr.Anndelta != 3000 {
		t.Fatalf("expected ptr.Anndelta==3000, got %v", ptr.Anndelta)
	}

	if ptr.Licences != 0 {
		t.Fatalf("expected ptr.Licences==0, got %v", ptr.Licences)
	}

	if ptr.Name != "WIN2K19" {
		t.Fatalf("expected ptr.Name==WIN2K19, got %v", ptr.Name)
	}

	if ptr.Comment != "" {
		t.Fatalf("expected ptr.Comment==, got %v", ptr.Comment)
	}

	if ptr.Userpath != "c:\\" {
		t.Fatalf("expected ptr.Userpath==c:\\, got %v", ptr.Userpath)
	}
}

func TestNetSessionEnumReq(t *testing.T) {
	req := NewNetSessionEnumRequest("", "", 10)

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip test: unmarshal what we just marshaled
	var req2 NetSessionEnumRequest
	err = req2.Unmarshal(buf)
	if err != nil {
		t.Fatal(err)
	}

	if req2.Info.Level != 10 {
		t.Fatalf("expected Level==10, got %v", req2.Info.Level)
	}
	if req2.PreferredMaxLength != 0xffffffff {
		t.Fatalf("expected PreferredMaxLength==0xffffffff, got %v", req2.PreferredMaxLength)
	}
	if req2.ResumeHandle == nil || *req2.ResumeHandle != 0 {
		t.Fatalf("expected ResumeHandle==0, got %v", req2.ResumeHandle)
	}
}

func TestNetSessionEnumRes(t *testing.T) {
	pkt, err := hex.DecodeString("0a0000000a00000000000200010000000400020001000000080002000c00020002000000000000001100000000000000110000005c005c003100300030002e003100300030002e003100300030002e0035003100000000000e000000000000000e000000610064006d0069006e006900730074007200610074006f007200000001000000100002000700000000000000")
	if err != nil {
		t.Fatal(err)
	}

	var res NetSessionEnumResponse
	err = res.Unmarshal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.WindowsError != 0 {
		t.Fatalf("expected res.WindowsError==0, got %v", res.WindowsError)
	}

	if res.Info.Level != 10 {
		t.Fatalf("expected res.Info.Level==10, got %v", res.Info.Level)
	}

	ctr10 := res.Info.Level10
	if ctr10 == nil {
		t.Fatal("expected non-nil Level10 container")
	}

	if ctr10.EntriesRead != 1 {
		t.Fatalf("expected ctr10.EntriesRead==1, got %v", ctr10.EntriesRead)
	}

	if ctr10.Buffer[0].Cname != "\\\\100.100.100.51" {
		t.Fatalf("expected ctr10.Buffer[0].Cname==\\\\100.100.100.51, got %v", ctr10.Buffer[0].Cname)
	}

	if ctr10.Buffer[0].Username != "administrator" {
		t.Fatalf("expected ctr10.Buffer[0].Username==administrator, got %v", ctr10.Buffer[0].Username)
	}

	if ctr10.Buffer[0].Time != 2 {
		t.Fatalf("expected ctr10.Buffer[0].Time==2, got %v", ctr10.Buffer[0].Time)
	}

	if ctr10.Buffer[0].IdleTime != 0 {
		t.Fatalf("expected ctr10.Buffer[0].IdleTime==0, got %v", ctr10.Buffer[0].IdleTime)
	}
}
