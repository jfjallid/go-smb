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
	"bytes"
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

func TestNetShareEnumAllReqExt(t *testing.T) {
	for _, level := range []uint32{1, 501, 502} {
		req := NewNetShareEnumAllRequestExt("WIN2K19", level)
		buf, err := req.Marshal()
		if err != nil {
			t.Fatalf("level %d marshal: %v", level, err)
		}

		var req2 NetShareEnumAllRequest
		if err := req2.Unmarshal(buf); err != nil {
			t.Fatalf("level %d unmarshal: %v", level, err)
		}
		if req2.InfoStruct.Level != level {
			t.Fatalf("expected Level==%d, got %d", level, req2.InfoStruct.Level)
		}
		switch level {
		case 1:
			if req2.InfoStruct.Level1 == nil {
				t.Fatalf("level 1: expected non-nil Level1 container")
			}
		case 501:
			if req2.InfoStruct.Level501 == nil {
				t.Fatalf("level 501: expected non-nil Level501 container")
			}
		case 502:
			if req2.InfoStruct.Level502 == nil {
				t.Fatalf("level 502: expected non-nil Level502 container")
			}
		}
	}
}

func TestNetShareEnumAll501Res(t *testing.T) {
	resume := uint32(0)
	res := NetShareEnumAllResponse{
		InfoStruct: ShareEnumStruct{
			Level: 501,
			Level501: &ShareInfoContainer501{
				EntriesRead: 2,
				Buffer: []ShareInfo501{
					{Name: "ADMIN$", Type: StypeDisktree | StypeSpecial, Comment: "Remote Admin", Flags: 0x10},
					{Name: "share", Type: StypeDisktree, Comment: "", Flags: 0},
				},
			},
		},
		TotalEntries: 2,
		ResumeHandle: &resume,
		WindowsError: 0,
	}

	buf, err := res.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got NetShareEnumAllResponse
	if err := got.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}

	if got.InfoStruct.Level != 501 {
		t.Fatalf("expected Level==501, got %d", got.InfoStruct.Level)
	}
	ctr := got.InfoStruct.Level501
	if ctr == nil {
		t.Fatal("expected non-nil Level501 container")
	}
	if ctr.EntriesRead != 2 || len(ctr.Buffer) != 2 {
		t.Fatalf("expected 2 entries, got EntriesRead=%d len=%d", ctr.EntriesRead, len(ctr.Buffer))
	}
	if ctr.Buffer[0].Name != "ADMIN$" || ctr.Buffer[0].Comment != "Remote Admin" || ctr.Buffer[0].Flags != 0x10 {
		t.Fatalf("entry 0 mismatch: %+v", ctr.Buffer[0])
	}
	if ctr.Buffer[0].Type != StypeDisktree|StypeSpecial {
		t.Fatalf("entry 0 Type mismatch: %x", ctr.Buffer[0].Type)
	}
	if ctr.Buffer[1].Name != "share" || ctr.Buffer[1].Comment != "" || ctr.Buffer[1].Flags != 0 {
		t.Fatalf("entry 1 mismatch: %+v", ctr.Buffer[1])
	}
}

func TestNetShareEnumAll502Res(t *testing.T) {
	// Minimal valid empty self-relative security descriptor (revision 1,
	// SE_SELF_RELATIVE, all offsets zero).
	sd := []byte{
		0x01, 0x00, 0x00, 0x80, // Revision, Sbz1, Control(0x8000)
		0x00, 0x00, 0x00, 0x00, // OffsetOwner
		0x00, 0x00, 0x00, 0x00, // OffsetGroup
		0x00, 0x00, 0x00, 0x00, // OffsetSacl
		0x00, 0x00, 0x00, 0x00, // OffsetDacl
	}
	resume := uint32(0)
	res := NetShareEnumAllResponse{
		InfoStruct: ShareEnumStruct{
			Level: 502,
			Level502: &ShareInfoContainer502{
				EntriesRead: 2,
				Buffer: []ShareInfo502{
					{
						Name: "C$", Type: StypeDisktree | StypeSpecial, Comment: "Default share",
						Permissions: 0, MaxUses: 0xffffffff, CurrentUses: 1,
						Path: "C:\\", Passwd: "",
						Reserved: uint32(len(sd)), SecurityDescriptor: sd,
					},
					{
						// Null SD path (Reserved==0, SecurityDescriptor nil) exercises
						// the fullpointer NULL encode/decode branch.
						Name: "data", Type: StypeDisktree, Comment: "",
						Permissions: 0, MaxUses: 10, CurrentUses: 0,
						Path: "D:\\data", Passwd: "",
						Reserved: 0, SecurityDescriptor: nil,
					},
				},
			},
		},
		TotalEntries: 2,
		ResumeHandle: &resume,
		WindowsError: 0,
	}

	buf, err := res.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got NetShareEnumAllResponse
	if err := got.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}

	if got.InfoStruct.Level != 502 {
		t.Fatalf("expected Level==502, got %d", got.InfoStruct.Level)
	}
	ctr := got.InfoStruct.Level502
	if ctr == nil {
		t.Fatal("expected non-nil Level502 container")
	}
	if ctr.EntriesRead != 2 || len(ctr.Buffer) != 2 {
		t.Fatalf("expected 2 entries, got EntriesRead=%d len=%d", ctr.EntriesRead, len(ctr.Buffer))
	}

	e0 := ctr.Buffer[0]
	if e0.Name != "C$" || e0.Comment != "Default share" || e0.Path != "C:\\" {
		t.Fatalf("entry 0 strings mismatch: %+v", e0)
	}
	if e0.MaxUses != 0xffffffff || e0.CurrentUses != 1 {
		t.Fatalf("entry 0 uses mismatch: %+v", e0)
	}
	if e0.Reserved != uint32(len(sd)) || !bytes.Equal(e0.SecurityDescriptor, sd) {
		t.Fatalf("entry 0 SD mismatch: reserved=%d sd=%x", e0.Reserved, e0.SecurityDescriptor)
	}

	e1 := ctr.Buffer[1]
	if e1.Name != "data" || e1.Path != "D:\\data" {
		t.Fatalf("entry 1 strings mismatch: %+v", e1)
	}
	if e1.Reserved != 0 || len(e1.SecurityDescriptor) != 0 {
		t.Fatalf("entry 1 expected nil SD, got reserved=%d sd=%x", e1.Reserved, e1.SecurityDescriptor)
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

// minimal valid empty self-relative security descriptor used by several tests.
var emptySD = []byte{
	0x01, 0x00, 0x00, 0x80, // Revision, Sbz1, Control(0x8000)
	0x00, 0x00, 0x00, 0x00, // OffsetOwner
	0x00, 0x00, 0x00, 0x00, // OffsetGroup
	0x00, 0x00, 0x00, 0x00, // OffsetSacl
	0x00, 0x00, 0x00, 0x00, // OffsetDacl
}

func TestNetShareGetInfoReq(t *testing.T) {
	req := NewNetShareGetInfoRequest("WIN2K19", "C$", 502)
	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got NetShareGetInfoRequest
	if err := got.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if got.ServerName == nil || *got.ServerName != "WIN2K19" {
		t.Fatalf("expected ServerName==WIN2K19, got %v", got.ServerName)
	}
	if got.NetName != "C$" {
		t.Fatalf("expected NetName==C$, got %q", got.NetName)
	}
	if got.Level != 502 {
		t.Fatalf("expected Level==502, got %d", got.Level)
	}
}

func TestNetShareGetInfoRes(t *testing.T) {
	cases := []struct {
		name string
		info ShareInfoUnion
	}{
		{"level0", ShareInfoUnion{Level: 0, Level0: &ShareInfo0{Name: "C$"}}},
		{"level1", ShareInfoUnion{Level: 1, Level1: &ShareInfo1{
			Name: "C$", Type: StypeDisktree | StypeSpecial, Comment: "Default share"}}},
		{"level2", ShareInfoUnion{Level: 2, Level2: &ShareInfo2{
			Name: "C$", Type: StypeDisktree | StypeSpecial, Comment: "Default share",
			MaxUses: 0xffffffff, CurrentUses: 1, Path: "C:\\", Passwd: ""}}},
		{"level501", ShareInfoUnion{Level: 501, Level501: &ShareInfo501{
			Name: "C$", Type: StypeDisktree | StypeSpecial, Comment: "Default share", Flags: 0x10}}},
		{"level502", ShareInfoUnion{Level: 502, Level502: &ShareInfo502{
			Name: "C$", Type: StypeDisktree | StypeSpecial, Comment: "Default share",
			MaxUses: 0xffffffff, CurrentUses: 1, Path: "C:\\",
			Reserved: uint32(len(emptySD)), SecurityDescriptor: emptySD}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := NetShareGetInfoResponse{Info: tc.info, WindowsError: 0}
			buf, err := res.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var got NetShareGetInfoResponse
			if err := got.Unmarshal(buf); err != nil {
				t.Fatal(err)
			}
			if got.Info.Level != tc.info.Level {
				t.Fatalf("expected Level==%d, got %d", tc.info.Level, got.Info.Level)
			}
			switch tc.info.Level {
			case 0:
				if got.Info.Level0 == nil || got.Info.Level0.Name != "C$" {
					t.Fatalf("level0 mismatch: %+v", got.Info.Level0)
				}
			case 1:
				g := got.Info.Level1
				if g == nil || g.Name != "C$" || g.Comment != "Default share" ||
					g.Type != StypeDisktree|StypeSpecial {
					t.Fatalf("level1 mismatch: %+v", g)
				}
			case 2:
				g := got.Info.Level2
				if g == nil || g.Name != "C$" || g.Path != "C:\\" ||
					g.MaxUses != 0xffffffff || g.CurrentUses != 1 {
					t.Fatalf("level2 mismatch: %+v", g)
				}
			case 501:
				g := got.Info.Level501
				if g == nil || g.Name != "C$" || g.Flags != 0x10 {
					t.Fatalf("level501 mismatch: %+v", g)
				}
			case 502:
				g := got.Info.Level502
				if g == nil || g.Name != "C$" || g.Path != "C:\\" ||
					!bytes.Equal(g.SecurityDescriptor, emptySD) {
					t.Fatalf("level502 mismatch: %+v", g)
				}
			}
		})
	}
}

func TestNetShareSetInfoReq(t *testing.T) {
	cases := []struct {
		name  string
		level uint32
		info  ShareInfoUnion
		check func(t *testing.T, got *NetShareSetInfoRequest)
	}{
		{
			name:  "comment1004",
			level: 1004,
			info:  ShareInfoUnion{Level1004: &ShareInfo1004{Comment: "new comment"}},
			check: func(t *testing.T, got *NetShareSetInfoRequest) {
				if got.ShareInfo.Level1004 == nil || got.ShareInfo.Level1004.Comment != "new comment" {
					t.Fatalf("1004 mismatch: %+v", got.ShareInfo.Level1004)
				}
			},
		},
		{
			name:  "flags1005",
			level: 1005,
			info:  ShareInfoUnion{Level1005: &ShareInfo1005{Flags: 0x30}},
			check: func(t *testing.T, got *NetShareSetInfoRequest) {
				if got.ShareInfo.Level1005 == nil || got.ShareInfo.Level1005.Flags != 0x30 {
					t.Fatalf("1005 mismatch: %+v", got.ShareInfo.Level1005)
				}
			},
		},
		{
			name:  "sd1501",
			level: 1501,
			info:  ShareInfoUnion{Level1501: &ShareInfo1501{Reserved: uint32(len(emptySD)), SecurityDescriptor: emptySD}},
			check: func(t *testing.T, got *NetShareSetInfoRequest) {
				g := got.ShareInfo.Level1501
				if g == nil || g.Reserved != uint32(len(emptySD)) || !bytes.Equal(g.SecurityDescriptor, emptySD) {
					t.Fatalf("1501 mismatch: %+v", g)
				}
			},
		},
		{
			name:  "full502",
			level: 502,
			info: ShareInfoUnion{Level502: &ShareInfo502{
				Name: "share", Type: StypeDisktree, Comment: "c", MaxUses: 5, Path: "D:\\data"}},
			check: func(t *testing.T, got *NetShareSetInfoRequest) {
				g := got.ShareInfo.Level502
				if g == nil || g.Name != "share" || g.Path != "D:\\data" || g.MaxUses != 5 {
					t.Fatalf("502 mismatch: %+v", g)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info := tc.info
			info.Level = tc.level
			server := "WIN2K19"
			parm := uint32(0)
			req := NetShareSetInfoRequest{
				ServerName: &server,
				NetName:    "share",
				Level:      tc.level,
				ShareInfo:  info,
				ParmErr:    &parm,
			}
			buf, err := req.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			var got NetShareSetInfoRequest
			if err := got.Unmarshal(buf); err != nil {
				t.Fatal(err)
			}
			if got.Level != tc.level {
				t.Fatalf("expected request Level==%d, got %d", tc.level, got.Level)
			}
			if got.ShareInfo.Level != tc.level {
				t.Fatalf("expected union Level==%d, got %d", tc.level, got.ShareInfo.Level)
			}
			tc.check(t, &got)
		})
	}
}

func TestNetServerDiskEnumRes(t *testing.T) {
	drives := []string{"A:", "C:", "D:"}
	buffer := make([]DiskInfo, len(drives))
	for i, d := range drives {
		buffer[i] = DiskInfo{Disk: d}
	}
	resume := uint32(0)
	res := NetServerDiskEnumResponse{
		DiskInfo: DiskEnumContainer{
			EntriesRead: uint32(len(buffer)),
			Buffer:      buffer,
		},
		TotalEntries: uint32(len(buffer)),
		ResumeHandle: &resume,
		WindowsError: 0,
	}
	buf, err := res.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got NetServerDiskEnumResponse
	if err := got.Unmarshal(buf); err != nil {
		t.Fatal(err)
	}
	if got.TotalEntries != 3 {
		t.Fatalf("expected TotalEntries==3, got %d", got.TotalEntries)
	}
	if len(got.DiskInfo.Buffer) != 3 {
		t.Fatalf("expected 3 disk entries, got %d", len(got.DiskInfo.Buffer))
	}
	for i, d := range drives {
		if name := got.DiskInfo.Buffer[i].Disk; name != d {
			t.Fatalf("entry %d: expected %q, got %q", i, d, name)
		}
	}
}

// Captured NetrServerDiskEnum response from a Windows Server 2022 DC with a
// single C: drive. DISK_INFO.Disk is a [string] field, so every entry carries
// an offset/actual-count pair ahead of its UTF-16 data; decoding it as three
// bare WCHARs slides the rest of the stub and reads TotalEntries as the return
// code. A round-trip test cannot catch that, so pin the real bytes.
var netServerDiskEnumGolden = []byte{
	0x02, 0x00, 0x00, 0x00, // DiskInfo.EntriesRead = 2
	0x00, 0x00, 0x02, 0x00, // DiskInfo.Buffer referent id
	0x02, 0x00, 0x00, 0x00, // MaxCount = 2
	0x00, 0x00, 0x00, 0x00, // Offset = 0
	0x02, 0x00, 0x00, 0x00, // ActualCount = 2
	0x00, 0x00, 0x00, 0x00, // [0] Disk offset = 0
	0x03, 0x00, 0x00, 0x00, // [0] Disk actual count = 3
	0x43, 0x00, 0x3a, 0x00, // [0] "C:"
	0x00, 0x00, // [0] null terminator
	0x00, 0x00, // pad to 4
	0x00, 0x00, 0x00, 0x00, // [1] Disk offset = 0
	0x01, 0x00, 0x00, 0x00, // [1] Disk actual count = 1
	0x00, 0x00, // [1] "" (terminator only)
	0x00, 0x00, // pad to 4
	0x01, 0x00, 0x00, 0x00, // TotalEntries = 1
	0x04, 0x00, 0x02, 0x00, // ResumeHandle referent id
	0x00, 0x00, 0x00, 0x00, // ResumeHandle = 0
	0x00, 0x00, 0x00, 0x00, // WindowsError = ERROR_SUCCESS
}

func TestNetServerDiskEnumResGolden(t *testing.T) {
	var got NetServerDiskEnumResponse
	if err := got.Unmarshal(netServerDiskEnumGolden); err != nil {
		t.Fatal(err)
	}
	if got.WindowsError != ErrorSuccess {
		t.Fatalf("expected WindowsError==0, got 0x%08x", got.WindowsError)
	}
	if got.TotalEntries != 1 {
		t.Fatalf("expected TotalEntries==1, got %d", got.TotalEntries)
	}
	if got.ResumeHandle == nil || *got.ResumeHandle != 0 {
		t.Fatalf("expected ResumeHandle==0, got %v", got.ResumeHandle)
	}
	if got.DiskInfo.EntriesRead != 2 {
		t.Fatalf("expected EntriesRead==2, got %d", got.DiskInfo.EntriesRead)
	}
	want := []string{"C:", ""}
	if len(got.DiskInfo.Buffer) != len(want) {
		t.Fatalf("expected %d disk entries, got %d", len(want), len(got.DiskInfo.Buffer))
	}
	for i, w := range want {
		if got.DiskInfo.Buffer[i].Disk != w {
			t.Fatalf("entry %d: expected %q, got %q", i, w, got.DiskInfo.Buffer[i].Disk)
		}
	}

	// Re-encoding the decoded response must reproduce the captured stub.
	buf, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, netServerDiskEnumGolden) {
		t.Fatalf("re-encoded stub differs from capture:\n got %x\nwant %x", buf, netServerDiskEnumGolden)
	}
}
