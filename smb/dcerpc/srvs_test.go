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
package dcerpc

import (
	"bytes"
	"encoding/hex"

	"github.com/jfjallid/go-smb/smb/encoder"

	"testing"
)

func TestNetServerInfoReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
    pkt, err := hex.DecodeString("0000000066000000")
	if err != nil {
		t.Fatal(err)
	}


	req := NetServerGetInfoRequest{
        ServerName: nil,
        Level: 102,
    }

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestNetServerInfoRes(t *testing.T) {
    pkt, err := hex.DecodeString("6600000000000200f4010000040002000a000000000000000390000008000200000000010f000000000000003c000000b80b0000000000000c000200080000000000000008000000570049004e0032004b003100390000000100000000000000010000000000000004000000000000000400000063003a005c00000000000000")
	// Simple test to verify that the packet structure is valid
	if err != nil {
		t.Fatal(err)
	}

    res := NetServerGetInfoResponse{Info: &NetServerInfo{},}
	err = encoder.Unmarshal(pkt, &res)
	if err != nil {
		t.Fatal(err)
	}

    if res.WindowsError != 0 {
        t.Error("Fail")
    }

    if res.Info.Level != 102 {
        t.Error("Fail")
    }

    ptr := res.Info.Pointer.(*NetServerInfo102)

    if ptr.platformId != 500 {
        t.Error("Fail")
    }
    name, err := encoder.FromUnicodeString(ptr.name.EncodedString)
	if err != nil {
        t.Fatal(err)
	}
    comment, err := encoder.FromUnicodeString(ptr.comment.EncodedString)
	if err != nil {
        t.Fatal(err)
	}
    userpath, err := encoder.FromUnicodeString(ptr.userpath.EncodedString)
	if err != nil {
        t.Fatal(err)
	}

    if ptr.versionMajor != 10 {
        t.Fatal(err)
    }

    if ptr.versionMinor != 0 {
        t.Fatal(err)
    }

    if ptr.svType != 0x9003 {
        t.Fatal(err)
    }

    if ptr.users != 16777216 {
        t.Fatal(err)
    }

    if ptr.disc != 15 {
        t.Fatal(err)
    }

    if ptr.hidden != 0 {
        t.Fatal(err)
    }

    if ptr.announce != 60 {
        t.Fatal(err)
    }

    if ptr.anndelta != 3000 {
        t.Fatal(err)
    }

    if ptr.licences != 0 {
        t.Fatal(err)
    }

    if name != "WIN2K19\x00" {
        t.Error("Fail")
    }

    if comment != "\x00" {
        t.Error("Fail")
    }

    if userpath != "c:\\\x00" {
        t.Error("Fail")
    }
}

func TestNetSessionEnumReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
    pkt, err := hex.DecodeString("0000000000000000000000000a0000000a000000010000000000000000000000ffffffff0300000000000000")
	if err != nil {
		t.Fatal(err)
	}


	req := NetSessionEnumRequest{
        ServerName: nil,
        ClientName: nil,
        UserName: nil,
        Info: SessionEnum{
            Level: 10,
            SessionInfo: SessionInfoContainer10{
                EntriesRead: 0,
                Buffer: nil,
            },

        },
        PreferredMaxLength: 4294967295,
        ResumeHandle: ResumeHandle{ReferentId: 3},
    }

	buf, err := req.MarshalBinary(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Error("Fail")
	}
}

func TestNetSessionEnumRes(t *testing.T) {
    pkt, err := hex.DecodeString("0a0000000a00000000000200010000000400020001000000080002000c00020002000000000000001100000000000000110000005c005c003100300030002e003100300030002e003100300030002e0035003100000000000e000000000000000e000000610064006d0069006e006900730074007200610074006f007200000001000000100002000700000000000000")
	// Simple test to verify that the packet structure is valid
	if err != nil {
		t.Fatal(err)
	}

    res := NetSessionEnumResponse{}
	err = encoder.Unmarshal(pkt, &res)
	if err != nil {
		t.Fatal(err)
	}

    if res.WindowsError != 0 {
        t.Error("Fail")
    }

    if res.Info.Level != 10 {
        t.Error("Fail")
    }

    ptr := res.Info.SessionInfo.(*SessionInfoContainer10)

    if ptr.EntriesRead != 1 {
        t.Fatal("Fail")
    }
    
    clientName, err := encoder.FromUnicodeString(ptr.Buffer[0].Cname.EncodedString)
	if err != nil {
        t.Fatal(err)
	}

    userName, err := encoder.FromUnicodeString(ptr.Buffer[0].Username.EncodedString)
	if err != nil {
        t.Fatal(err)
	}

    if ptr.Buffer[0].Time != 2 {
        t.Fatal(err)
    }

    if ptr.Buffer[0].IdleTime != 0 {
        t.Fatal(err)
    }

    if clientName != "\\\\100.100.100.51\x00" {
        t.Error("Fail")
    }

    if userName != "administrator\x00" {
        t.Error("Fail")
    }
}
