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

package mswkst

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/mswkst")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidWksSvc                = "6BFFD098-A112-3610-9833-46C3F87E345A"
	MSRPCWksSvcPipe                = "wkssvc"
	MSRPCWksSvcMajorVersion uint16 = 1
	MSRPCWksSvcMinorVersion uint16 = 0
)

// MSRPC Workstation Service Remote (wkssvc) Operations
const (
	WksSvcWkstaUserEnum uint16 = 2
)

// MS-WKST Section 2.2.5.14
const (
	WkstaUserEnumInfoLevel0 uint32 = 0
	WkstaUserEnumInfoLevel1 uint32 = 1
)

const WkstaMaxPreferredLength uint32 = 0xFFFFFFFF

const (
	ErrorSuccess          uint32 = 0x0   // The operation completed successfully
	ErrorAccessDenied     uint32 = 0x5   // Access is denied
	ErrorInvalidParameter uint32 = 0x57  // One of the function parameters is not valid.
	ErrorInvalidLevel     uint32 = 0x7c  // The information level is invalid.
	ErrorMoreData         uint32 = 0xea  // More entries are available. The UserInfo buffer was not large enough to contain all the entries.
	ErrorBufTooSmall      uint32 = 0x84b // More entries are available. The TransportInfo buffer was not large enough to contain all the entries.
)

var ResponseCodeMap = map[uint32]error{
	ErrorSuccess:          fmt.Errorf("The operation completed successfully"),
	ErrorAccessDenied:     fmt.Errorf("Access is denied"),
	ErrorInvalidParameter: fmt.Errorf("One of the function parameters is not valid."),
	ErrorInvalidLevel:     fmt.Errorf("The information level is invalid."),
	ErrorMoreData:         fmt.Errorf("More entries are available. The UserInfo buffer was not large enough to contain all the entries."),
	ErrorBufTooSmall:      fmt.Errorf("More entries are available. The TransportInfo buffer was not large enough to contain all the entries."),
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{sb}
}

func (sb *RPCCon) EnumWkstLoggedOnUsers(level int) (res WkstaUserEnumUnion, err error) {
	log.Debugln("In EnumWkstLoggedOnUsers")
	if level < 0 || level > 1 {
		return nil, fmt.Errorf("Only levels 0 and 1 are valid")
	}

	innerReq := NetWkstaUserEnumReq{
		ServerName:             "",
		UserInfo:               WkstaUserEnum{Level: uint32(level)},
		PreferredMaximumLength: WkstaMaxPreferredLength,
	}
	if level == 0 {
		innerReq.UserInfo.Data = &WkstaUserInfo0Container{}
	} else {
		innerReq.UserInfo.Data = &WkstaUserInfo1Container{}
	}
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(WksSvcWkstaUserEnum, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to WkstaUserEnum was too small. Expected at atleast 24 bytes")
	}

	var resp NetWkstaUserEnumRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	return resp.UserInfo.Data, err
}
