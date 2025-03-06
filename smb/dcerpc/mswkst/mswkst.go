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

package mswkst

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
	"io"
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

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{sb}
}

type WkstaUserInfo0 struct {
	Username string
}

type WkstaUserInfo1 struct {
	Username     string
	LogonDomain  string
	OtherDomains string
	LogonServer  string
}

type WkstaUserInfo0Container struct {
	EntriesRead uint32
	Buffer      []WkstaUserInfo0
}

type WkstaUserInfo1Container struct {
	EntriesRead uint32
	Buffer      []WkstaUserInfo1
}

/*
typedef struct _WKSTA_USER_ENUM_STRUCT {
unsigned long Level;
[switch_is(Level)] union _WKSTA_USER_ENUM_UNION {
[case(0)]
LPWKSTA_USER_INFO_0_CONTAINER Level0;
[case(1)]
LPWKSTA_USER_INFO_1_CONTAINER Level1;
[default] ;
} WkstaUserInfo;
} WKSTA_USER_ENUM_STRUCT,
*PWKSTA_USER_ENUM_STRUCT,
*LPWKSTA_USER_ENUM_STRUCT;
*/
type WkstaUserEnum struct {
	Level uint32
	Data  WkstaUserEnumUnion
}

type WkstaUserEnumUnion interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

/*
unsigned long NetrWkstaUserEnum(
[in, string, unique] WKSSVC_IDENTIFY_HANDLE ServerName,
[in, out] LPWKSTA_USER_ENUM_STRUCT UserInfo,
[in] unsigned long PreferredMaximumLength,
[out] unsigned long* TotalEntries,
[in, out, unique] unsigned long* ResumeHandle
);
*/

type NetWkstaUserEnumReq struct {
	ServerName             string //The server MUST ignore this parameter.
	UserInfo               WkstaUserEnum
	PreferredMaximumLength uint32
	ResumeHandle           uint32
}

type NetWkstaUserEnumRes struct {
	UserInfo     WkstaUserEnum
	TotalEntries uint32
	ResumeHandle uint32
	ReturnCode   uint32
}

func (self *NetWkstaUserEnumReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for NetWkstaUserEnumReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = dcerpc.WriteConformantVaryingStringPtr(w, self.ServerName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.ServerName != "" {
		refId++
	}

	buf, err := self.UserInfo.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	n, err := w.Write(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	if n != len(buf) {
		err = fmt.Errorf("Failed to marshal all %d bytes to byte buffer. Only wrote %d bytes", len(buf), n)
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PreferredMaximumLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *NetWkstaUserEnumReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetWkstaUserEnumReq")
}

func (self *NetWkstaUserEnumRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of NetWkstaUserEnumRes")
}

func (self *NetWkstaUserEnumRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for NetWkstaUserEnumRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for NetWkstaUserEnumRes")
	}
	r := bytes.NewReader(buf)

	// Begin by reading the fixed size fields
	_, err = r.Seek(-12, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.TotalEntries)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Server could return partial data even with the ErrorMoreData response
	// But skipping parse of that since I always request the max number of entries back
	if self.ReturnCode > 0 {
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown WKST return code for NetWkstaEnum response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	err = self.UserInfo.UnmarshalBinary(buf[:len(buf)-12])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *WkstaUserEnum) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for WkstaUserEnum")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Level)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if self.Data != nil {
		var buf []byte
		buf, err = self.Data.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}
		var n int
		n, err = w.Write(buf)
		if err != nil {
			log.Errorln(err)
			return
		}
		if n != len(buf) {
			err = fmt.Errorf("Failed to marshal all %d bytes to byte buffer. Only wrote %d bytes", len(buf), n)
			log.Errorln(err)
			return
		}
	} else {
		_, err = w.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (self *WkstaUserEnum) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for WkstaUserEnum")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for WkstaUserEnum")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.Level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch self.Level {
	case WkstaUserEnumInfoLevel0:
		var data WkstaUserInfo0Container
		err = data.UnmarshalBinary(buf[4:])
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Data = &data
	case WkstaUserEnumInfoLevel1:
		var data WkstaUserInfo1Container
		err = data.UnmarshalBinary(buf[4:])
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Data = &data
	default:
		err = fmt.Errorf("Unknown Level %d in WkstaUserEnum response structure", self.Level)
		log.Errorln(err)
		return
	}

	return
}

func (self *WkstaUserInfo0Container) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for WkstaUserInfo0Container")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, WkstaUserEnumInfoLevel0)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	// Encode refId
	err = binary.Write(w, le, uint32(1))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, self.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Nothing to encode in the request except for a null ptr
	err = binary.Write(w, le, []byte{0x0, 0x0, 0x0, 0x0}) // Null ptr
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.EntriesRead > 0 {
		return nil, fmt.Errorf("Not implemented support for specifying WkstaUserInfo0 array items")
	}

	return w.Bytes(), nil
}

func (self *WkstaUserInfo0Container) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for WkstaUserInfo0Container")
	if len(buf) < 16 {
		return fmt.Errorf("Buffer to small for WkstaUserInfo0Container")
	}
	r := bytes.NewReader(buf)

	// Skip union switch (level) and ref id ptr
	_, err = r.Seek(8, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ref id ptr, max count and all the ref id ptrs for the array items
	if self.EntriesRead > 0 {
		_, err = r.Seek(8+int64(self.EntriesRead*4), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	for i := 0; i < int(self.EntriesRead); i++ {
		s := ""
		if err != nil {
			log.Errorln(err)
			return
		}
		s, err = dcerpc.ReadConformantVaryingString(r)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		self.Buffer = append(self.Buffer, WkstaUserInfo0{Username: s})
	}

	return nil
}

func (self *WkstaUserInfo1Container) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for WkstaUserInfo1Container")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, WkstaUserEnumInfoLevel1)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	// Encode refId
	err = binary.Write(w, le, uint32(1))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, self.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Nothing to encode in the request except for a null ptr
	err = binary.Write(w, le, []byte{0x0, 0x0, 0x0, 0x0}) // Null ptr
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.EntriesRead > 0 {
		return nil, fmt.Errorf("Not implemented support for specifying WkstaUserInfo1 array items")
	}

	return w.Bytes(), nil
}

func (self *WkstaUserInfo1Container) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for WkstaUserInfo1Container")
	if len(buf) < 16 {
		return fmt.Errorf("Buffer to small for WkstaUserInfo1Container")
	}
	r := bytes.NewReader(buf)

	// Skip union switch (level) and ref id ptr
	_, err = r.Seek(8, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ref id ptr, max count and all the ref id ptrs for the array items
	if self.EntriesRead > 0 {
		_, err = r.Seek(8+int64(self.EntriesRead*4*4), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	for i := 0; i < int(self.EntriesRead); i++ {
		s0 := ""
		s0, err = dcerpc.ReadConformantVaryingString(r)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s1 := ""
		s1, err = dcerpc.ReadConformantVaryingString(r)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s2 := ""
		s2, err = dcerpc.ReadConformantVaryingString(r)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s3 := ""
		s3, err = dcerpc.ReadConformantVaryingString(r)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		self.Buffer = append(self.Buffer, WkstaUserInfo1{Username: s0, LogonDomain: s1, OtherDomains: s2, LogonServer: s3})
	}

	return nil
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
