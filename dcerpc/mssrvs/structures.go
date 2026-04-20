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

package mssrvs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/ndr"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

// Returned to clients calling the NetShareEnumAll request
type NetShare struct {
	Name    string
	Comment string
	Type    string
	TypeId  uint32
	Hidden  bool
}

type ShareInfo1 struct {
	Name    string `ndr:"pointer,conformant,varying"`
	Type    uint32
	Comment string `ndr:"pointer,conformant,varying"`
}

/*
	typedef struct _SHARE_INFO_1_CONTAINER {
	  DWORD EntriesRead;
	  [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
	} SHARE_INFO_1_CONTAINER;
*/
type ShareInfoContainer1 struct {
	EntriesRead uint32
	Buffer      []ShareInfo1 `ndr:"fullpointer,conformant"`
}

// ShareEnumStruct represents SHARE_ENUM_STRUCT (MS-SRVS 2.2.4.38)
// Non-encapsulated union: Level is written twice on the wire
type ShareEnumStruct struct {
	Level  uint32               `ndr:"unionTag"`
	Level1 *ShareInfoContainer1 `ndr:"unionField,pointer"`
}

func (u ShareEnumStruct) SwitchFunc(tag interface{}) string {
	t := tag.(uint32)
	switch t {
	case 1:
		return "Level1"
	}
	return ""
}

type NetShareEnumAllRequest struct {
	ServerName   *string         `ndr:"toplevel,fullpointer,conformant,varying"`
	InfoStruct   ShareEnumStruct `ndr:"toplevel"`
	MaxBuffer    uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
}

type NetShareEnumAllResponse struct {
	InfoStruct   ShareEnumStruct `ndr:"toplevel"`
	TotalEntries uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
	WindowsError uint32
}

// SESSION_INFO_0 — MS-SRVS 2.2.4.10
type NetSessionInfo0 struct {
	Cname string `ndr:"pointer,conformant,varying"`
}

// SESSION_INFO_10 — MS-SRVS 2.2.4.4
type NetSessionInfo10 struct {
	Cname    string `ndr:"pointer,conformant,varying"`
	Username string `ndr:"pointer,conformant,varying"`
	Time     uint32
	IdleTime uint32
}

// SESSION_INFO_502 — MS-SRVS 2.2.4.8
type NetSessionInfo502 struct {
	Cname     string `ndr:"pointer,conformant,varying"`
	Username  string `ndr:"pointer,conformant,varying"`
	NumOpens  uint32
	Time      uint32
	IdleTime  uint32
	UserFlags uint32
	ClType    string `ndr:"pointer,conformant,varying"`
	Transport string `ndr:"pointer,conformant,varying"`
}

type SessionInfoContainer0 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo0 `ndr:"fullpointer,conformant"`
}

type SessionInfoContainer10 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo10 `ndr:"fullpointer,conformant"`
}

type SessionInfoContainer502 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo502 `ndr:"fullpointer,conformant"`
}

// SESSION_ENUM_STRUCT — non-encapsulated union (Level written twice on wire)
type SessionEnumStruct struct {
	Level    uint32                   `ndr:"unionTag"`
	Level0   *SessionInfoContainer0   `ndr:"unionField,pointer"`
	Level10  *SessionInfoContainer10  `ndr:"unionField,pointer"`
	Level502 *SessionInfoContainer502 `ndr:"unionField,pointer"`
}

func (u SessionEnumStruct) SwitchFunc(tag interface{}) string {
	t := tag.(uint32)
	switch t {
	case 0:
		return "Level0"
	case 10:
		return "Level10"
	case 502:
		return "Level502"
	}
	return ""
}

// NET_API_STATUS
// NetrSessionEnum (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in,string,unique] WCHAR * ClientName,
// [in,string,unique] WCHAR * UserName,
// [in,out] PSESSION_ENUM_STRUCT InfoStruct,
// [in] DWORD PreferedMaximumLength,
// [out] DWORD * TotalEntries,
// [in,out,unique] DWORD * ResumeHandle
// );
type NetSessionEnumRequest struct {
	ServerName         *string           `ndr:"toplevel,fullpointer,conformant,varying"`
	ClientName         *string           `ndr:"toplevel,fullpointer,conformant,varying"`
	UserName           *string           `ndr:"toplevel,fullpointer,conformant,varying"`
	Info               SessionEnumStruct `ndr:"toplevel"`
	PreferredMaxLength uint32
	ResumeHandle       *uint32 `ndr:"toplevel,fullpointer"`
}

type NetSessionEnumResponse struct {
	Info         SessionEnumStruct `ndr:"toplevel"`
	TotalEntries uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
	WindowsError uint32
}

// SERVER_INFO_100 — MS-SRVS 2.2.4.40
type NetServerInfo100 struct {
	PlatformId uint32
	Name       string `ndr:"pointer,conformant,varying"`
}

// SERVER_INFO_101 — MS-SRVS 2.2.4.41
type NetServerInfo101 struct {
	PlatformId   uint32
	Name         string `ndr:"pointer,conformant,varying"`
	VersionMajor uint32
	VersionMinor uint32
	SvType       uint32
	Comment      string `ndr:"pointer,conformant,varying"`
}

// SERVER_INFO_102 — MS-SRVS 2.2.4.42
type NetServerInfo102 struct {
	PlatformId   uint32
	Name         string `ndr:"pointer,conformant,varying"`
	VersionMajor uint32
	VersionMinor uint32
	SvType       uint32
	Comment      string `ndr:"pointer,conformant,varying"`
	Users        uint32
	Disc         int32
	Hidden       uint32
	Announce     uint32
	Anndelta     uint32
	Licences     uint32
	Userpath     string `ndr:"pointer,conformant,varying"`
}

// SERVER_INFO — encapsulated union (discriminator written once)
type ServerInfoUnion struct {
	Level    uint32            `ndr:"unionTag,encapsulated"`
	Level100 *NetServerInfo100 `ndr:"unionField,pointer"`
	Level101 *NetServerInfo101 `ndr:"unionField,pointer"`
	Level102 *NetServerInfo102 `ndr:"unionField,pointer"`
}

func (u ServerInfoUnion) SwitchFunc(tag interface{}) string {
	t := tag.(uint32)
	switch t {
	case 100:
		return "Level100"
	case 101:
		return "Level101"
	case 102:
		return "Level102"
	}
	return ""
}

// NET_API_STATUS
// NetrServerGetInfo (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in] DWORD Level,
// [out, switch_is(Level)] LPSERVER_INFO InfoStruct
// );
type NetServerGetInfoRequest struct {
	ServerName *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Level      uint32
}

type NetServerGetInfoResponse struct {
	Info         ServerInfoUnion `ndr:"toplevel"`
	WindowsError uint32
}

type AdtSecurityDescriptor struct {
	Length uint32
	Buffer []byte `ndr:"pointer,conformant"`
}

//typedef struct _ADT_SECURITY_DESCRIPTOR {
//DWORD Length;
//[size_is(Length)] unsigned char* Buffer;
//} ADT_SECURITY_DESCRIPTOR,
//*PADT_SECURITY_DESCRIPTOR;

// MS-SRVS Opnum 39
type NetrpGetFileSecurityReq struct {
	ServerName           string `ndr:"toplevel,fullpointer,conformant,varying"`
	ShareName            string `ndr:"toplevel,fullpointer,conformant,varying"`
	FileName             string `ndr:"toplevel,conformant,varying"`
	RequestedInformation uint32
}

// DWORD NetrpGetFileSecurity(
// [in, string, unique] SRVSVC_HANDLE ServerName,
// [in, string, unique] WCHAR* ShareName,
// [in, string] WCHAR* lpFileName,
// [in] SECURITY_INFORMATION RequestedInformation,
// [out] PADT_SECURITY_DESCRIPTOR* SecurityDescriptor
// );
// MS-SRVS Opnum 39
type NetrpGetFileSecurityRes struct {
	SecurityDescriptor AdtSecurityDescriptor `ndr:"toplevel,fullpointer"`
	WindowsError       uint32
}

func (s *NetServerGetInfoRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetServerGetInfoRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetServerGetInfoRequest: %v", err)
	}
	return
}

func (s *NetServerGetInfoRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerGetInfoRequest: %v", err)
	}
	return nil
}

func (s *NetServerGetInfoResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetServerGetInfoResponse: %v", err)
	}
	return
}

func (s *NetServerGetInfoResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetServerGetInfoResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerGetInfoResponse: %v", err)
	}
	return nil
}

func (s *NetSessionEnumRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetSessionEnumRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetSessionEnumRequest: %v", err)
	}
	return
}

func (s *NetSessionEnumRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetSessionEnumRequest: %v", err)
	}
	return nil
}

func (s *NetSessionEnumResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetSessionEnumResponse: %v", err)
	}
	return
}

func (s *NetSessionEnumResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetSessionEnumResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetSessionEnumResponse: %v", err)
	}
	return nil
}

func (s *NetrpGetFileSecurityReq) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetrpGetFileSecurityReq: %v", err)
	}
	return
}

func (s *NetrpGetFileSecurityReq) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(s)
	if err != nil {
		err = fmt.Errorf("error unmarshaling NetrpGetFileSecurityReq: %v", err)
	}
	return
}

func (s *NetrpGetFileSecurityRes) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetrpGetFileSecurityRes: %v", err)
	}
	return
}

func (s *NetrpGetFileSecurityRes) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(s)
	if err != nil {
		err = fmt.Errorf("error unmarshaling NetrpGetFileSecurityRes: %v", err)
	}
	return
}

func (s *NetShareEnumAllRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetShareEnumAllRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareEnumAllRequest: %v", err)
	}
	return
}

func (s *NetShareEnumAllRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareEnumAllRequest: %v", err)
	}
	return nil
}

func (s *NetShareEnumAllResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareEnumAllResponse: %v", err)
	}
	return
}

func (s *NetShareEnumAllResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetShareEnumAllResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareEnumAllResponse: %v", err)
	}
	return nil
}
