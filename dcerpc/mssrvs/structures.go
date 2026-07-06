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
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/ndr"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

// Returned to clients calling the NetShareEnumAll request. The fields below
// Hidden are only populated by the higher enum levels (see NetShareEnumAllExt):
// Flags by level 501, and Permissions/MaxUses/CurrentUses/Path/SecurityDescriptor
// by level 502. They keep their zero values (and SecurityDescriptor is nil) for
// levels that do not carry them.
type NetShare struct {
	Name    string
	Comment string
	Type    string
	TypeId  uint32
	Hidden  bool
	// Higher-level fields:
	Flags              uint32                     // level 501
	Permissions        uint32                     // level 502
	MaxUses            uint32                     // level 502
	CurrentUses        uint32                     // level 502
	Path               string                     // level 502
	SecurityDescriptor *msdtyp.SecurityDescriptor // level 502 (nil if absent)
}

type ShareInfo1 struct {
	// Name and Comment are [unique]-style wchar_t* in MS-SRVS but are
	// modelled here as embedded ref pointers (always present). The
	// notnullptr tag tells the encoder to emit a non-null pointer to an
	// empty referent rather than rejecting empty Go strings — Windows
	// servers do return empty comments this way.
	Name    string `ndr:"pointer,conformant,varying,notnullptr"`
	Type    uint32
	Comment string `ndr:"pointer,conformant,varying,notnullptr"`
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

// SHARE_INFO_501 — MS-SRVS 2.2.4.23. Same shape as ShareInfo1 plus
// shi501_flags (CSC caching / access-based-enumeration flags), which is the
// one useful field SHARE_INFO_502_I does not carry.
type ShareInfo501 struct {
	Name    string `ndr:"pointer,conformant,varying,notnullptr"`
	Type    uint32
	Comment string `ndr:"pointer,conformant,varying,notnullptr"`
	Flags   uint32
}

// SHARE_INFO_502_I — MS-SRVS 2.2.4.26. The richest enum level: adds the
// on-disk path, permissions, connection counts and the share's security
// descriptor.
//
// Passwd and shi502_security_descriptor are NULL-able [unique] pointers
// (Windows always returns a NULL password, and a NULL security descriptor when
// shi502_reserved is 0), so they are tagged fullpointer — plain `pointer`
// would refuse to encode a zero value. NDR has no size_is tag; the conformant
// SD byte array carries its own max_count on the wire (cf. AdtSecurityDescriptor).
type ShareInfo502 struct {
	Name               string `ndr:"pointer,conformant,varying,notnullptr"`
	Type               uint32
	Comment            string `ndr:"pointer,conformant,varying,notnullptr"`
	Permissions        uint32
	MaxUses            uint32
	CurrentUses        uint32
	Path               string `ndr:"pointer,conformant,varying,notnullptr"`
	Passwd             string `ndr:"fullpointer,conformant,varying"`
	Reserved           uint32
	SecurityDescriptor []byte `ndr:"fullpointer,conformant"`
}

type ShareInfoContainer501 struct {
	EntriesRead uint32
	Buffer      []ShareInfo501 `ndr:"fullpointer,conformant"`
}

type ShareInfoContainer502 struct {
	EntriesRead uint32
	Buffer      []ShareInfo502 `ndr:"fullpointer,conformant"`
}

// SHARE_INFO_0 — MS-SRVS 2.2.4.22. Just the share name.
type ShareInfo0 struct {
	Name string `ndr:"pointer,conformant,varying,notnullptr"`
}

// SHARE_INFO_2 — MS-SRVS 2.2.4.24. Like ShareInfo502 minus the security
// descriptor, plus the (always-NULL on the wire) password. Passwd is a
// NULL-able [unique] pointer so it is tagged fullpointer.
type ShareInfo2 struct {
	Name        string `ndr:"pointer,conformant,varying,notnullptr"`
	Type        uint32
	Comment     string `ndr:"pointer,conformant,varying,notnullptr"`
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        string `ndr:"pointer,conformant,varying,notnullptr"`
	Passwd      string `ndr:"fullpointer,conformant,varying"`
}

// SHARE_INFO_1004 — MS-SRVS 2.2.4.29. A single settable field: the comment.
type ShareInfo1004 struct {
	Comment string `ndr:"pointer,conformant,varying,notnullptr"`
}

// SHARE_INFO_1005 — MS-SRVS 2.2.4.30. A single settable field: the share flags.
type ShareInfo1005 struct {
	Flags uint32
}

// SHARE_INFO_1501_I — MS-SRVS 2.2.4.34. A settable security descriptor.
// SecurityDescriptor is [size_is(Reserved)] so set Reserved == len(bytes) when
// building a request.
type ShareInfo1501 struct {
	Reserved           uint32
	SecurityDescriptor []byte `ndr:"pointer,conformant"`
}

// ShareInfoUnion represents SHARE_INFO (MS-SRVS 2.2.3.6), the switch_is(Level)
// union used by NetrShareGetInfo (response) and NetrShareSetInfo (request).
// Encapsulated: the discriminant is carried once by the union itself. For
// NetrShareSetInfo the matching standalone [in] Level parameter supplies the
// second on-the-wire occurrence (cf. ServerInfoUnion).
type ShareInfoUnion struct {
	Level     uint32         `ndr:"unionTag,encapsulated"`
	Level0    *ShareInfo0    `ndr:"unionField,pointer"`
	Level1    *ShareInfo1    `ndr:"unionField,pointer"`
	Level2    *ShareInfo2    `ndr:"unionField,pointer"`
	Level501  *ShareInfo501  `ndr:"unionField,pointer"`
	Level502  *ShareInfo502  `ndr:"unionField,pointer"`
	Level1004 *ShareInfo1004 `ndr:"unionField,pointer"`
	Level1005 *ShareInfo1005 `ndr:"unionField,pointer"`
	Level1501 *ShareInfo1501 `ndr:"unionField,pointer"`
}

func (u ShareInfoUnion) SwitchFunc(tag any) string {
	switch tag.(uint32) {
	case 0:
		return "Level0"
	case 1:
		return "Level1"
	case 2:
		return "Level2"
	case 501:
		return "Level501"
	case 502:
		return "Level502"
	case 1004:
		return "Level1004"
	case 1005:
		return "Level1005"
	case 1501:
		return "Level1501"
	}
	return ""
}

// ShareEnumStruct represents SHARE_ENUM_STRUCT (MS-SRVS 2.2.4.38)
// Non-encapsulated union: Level is written twice on the wire
type ShareEnumStruct struct {
	Level    uint32                 `ndr:"unionTag"`
	Level1   *ShareInfoContainer1   `ndr:"unionField,pointer"`
	Level501 *ShareInfoContainer501 `ndr:"unionField,pointer"`
	Level502 *ShareInfoContainer502 `ndr:"unionField,pointer"`
}

func (u ShareEnumStruct) SwitchFunc(tag any) string {
	t := tag.(uint32)
	switch t {
	case 1:
		return "Level1"
	case 501:
		return "Level501"
	case 502:
		return "Level502"
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

// NET_API_STATUS
// NetrShareGetInfo (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in,string] WCHAR * NetName,
// [in] DWORD Level,
// [out, switch_is(Level)] LPSHARE_INFO InfoStruct
// );
// MS-SRVS Opnum 16
type NetShareGetInfoRequest struct {
	ServerName *string `ndr:"toplevel,fullpointer,conformant,varying"`
	NetName    string  `ndr:"toplevel,conformant,varying"`
	Level      uint32
}

type NetShareGetInfoResponse struct {
	Info         ShareInfoUnion `ndr:"toplevel"`
	WindowsError uint32
}

// NET_API_STATUS
// NetrShareSetInfo (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in,string] WCHAR * NetName,
// [in] DWORD Level,
// [in, switch_is(Level)] LPSHARE_INFO ShareInfo,
// [in,out,unique] DWORD * ParmErr
// );
// MS-SRVS Opnum 17
type NetShareSetInfoRequest struct {
	ServerName *string `ndr:"toplevel,fullpointer,conformant,varying"`
	NetName    string  `ndr:"toplevel,conformant,varying"`
	Level      uint32
	ShareInfo  ShareInfoUnion `ndr:"toplevel"`
	ParmErr    *uint32        `ndr:"toplevel,fullpointer"`
}

type NetShareSetInfoResponse struct {
	ParmErr      *uint32 `ndr:"toplevel,fullpointer"`
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

func (u SessionEnumStruct) SwitchFunc(tag any) string {
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

func (u ServerInfoUnion) SwitchFunc(tag any) string {
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

// DISK_INFO — MS-SRVS 2.2.4.1. Disk is a fixed 3-WCHAR field holding a
// null-terminated drive name (e.g. "C:"). Use diskInfoToString to decode it.
type DiskInfo struct {
	Disk [3]uint16
}

// DISK_ENUM_CONTAINER — MS-SRVS 2.2.4.79. Buffer is a [size_is,length_is]
// unique pointer to a conformant+varying array of DISK_INFO.
type DiskEnumContainer struct {
	EntriesRead uint32
	Buffer      []DiskInfo `ndr:"fullpointer,conformant,varying"`
}

// NET_API_STATUS
// NetrServerDiskEnum (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in] DWORD Level,
// [in,out] DISK_ENUM_CONTAINER * DiskInfoStruct,
// [in] DWORD PreferedMaximumLength,
// [out] DWORD * TotalEntries,
// [in,out,unique] DWORD * ResumeHandle
// );
// MS-SRVS Opnum 23
type NetServerDiskEnumRequest struct {
	ServerName   *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Level        uint32
	DiskInfo     DiskEnumContainer `ndr:"toplevel"`
	PrefMaxLen   uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
}

type NetServerDiskEnumResponse struct {
	DiskInfo     DiskEnumContainer `ndr:"toplevel"`
	TotalEntries uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
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
		err = fmt.Errorf("error marshaling NetServerGetInfoRequest: %w", err)
	}
	return
}

func (s *NetServerGetInfoRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerGetInfoRequest: %w", err)
	}
	return nil
}

func (s *NetServerGetInfoResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetServerGetInfoResponse: %w", err)
	}
	return
}

func (s *NetServerGetInfoResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetServerGetInfoResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerGetInfoResponse: %w", err)
	}
	return nil
}

func (s *NetSessionEnumRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetSessionEnumRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetSessionEnumRequest: %w", err)
	}
	return
}

func (s *NetSessionEnumRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetSessionEnumRequest: %w", err)
	}
	return nil
}

func (s *NetSessionEnumResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetSessionEnumResponse: %w", err)
	}
	return
}

func (s *NetSessionEnumResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetSessionEnumResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetSessionEnumResponse: %w", err)
	}
	return nil
}

func (s *NetrpGetFileSecurityReq) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetrpGetFileSecurityReq: %w", err)
	}
	return
}

func (s *NetrpGetFileSecurityReq) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(s)
	if err != nil {
		err = fmt.Errorf("error unmarshaling NetrpGetFileSecurityReq: %w", err)
	}
	return
}

func (s *NetrpGetFileSecurityRes) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetrpGetFileSecurityRes: %w", err)
	}
	return
}

func (s *NetrpGetFileSecurityRes) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(s)
	if err != nil {
		err = fmt.Errorf("error unmarshaling NetrpGetFileSecurityRes: %w", err)
	}
	return
}

func (s *NetShareEnumAllRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetShareEnumAllRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareEnumAllRequest: %w", err)
	}
	return
}

func (s *NetShareEnumAllRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareEnumAllRequest: %w", err)
	}
	return nil
}

func (s *NetShareEnumAllResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareEnumAllResponse: %w", err)
	}
	return
}

func (s *NetShareEnumAllResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetShareEnumAllResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareEnumAllResponse: %w", err)
	}
	return nil
}

func (s *NetShareGetInfoRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetShareGetInfoRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareGetInfoRequest: %w", err)
	}
	return
}

func (s *NetShareGetInfoRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareGetInfoRequest: %w", err)
	}
	return nil
}

func (s *NetShareGetInfoResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareGetInfoResponse: %w", err)
	}
	return
}

func (s *NetShareGetInfoResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetShareGetInfoResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareGetInfoResponse: %w", err)
	}
	return nil
}

func (s *NetShareSetInfoRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetShareSetInfoRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareSetInfoRequest: %w", err)
	}
	return
}

func (s *NetShareSetInfoRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareSetInfoRequest: %w", err)
	}
	return nil
}

func (s *NetShareSetInfoResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetShareSetInfoResponse: %w", err)
	}
	return
}

func (s *NetShareSetInfoResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetShareSetInfoResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetShareSetInfoResponse: %w", err)
	}
	return nil
}

func (s *NetServerDiskEnumRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetServerDiskEnumRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetServerDiskEnumRequest: %w", err)
	}
	return
}

func (s *NetServerDiskEnumRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerDiskEnumRequest: %w", err)
	}
	return nil
}

func (s *NetServerDiskEnumResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetServerDiskEnumResponse: %w", err)
	}
	return
}

func (s *NetServerDiskEnumResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetServerDiskEnumResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetServerDiskEnumResponse: %w", err)
	}
	return nil
}
