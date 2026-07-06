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
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/ndr"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

type WkstaUserInfo0 struct {
	Username string `ndr:"pointer,conformant,varying"`
}

type WkstaUserInfo1 struct {
	Username     string `ndr:"pointer,conformant,varying"`
	LogonDomain  string `ndr:"pointer,conformant,varying"`
	OtherDomains string `ndr:"pointer,conformant,varying"`
	LogonServer  string `ndr:"pointer,conformant,varying"`
}

type WkstaUserInfo0Container struct {
	EntriesRead uint32
	Buffer      []WkstaUserInfo0 `ndr:"fullpointer,conformant"`
}

type WkstaUserInfo1Container struct {
	EntriesRead uint32
	Buffer      []WkstaUserInfo1 `ndr:"fullpointer,conformant"`
}

// WkstaUserEnum represents WKSTA_USER_ENUM_STRUCT (MS-WKST 2.2.5.14)
// Non-encapsulated union: Level is written twice on the wire
type WkstaUserEnum struct {
	Level  uint32                   `ndr:"unionTag"`
	Level0 *WkstaUserInfo0Container `ndr:"unionField,pointer"`
	Level1 *WkstaUserInfo1Container `ndr:"unionField,pointer"`
}

func (u WkstaUserEnum) SwitchFunc(tag any) string {
	t := tag.(uint32)
	switch t {
	case 0:
		return "Level0"
	case 1:
		return "Level1"
	}
	return ""
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

type NetWkstaUserEnumRequest struct {
	ServerName             *string       `ndr:"toplevel,fullpointer,conformant,varying"`
	UserInfo               WkstaUserEnum `ndr:"toplevel"`
	PreferredMaximumLength uint32
	ResumeHandle           *uint32 `ndr:"toplevel,fullpointer"`
}

type NetWkstaUserEnumResponse struct {
	UserInfo     WkstaUserEnum `ndr:"toplevel"`
	TotalEntries uint32
	ResumeHandle *uint32 `ndr:"toplevel,fullpointer"`
	ReturnCode   uint32
}

func (s *NetWkstaUserEnumRequest) Marshal() (b []byte, err error) {
	log.Traceln("In Marshal for NetWkstaUserEnumRequest")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetWkstaUserEnumRequest: %w", err)
	}
	return
}

func (s *NetWkstaUserEnumRequest) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetWkstaUserEnumRequest: %w", err)
	}
	return nil
}

func (s *NetWkstaUserEnumResponse) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling NetWkstaUserEnumResponse: %w", err)
	}
	return
}

func (s *NetWkstaUserEnumResponse) Unmarshal(b []byte) error {
	log.Traceln("In Unmarshal for NetWkstaUserEnumResponse")
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling NetWkstaUserEnumResponse: %w", err)
	}
	return nil
}
