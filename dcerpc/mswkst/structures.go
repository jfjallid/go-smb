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
	"io"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/dcerpc"
)

type RPCCon struct {
	*dcerpc.ServiceBind
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

func (s *NetWkstaUserEnumReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for NetWkstaUserEnumReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.ServerName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}
	if s.ServerName != "" {
		refId++
	}

	buf, err := s.UserInfo.MarshalBinary()
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

	err = binary.Write(w, le, s.PreferredMaximumLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *NetWkstaUserEnumReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetWkstaUserEnumReq")
}

func (s *NetWkstaUserEnumRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of NetWkstaUserEnumRes")
}

func (s *NetWkstaUserEnumRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for NetWkstaUserEnumRes")
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

	err = binary.Read(r, le, &s.TotalEntries)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Server could return partial data even with the ErrorMoreData response
	// But skipping parse of that since I always request the max number of entries back
	if s.ReturnCode > 0 {
		status, found := ResponseCodeMap[s.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown WKST return code for NetWkstaEnum response: 0x%x\n", s.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	err = s.UserInfo.UnmarshalBinary(buf[:len(buf)-12])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (s *WkstaUserEnum) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for WkstaUserEnum")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, s.Level)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if s.Data != nil {
		var buf []byte
		buf, err = s.Data.MarshalBinary()
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

func (s *WkstaUserEnum) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for WkstaUserEnum")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for WkstaUserEnum")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.Level)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch s.Level {
	case WkstaUserEnumInfoLevel0:
		var data WkstaUserInfo0Container
		err = data.UnmarshalBinary(buf[4:])
		if err != nil {
			log.Errorln(err)
			return
		}
		s.Data = &data
	case WkstaUserEnumInfoLevel1:
		var data WkstaUserInfo1Container
		err = data.UnmarshalBinary(buf[4:])
		if err != nil {
			log.Errorln(err)
			return
		}
		s.Data = &data
	default:
		err = fmt.Errorf("Unknown Level %d in WkstaUserEnum response structure", s.Level)
		log.Errorln(err)
		return
	}

	return
}

func (s *WkstaUserInfo0Container) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for WkstaUserInfo0Container")

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

	err = binary.Write(w, le, s.EntriesRead)
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

	if s.EntriesRead > 0 {
		return nil, fmt.Errorf("Not implemented support for specifying WkstaUserInfo0 array items")
	}

	return w.Bytes(), nil
}

func (s *WkstaUserInfo0Container) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for WkstaUserInfo0Container")
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

	err = binary.Read(r, le, &s.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ref id ptr, max count and all the ref id ptrs for the array items
	if s.EntriesRead > 0 {
		_, err = r.Seek(8+int64(s.EntriesRead*4), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	for i := 0; i < int(s.EntriesRead); i++ {
		str := ""
		if err != nil {
			log.Errorln(err)
			return
		}
		str, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s.Buffer = append(s.Buffer, WkstaUserInfo0{Username: str})
	}

	return nil
}

func (s *WkstaUserInfo1Container) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for WkstaUserInfo1Container")

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

	err = binary.Write(w, le, s.EntriesRead)
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

	if s.EntriesRead > 0 {
		return nil, fmt.Errorf("Not implemented support for specifying WkstaUserInfo1 array items")
	}

	return w.Bytes(), nil
}

func (s *WkstaUserInfo1Container) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for WkstaUserInfo1Container")
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

	err = binary.Read(r, le, &s.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ref id ptr, max count and all the ref id ptrs for the array items
	if s.EntriesRead > 0 {
		_, err = r.Seek(8+int64(s.EntriesRead*4*4), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	for i := 0; i < int(s.EntriesRead); i++ {
		s0 := ""
		s0, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s1 := ""
		s1, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s2 := ""
		s2, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s3 := ""
		s3, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorf("Error trying to read string for entry %d: %v\n", i, err)
			return
		}
		s.Buffer = append(s.Buffer, WkstaUserInfo1{Username: s0, LogonDomain: s1, OtherDomains: s2, LogonServer: s3})
	}

	return nil
}
