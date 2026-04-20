// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

package mstsch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/ndr"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

type SYSTEMTIME struct {
	Year         uint16
	Month        uint16
	DayOfWeek    uint16
	Day          uint16
	Hour         uint16
	Minute       uint16
	Second       uint16
	Milliseconds uint16
}

func (st SYSTEMTIME) ToTime() time.Time {
	if st.Year == 0 {
		return time.Time{}
	}
	return time.Date(
		int(st.Year),
		time.Month(st.Month),
		int(st.Day),
		int(st.Hour),
		int(st.Minute),
		int(st.Second),
		int(st.Milliseconds)*1000000,
		time.UTC,
	)
}

// TaskUserCred mirrors MS-TSCH 2.3.8 TASK_USER_CRED. Element type for the
// [unique] pCreds array parameter in SchRpcRegisterTask. Not currently
// populated by the high-level API — callers always pass a nil PCreds.
type TaskUserCred struct {
	UserId   string `ndr:"pointer,conformant,varying"`
	Password string `ndr:"pointer,conformant,varying"`
	Flags    uint32
}

// rpcStringPtr is the element type for wchar_t** array parameters — a
// single embedded pointer-to-wchar_t-string. Used by SchRpcRun's pArgs.
type rpcStringPtr struct {
	Value string `ndr:"pointer,conformant,varying"`
}

// TaskXmlErrorInfo mirrors MS-TSCH 2.3.7 TASK_XML_ERROR_INFO, returned by
// SchRpcRegisterTask when the task XML fails validation.
type TaskXmlErrorInfo struct {
	Line   uint32
	Column uint32
	Node   string `ndr:"pointer,conformant,varying"`
	Value  string `ndr:"pointer,conformant,varying"`
}

// SchRpcRegisterTask request (Opnum 1)
//
//	HRESULT SchRpcRegisterTask(
//	  [in, string, unique] const wchar_t* path,
//	  [in, string] const wchar_t* xml,
//	  [in] DWORD flags,
//	  [in, string, unique] const wchar_t* sddl,
//	  [in] DWORD logonType,
//	  [in] DWORD cCreds,
//	  [in, size_is(cCreds), unique] const TASK_USER_CRED* pCreds,
//	  [out, string] wchar_t** pActualPath,
//	  [out] PTASK_XML_ERROR_INFO* pErrorInfo
//	);
type SchRpcRegisterTaskReq struct {
	Path      *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Xml       string  `ndr:"toplevel,conformant,varying"`
	Flags     uint32
	Sddl      *string `ndr:"toplevel,fullpointer,conformant,varying"`
	LogonType uint32
	CCreds    uint32
	PCreds    *[]TaskUserCred `ndr:"toplevel,fullpointer,conformant"`
}

func (s *SchRpcRegisterTaskReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcRegisterTaskReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcRegisterTaskReq: %v", err)
	}
	return b, nil
}

type SchRpcRegisterTaskRes struct {
	ActualPath string            `ndr:"toplevel,fullpointer,conformant,varying"`
	ErrorInfo  *TaskXmlErrorInfo `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

func (s *SchRpcRegisterTaskRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for SchRpcRegisterTaskRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling SchRpcRegisterTaskRes: %v", err)
	}
	return nil
}

// SchRpcEnumInstances request (Opnum 4)
//
//	HRESULT SchRpcEnumInstances(
//	  [in, string, unique] const wchar_t* path,
//	  [in] DWORD flags,
//	  [out] DWORD* pNumGuids,
//	  [out, size_is(,*pNumGuids)] GUID** pGuids
//	);
type SchRpcEnumInstancesReq struct {
	Path  *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Flags uint32
}

func (s *SchRpcEnumInstancesReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcEnumInstancesReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcEnumInstancesReq: %v", err)
	}
	return b, nil
}

type SchRpcEnumInstancesRes struct {
	NumGuids   uint32
	Guids      [][16]byte `ndr:"toplevel,fullpointer,conformant"`
	ReturnCode uint32
}

func (s *SchRpcEnumInstancesRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for SchRpcEnumInstancesRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling SchRpcEnumInstancesRes: %v", err)
	}
	return nil
}

// SchRpcStop request (Opnum 14)
//
//	HRESULT SchRpcStop(
//	  [in, string, unique] const wchar_t* path,
//	  [in] DWORD flags
//	);
type SchRpcStopReq struct {
	Path  *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Flags uint32
}

func (s *SchRpcStopReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcStopReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcStopReq: %v", err)
	}
	return b, nil
}

// SchRpcDelete request (Opnum 8)
//
//	HRESULT SchRpcDelete(
//	  [in, string] const wchar_t* path,
//	  [in] DWORD flags
//	);
type SchRpcDeleteReq struct {
	Path  string `ndr:"toplevel,conformant,varying"`
	Flags uint32
}

func (s *SchRpcDeleteReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcDeleteReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcDeleteReq: %v", err)
	}
	return b, nil
}

// SchRpcGetLastRunInfo request (Opnum 11)
//
//	HRESULT SchRpcGetLastRunInfo(
//	  [in, string] const wchar_t* path,
//	  [out] PSYSTEMTIME pLastRuntime,
//	  [out] DWORD* pLastReturnCode
//	);
type SchRpcGetLastRunInfoReq struct {
	Path string `ndr:"toplevel,conformant,varying"`
}

func (s *SchRpcGetLastRunInfoReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcGetLastRunInfoReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcGetLastRunInfoReq: %v", err)
	}
	return b, nil
}

type SchRpcGetLastRunInfoRes struct {
	LastRunTime    SYSTEMTIME
	LastReturnCode uint32
	ReturnCode     uint32
}

func (s *SchRpcGetLastRunInfoRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for SchRpcGetLastRunInfoRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling SchRpcGetLastRunInfoRes: %v", err)
	}
	return nil
}

// SchRpcRun request (Opnum 12)
//
//	HRESULT SchRpcRun(
//	  [in, string] const wchar_t* path,
//	  [in] DWORD cArgs,
//	  [in, string, size_is(cArgs), unique] const wchar_t** pArgs,
//	  [in] DWORD flags,
//	  [in] DWORD sessionId,
//	  [in, unique, string] const wchar_t* user,
//	  [out] GUID* pGuid
//	);
type SchRpcRunReq struct {
	Path      string `ndr:"toplevel,conformant,varying"`
	CArgs     uint32
	PArgs     *[]rpcStringPtr `ndr:"toplevel,fullpointer,conformant"`
	Flags     uint32
	SessionId uint32
	User      *string `ndr:"toplevel,fullpointer,conformant,varying"`
}

func (s *SchRpcRunReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcRunReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcRunReq: %v", err)
	}
	return b, nil
}

type SchRpcRunRes struct {
	GUID       [16]byte
	ReturnCode uint32
}

func (s *SchRpcRunRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for SchRpcRunRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling SchRpcRunRes: %v", err)
	}
	return nil
}

// SchRpcRetrieveTask request (Opnum 13)
//
//	HRESULT SchRpcRetrieveTask(
//	  [in, string] const wchar_t* path,
//	  [in, string] const wchar_t* lpcwszLanguagesBuffer,
//	  [in] unsigned long* pulNumLanguages,
//	  [out, string] wchar_t** pDefinition
//	);
type SchRpcRetrieveTaskReq struct {
	Path            string `ndr:"toplevel,conformant,varying"`
	LanguagesBuffer string `ndr:"toplevel,conformant,varying"`
	NumLanguages    uint32
}

func (s *SchRpcRetrieveTaskReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for SchRpcRetrieveTaskReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling SchRpcRetrieveTaskReq: %v", err)
	}
	return b, nil
}

type SchRpcRetrieveTaskRes struct {
	Definition string `ndr:"toplevel,fullpointer,conformant,varying"`
	ReturnCode uint32
}

func (s *SchRpcRetrieveTaskRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for SchRpcRetrieveTaskRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling SchRpcRetrieveTaskRes: %v", err)
	}
	return nil
}
