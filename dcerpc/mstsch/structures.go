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
//
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package mstsch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
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
	Path      string
	Xml       string
	Flags     uint32
	Sddl      string
	LogonType uint32
	CCreds    uint32
}

func (s *SchRpcRegisterTaskReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcRegisterTaskReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Path is [in, unique] - write as pointer (NULL if empty)
	_, err := msdtyp.WriteConformantVaryingStringPtr(w, s.Path, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Xml is [in, ref] - write as conformant varying string (not a pointer)
	_, err = msdtyp.WriteConformantVaryingString(w, s.Xml, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Flags
	err = binary.Write(w, le, s.Flags)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Sddl is [in, unique] - write as pointer (NULL if empty)
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.Sddl, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// LogonType
	err = binary.Write(w, le, s.LogonType)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// CCreds
	err = binary.Write(w, le, s.CCreds)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// PCreds - NULL pointer (cCreds = 0)
	err = binary.Write(w, le, uint32(0))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

type SchRpcRegisterTaskRes struct {
	ActualPath string
	ReturnCode uint32
}

func (s *SchRpcRegisterTaskRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SchRpcRegisterTaskRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SchRpcRegisterTaskRes")
	}
	r := bytes.NewReader(buf)

	// pActualPath is [out, string] wchar_t** — unique pointer to string
	var ptrActualPath uint32
	err = binary.Read(r, le, &ptrActualPath)
	if err != nil {
		log.Errorln(err)
		return
	}
	if ptrActualPath != 0 {
		s.ActualPath, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// pErrorInfo is PTASK_XML_ERROR_INFO* — unique pointer, skip it
	var ptrErrorInfo uint32
	err = binary.Read(r, le, &ptrErrorInfo)
	if err != nil {
		log.Errorln(err)
		return
	}
	if ptrErrorInfo != 0 {
		// Skip over the error info structure if present
		// It contains: Line(4), Column(4), Node(4), then a string pointer
		// For now we just skip past it to get to the return code
		// We need to skip: line, column, node, and a string pointer
		var line, column, node uint32
		binary.Read(r, le, &line)
		binary.Read(r, le, &column)
		binary.Read(r, le, &node)
		var strPtr uint32
		binary.Read(r, le, &strPtr)
		if strPtr != 0 {
			// Read and discard the string
			_, _ = msdtyp.ReadConformantVaryingString(r, true)
		}
	}

	// HRESULT
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
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
	Path  string
	Flags uint32
}

func (s *SchRpcEnumInstancesReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcEnumInstancesReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Path is [in, unique] - write as pointer (NULL if empty)
	_, err := msdtyp.WriteConformantVaryingStringPtr(w, s.Path, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Flags
	err = binary.Write(w, le, s.Flags)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

type SchRpcEnumInstancesRes struct {
	NumGuids   uint32
	Guids      [][16]byte
	ReturnCode uint32
}

func (s *SchRpcEnumInstancesRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SchRpcEnumInstancesRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SchRpcEnumInstancesRes")
	}
	r := bytes.NewReader(buf)

	// pNumGuids [out] DWORD*
	err = binary.Read(r, le, &s.NumGuids)
	if err != nil {
		log.Errorln(err)
		return
	}

	// pGuids [out, size_is(,*pNumGuids)] GUID** — unique pointer
	var ptrGuids uint32
	err = binary.Read(r, le, &ptrGuids)
	if err != nil {
		log.Errorln(err)
		return
	}
	if ptrGuids != 0 && s.NumGuids > 0 {
		// Conformant array: MaxCount first
		var maxCount uint32
		err = binary.Read(r, le, &maxCount)
		if err != nil {
			log.Errorln(err)
			return
		}
		s.Guids = make([][16]byte, s.NumGuids)
		for i := uint32(0); i < s.NumGuids; i++ {
			err = binary.Read(r, le, &s.Guids[i])
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	}

	// HRESULT
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

// SchRpcStop request (Opnum 14)
//
//	HRESULT SchRpcStop(
//	  [in, string, unique] const wchar_t* path,
//	  [in] DWORD flags
//	);
type SchRpcStopReq struct {
	Path  string
	Flags uint32
}

func (s *SchRpcStopReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcStopReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Path is [in, unique] - write as pointer (NULL if empty)
	_, err := msdtyp.WriteConformantVaryingStringPtr(w, s.Path, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Flags
	err = binary.Write(w, le, s.Flags)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

// SchRpcDelete request (Opnum 8)
//
//	HRESULT SchRpcDelete(
//	  [in, string] const wchar_t* path,
//	  [in] DWORD flags
//	);
type SchRpcDeleteReq struct {
	Path  string
	Flags uint32
}

func (s *SchRpcDeleteReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcDeleteReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// Path is [in, ref] - conformant varying string (not a pointer)
	_, err := msdtyp.WriteConformantVaryingString(w, s.Path, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Flags
	err = binary.Write(w, le, s.Flags)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

// SchRpcGetLastRunInfo request (Opnum 11)
//
//	HRESULT SchRpcGetLastRunInfo(
//	  [in, string] const wchar_t* path,
//	  [out] PSYSTEMTIME pLastRuntime,
//	  [out] DWORD* pLastReturnCode
//	);
type SchRpcGetLastRunInfoReq struct {
	Path string
}

func (s *SchRpcGetLastRunInfoReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcGetLastRunInfoReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// Path is [in, ref] - conformant varying string
	_, err := msdtyp.WriteConformantVaryingString(w, s.Path, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

type SchRpcGetLastRunInfoRes struct {
	LastRunTime    SYSTEMTIME
	LastReturnCode uint32
	ReturnCode     uint32
}

func (s *SchRpcGetLastRunInfoRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SchRpcGetLastRunInfoRes")
	// SYSTEMTIME (16 bytes) + LastReturnCode (4 bytes) + HRESULT (4 bytes) = 24 bytes
	if len(buf) < 24 {
		return fmt.Errorf("Buffer too small for SchRpcGetLastRunInfoRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.LastRunTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.LastReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
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
	Path      string
	Flags     uint32
	SessionId uint32
	User      string // Account name or SID string (when TASK_RUN_USER_SID is set). Empty for NULL.
}

func (s *SchRpcRunReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcRunReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Path is [in, ref] - conformant varying string
	_, err := msdtyp.WriteConformantVaryingString(w, s.Path, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// cArgs = 0
	err = binary.Write(w, le, uint32(0))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// pArgs = NULL
	err = binary.Write(w, le, uint32(0))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Flags
	err = binary.Write(w, le, s.Flags)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// SessionId
	err = binary.Write(w, le, s.SessionId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// User is [in, unique, string] - write as pointer (NULL if empty)
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.User, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

type SchRpcRunRes struct {
	GUID       [16]byte
	ReturnCode uint32
}

func (s *SchRpcRunRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SchRpcRunRes")
	// GUID (16 bytes) + HRESULT (4 bytes) = 20 bytes
	if len(buf) < 20 {
		return fmt.Errorf("Buffer too small for SchRpcRunRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.GUID)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
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
	Path string
}

func (s *SchRpcRetrieveTaskReq) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for SchRpcRetrieveTaskReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// Path is [in, ref] - conformant varying string
	_, err := msdtyp.WriteConformantVaryingString(w, s.Path, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// lpcwszLanguagesBuffer is [in, string] - empty string with null terminator
	_, err = msdtyp.WriteConformantVaryingString(w, "", true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// pulNumLanguages - [in] unsigned long*
	err = binary.Write(w, le, uint32(0))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

type SchRpcRetrieveTaskRes struct {
	Definition string
	ReturnCode uint32
}

func (s *SchRpcRetrieveTaskRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SchRpcRetrieveTaskRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SchRpcRetrieveTaskRes")
	}
	r := bytes.NewReader(buf)

	// pDefinition is [out, string] wchar_t** — unique pointer to string
	var ptrDefinition uint32
	err = binary.Read(r, le, &ptrDefinition)
	if err != nil {
		log.Errorln(err)
		return
	}
	if ptrDefinition != 0 {
		s.Definition, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// HRESULT
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}
