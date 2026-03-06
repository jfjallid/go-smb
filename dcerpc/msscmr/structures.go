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
//
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package msscmr

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

type ServiceConfig struct {
	ServiceType      string
	StartType        string
	ErrorControl     string
	BinaryPathName   string
	LoadOrderGroup   string
	TagId            uint32
	Dependencies     string
	ServiceStartName string
	DisplayName      string
}

type ResumeHandle struct {
	ReferentId uint32
	Handle     uint32
}

/*
DWORD ROpenSCManagerW(

	[in, string, unique, range(0, SC_MAX_COMPUTER_NAME_LENGTH)]
	SVCCTL_HANDLEW lpMachineName,
	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
	wchar_t* lpDatabaseName,
	[in] DWORD dwDesiredAccess,
	[out] LPSC_RPC_HANDLE lpScHandle

);
*/
type ROpenSCManagerWReq struct {
	MachineName   string
	DatabaseName  string
	DesiredAccess uint32
}

type ROpenSCManagerWRes struct {
	ContextHandle [20]byte
	ReturnCode    uint32
}

/*
DWORD ROpenServiceW(

	[in] SC_RPC_HANDLE hSCManager,
	[in, string, range(0, SC_MAX_NAME_LENGTH)]
	wchar_t* lpServiceName,
	[in] DWORD dwDesiredAccess,
	[out] LPSC_RPC_HANDLE lpServiceHandle

);
*/
type ROpenServiceWReq struct {
	SCContextHandle []byte
	ServiceName     string
	DesiredAccess   uint32
}

type ROpenServiceWRes struct {
	ContextHandle []byte
	ReturnCode    uint32
}

type RCloseServiceHandleReq struct {
	ServiceHandle []byte
}

type RCloseServiceHandleRes struct {
	ContextHandle []byte
	ReturnCode    uint32
}

type RQueryServiceStatusReq struct {
	ContextHandle []byte
}

/*
	typedef struct {
	    DWORD dwServiceType;
	    DWORD dwCurrentState;
	    DWORD dwControlsAccepted;
	    DWORD dwWin32ExitCode;
	    DWORD dwServiceSpecificExitCode;
	    DWORD dwCheckPoint;
	    DWORD dwWaitHint;
	} SERVICE_STATUS,

*LPSERVICE_STATUS;
*/
type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

/*
DWORD RQueryServiceStatus(

	[in] SC_RPC_HANDLE hService,
	[out] LPSERVICE_STATUS lpServiceStatus

);
*/
type RQueryServiceStatusRes struct {
	ServiceStatus *ServiceStatus
	ReturnCode    uint32
}

// MS-SCMR Section 2.2.15
/*
typedef struct _QUERY_SERVICE_CONFIGW {
DWORD dwServiceType;
DWORD dwStartType;
DWORD dwErrorControl;
[string,range(0, 8 * 1024)] LPWSTR lpBinaryPathName;
[string,range(0, 8 * 1024)] LPWSTR lpLoadOrderGroup;
DWORD dwTagId;
[string,range(0, 8 * 1024)] LPWSTR lpDependencies;
[string,range(0, 8 * 1024)] LPWSTR lpServiceStartName;
[string,range(0, 8 * 1024)] LPWSTR lpDisplayName;
} QUERY_SERVICE_CONFIGW,
*LPQUERY_SERVICE_CONFIGW;
*/
type QueryServiceConfigW struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string
	LoadOrderGroup   string
	TagId            uint32
	Dependencies     string // Array?
	ServiceStartName string
	DisplayName      string
}

/*
DWORD RQueryServiceConfigW(

	[in] SC_RPC_HANDLE hService,
	[out] LPQUERY_SERVICE_CONFIGW lpServiceConfig,
	[in, range(0, 1024*8)] DWORD cbBufSize,
	[out] LPBOUNDED_DWORD_8K pcbBytesNeeded

);
*/
type RQueryServiceConfigWReq struct {
	ServiceHandle []byte
	BufSize       uint32
}

type RQueryServiceConfigWRes struct {
	ServiceConfig *QueryServiceConfigW
	BytesNeeded   uint32
	ErrorCode     uint32
}

// MS-SCMR Section 2.2.22 SC_RPC_CONFIG_INFOW
type ConfigInfoW struct {
	InfoLevel uint32
	Data      ConfigInfoWUnion
}

type ConfigInfoWUnion interface {
	MarshalBinary() ([]byte, error)
}

// MS-SCMR Section 2.2.35 SERVICE_DESCRIPTIONW
type ServiceDescription struct {
	Description string
}

type RChangeServiceConfig2WReq struct {
	ServiceHandle []byte
	Info          ConfigInfoW
}

type RQueryServiceConfig2WReq struct {
	ServiceHandle []byte
	InfoLevel     uint32
	BufSize       uint32
}

type RQueryServiceConfig2WRes struct {
	Buffer      []byte
	BytesNeeded uint32
	ErrorCode   uint32
}

/*
DWORD RChangeServiceConfigW(

	[in] SC_RPC_HANDLE hService,
	[in] DWORD dwServiceType,
	[in] DWORD dwStartType,
	[in] DWORD dwErrorControl,
	[in, string, unique, range(0, SC_MAX_PATH_LENGTH)]
	    wchar_t* lpBinaryPathName,
	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
	    wchar_t* lpLoadOrderGroup,
	[in, out, unique] LPDWORD lpdwTagId,
	[in, unique, size_is(dwDependSize)]
	    LPBYTE lpDependencies,
	[in, range(0, SC_MAX_DEPEND_SIZE)]
	    DWORD dwDependSize,
	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)]
	    wchar_t* lpServiceStartName,
	[in, unique, size_is(dwPwSize)]
	    LPBYTE lpPassword,
	[in, range(0, SC_MAX_PWD_SIZE)]
	    DWORD dwPwSize,
	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
	    wchar_t* lpDisplayName

);
*/
type RChangeServiceConfigWReq struct {
	ServiceHandle    []byte
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string
	LoadOrderGroup   string
	TagId            uint32
	Dependencies     string
	DependSize       uint32
	ServiceStartName string
	// RPC over SMB requires password encryption with session key
	// So have to encrypt the password before calling the marshal function
	Password    []byte // []byte instead of string to support encryption
	PwSize      uint32
	DisplayName string
}

type RChangeServiceConfigWRes struct {
	TagId      uint32
	ReturnCode uint32
}

type RControlServiceReq struct {
	ServiceHandle []byte
	Control       uint32
}

type RControlServiceRes struct {
	ServiceStatus *ServiceStatus
	ReturnValue   uint32
}

type RDeleteServiceReq struct {
	ServiceHandle []byte
}

type RStartServiceWReq struct {
	ServiceHandle []byte
	Argc          uint32
	Argv          []string
}

/*
DWORD RCreateServiceW(

	[in] SC_RPC_HANDLE hSCManager,
	[in, string, range(0, SC_MAX_NAME_LENGTH)]
	    wchar_t* lpServiceName,
	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
	    wchar_t* lpDisplayName,
	[in] DWORD dwDesiredAccess,
	[in] DWORD dwServiceType,
	[in] DWORD dwStartType,
	[in] DWORD dwErrorControl,
	[in, string, range(0, SC_MAX_PATH_LENGTH)]
	    wchar_t* lpBinaryPathName,
	[in, string, unique, range(0, SC_MAX_NAME_LENGTH)]
	    wchar_t* lpLoadOrderGroup,
	[in, out, unique] LPDWORD lpdwTagId,
	[in, unique, size_is(dwDependSize)]
	    LPBYTE lpDependencies,
	[in, range(0, SC_MAX_DEPEND_SIZE)]
	    DWORD dwDependSize,
	[in, string, unique, range(0, SC_MAX_ACCOUNT_NAME_LENGTH)]
	    wchar_t* lpServiceStartName,
	[in, unique, size_is(dwPwSize)]
	    LPBYTE lpPassword,
	[in, range(0, SC_MAX_PWD_SIZE)]
	    DWORD dwPwSize,
	[out] LPSC_RPC_HANDLE lpServiceHandle

);
*/
type RCreateServiceWReq struct {
	SCContextHandle  []byte
	ServiceName      string
	DisplayName      string
	DesiredAccess    uint32
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string
	LoadOrderGroup   string
	TagId            uint32
	Dependencies     string
	DependSize       uint32
	ServiceStartName string
	Password         []byte
	PwSize           uint32
}

type RCreateServiceWRes struct {
	TagId         uint32
	ContextHandle []byte
	ReturnCode    uint32
}

type EnumServiceStatusW struct {
	ServiceName   string
	DisplayName   string
	ServiceStatus *ServiceStatus
}

type REnumServicesStatusWReq struct {
	SCContextHandle []byte
	ServiceType     uint32
	ServiceState    uint32
	BufSize         uint32
	ResumeIndex     uint32
}

type REnumServicesStatusWRes struct {
	Services         []EnumServiceStatusW
	BytesNeeded      uint32
	ServicesReturned uint32
	ResumeIndex      uint32
	ReturnCode       uint32
}

func (s *ROpenSCManagerWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for ROpenSCManagerWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.MachineName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.DatabaseName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *ROpenSCManagerWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of ROpenSCManagerWReq")
}

func (s *ROpenSCManagerWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of ROpenSCManagerWRes")
}

func (s *ROpenSCManagerWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for ROpenSCManagerWRes")

	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &s.ContextHandle)
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

func (s *ROpenServiceWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for ROpenServiceWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	_, err = w.Write(s.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}
	// Pointer to a conformant and varying string, so include MaxCount
	// Skip ReferentId ptr because this is not a unique ptr
	_, err = msdtyp.WriteConformantVaryingString(w, s.ServiceName, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *ROpenServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of ROpenServiceWReq")
}

func (s *ROpenServiceWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of ROpenServiceWReq")
}

func (s *ROpenServiceWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for ROpenServiceWRes")

	s.ContextHandle = make([]byte, 20)
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &s.ContextHandle)
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

func (s *RCloseServiceHandleReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RCloseServiceHandleReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RCloseServiceHandleReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RCloseServiceHandleReq")
}

func (s *RCloseServiceHandleRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RCloseServiceHandleRes")
}

func (s *RCloseServiceHandleRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RCloseServiceHandleRes")

	s.ContextHandle = make([]byte, 20)
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &s.ContextHandle)
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

func (s *RQueryServiceStatusReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RQueryServiceStatusReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ContextHandle!")
	}

	_, err = w.Write(s.ContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RQueryServiceStatusReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceStatusReq")
}

func (s *RQueryServiceStatusRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceStatusRes")
}

func (s *RQueryServiceStatusRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RQueryServiceStatusRes")
	r := bytes.NewReader(buf)

	// Not sure why there is no RefId Ptr for the ServiceStatus struct ptr

	s.ServiceStatus = &ServiceStatus{}
	err = binary.Read(r, le, &s.ServiceStatus.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.CurrentState)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.ControlsAccepted)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.Win32ExitCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.ServiceSpecificExitCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.CheckPoint)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ServiceStatus.WaitHint)
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

func (s *RQueryServiceConfigWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RQueryServiceConfigWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RQueryServiceConfigWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceConfigWReq")
}

func (s *RQueryServiceConfigWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceConfigWRes")
}

func (s *RQueryServiceConfigWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RQueryServiceConfigWRes")
	if len(buf) < 44 {
		return fmt.Errorf("Buffer to small for RQueryServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	conf := QueryServiceConfigW{}
	s.ServiceConfig = &conf

	err = binary.Read(r, le, &conf.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &conf.StartType)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &conf.ErrorControl)
	if err != nil {
		log.Errorln(err)
		return
	}
	if len(buf) < 45 {
		// Probably ErrorInsuficientBuffer
		// Expect the rest of the QueryServiceConfigW struct fields to be null ptrs, so skip them
		_, err = r.Seek(24, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Read(r, le, &s.BytesNeeded)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &s.ErrorCode)
		if err != nil {
			log.Errorln(err)
			return
		}
		return
	}

	// Skip ReferentId ptr for BinaryPathName and LoadOrderGroup
	_, err = r.Seek(8, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &conf.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentId ptr for Dependencies, ServiceStartName and DisplayName
	_, err = r.Seek(12, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.BinaryPathName, err = msdtyp.ReadConformantVaryingString(r, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.LoadOrderGroup, err = msdtyp.ReadConformantVaryingString(r, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.Dependencies, err = msdtyp.ReadConformantVaryingString(r, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.ServiceStartName, err = msdtyp.ReadConformantVaryingString(r, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.DisplayName, err = msdtyp.ReadConformantVaryingString(r, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ErrorCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (s *RChangeServiceConfig2WReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RChangeServiceConfig2WReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := s.Info.MarshalBinary()
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

	return w.Bytes(), nil
}

func (s *RChangeServiceConfig2WReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RChangeServiceConfig2WReq")
}

func (s *RQueryServiceConfig2WReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RQueryServiceConfig2WReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.InfoLevel)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RQueryServiceConfig2WReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceConfig2WReq")
}

func (s *RQueryServiceConfig2WRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceConfig2WRes")
}

func (s *RQueryServiceConfig2WRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RQueryServiceConfig2WRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer to small for RQueryServiceConfig2WRes")
	}
	r := bytes.NewReader(buf)

	// Begin by reading the fixed size fields
	_, err = r.Seek(-8, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ErrorCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	var maxCount uint32
	err = binary.Read(r, le, &maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	if uint32(len(buf)) < (maxCount + 12) {
		err = fmt.Errorf("RQueryServiceConfig2W response buffer is smaller than indicated size of payload")
	}

	s.Buffer = make([]byte, maxCount)
	n, err := r.Read(s.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	if uint32(n) != maxCount {
		err = fmt.Errorf("Expected to read %d bytes buffer from response, but only read %d bytes", maxCount, n)
		return
	}

	return
}

func (s *RChangeServiceConfigWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RChangeServiceConfigWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.StartType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ErrorControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.BinaryPathName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.LoadOrderGroup, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.TagId != 0 {
		err = binary.Write(w, le, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, s.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		err = binary.Write(w, le, s.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if s.Dependencies != "" {
		uncDependencies := msdtyp.ToUnicode(s.Dependencies + "\x00")
		_, err = msdtyp.WriteConformantArrayPtr(w, uncDependencies, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, le, uint32(len(uncDependencies)))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		// Write null ptr for dependencies, and null value for DependSize
		err = binary.Write(w, le, uint64(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.ServiceStartName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.Password != nil {
		_, err = msdtyp.WriteConformantArrayPtr(w, s.Password, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, le, uint32(len(s.Password)))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		// Write null ptr for password, and null value for PwSize
		err = binary.Write(w, le, uint64(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.DisplayName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RChangeServiceConfigWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RChangeServiceConfigWReq")
}

func (s *RChangeServiceConfigWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RChangeServiceConfigWRes")
}

func (s *RChangeServiceConfigWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RChangeServiceConfigWRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for RchangeServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}
	if s.TagId > 0 {
		// First 4 bytes was Referent ID when tag is non-zero
		err = binary.Read(r, le, &s.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (s *RControlServiceReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RControlServiceReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.Control)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RControlServiceReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RControlServiceReq")
}

func (s *RControlServiceRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RControlServiceRes")
}

func (s *RControlServiceRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RControlServiceRes")

	// Skip implementing the same decoding function twice
	res := &RQueryServiceStatusRes{}
	err = res.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	s.ReturnValue = res.ReturnCode
	s.ServiceStatus = res.ServiceStatus

	return
}

func (s *RDeleteServiceReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RDeleteServiceReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(s.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *RDeleteServiceReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RDeleteServiceReq")
}

func (s *RStartServiceWReq) MarshalBinary() (res []byte, err error) {
	var ret []byte
	w := bytes.NewBuffer(ret)

	w.Write(s.ServiceHandle)

	// Encode Argc
	if err = binary.Write(w, le, s.Argc); err != nil {
		log.Errorln(err)
		return
	}

	// If Argc is 0, Argv will be a null pointer
	if s.Argc == 0 {
		w.Write([]byte{0x0, 0x0, 0x0, 0x0})
		return w.Bytes(), nil
	}

	refId := uint32(1)

	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	// Encode Max Element Count in array
	if err := binary.Write(w, le, s.Argc); err != nil {
		return nil, err
	}

	// Encode another RefId for each element in the array
	// This is because according to NDR, the pointers are lifted outside the array element and into the parent structure
	for i := 0; i < int(s.Argc); i++ {
		err = binary.Write(w, le, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++
	}

	for i := 0; i < int(s.Argc); i++ {
		_, err = msdtyp.WriteConformantVaryingString(w, s.Argv[i], true)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (s *RStartServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RStartServiceWReq")
}

func (s *RCreateServiceWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for RCreateServiceWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	if len(s.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	if s.ServiceName == "" {
		return nil, fmt.Errorf("Invalid ServiceName. Cannot be empty!")
	}

	_, err = w.Write(s.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentId ptr because this is not a unique ptr
	_, err = msdtyp.WriteConformantVaryingString(w, s.ServiceName, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.DisplayName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.StartType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ErrorControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentId ptr because this is not a unique ptr
	_, err = msdtyp.WriteConformantVaryingString(w, s.BinaryPathName, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.LoadOrderGroup, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.Dependencies != "" {
		uncDependencies := msdtyp.ToUnicode(s.Dependencies + "\x00")
		_, err = msdtyp.WriteConformantArrayPtr(w, uncDependencies, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, le, uint32(len(uncDependencies)))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		// Write null ptr for dependencies, and null value for DependSize
		err = binary.Write(w, le, uint64(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.ServiceStartName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.Password != nil {
		_, err = msdtyp.WriteConformantArrayPtr(w, s.Password, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, le, uint32(len(s.Password)))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		// Write null ptr for password and null value for PwSize
		err = binary.Write(w, le, uint64(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (s *RCreateServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RCreateServiceWReq")
}

func (s *RCreateServiceWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RCreateServiceWRes")
}

func (s *RCreateServiceWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RCreateServiceWRes")
	if len(buf) < 28 {
		return fmt.Errorf("Buffer to small for RchangeServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}

	s.ContextHandle = make([]byte, 20)
	err = binary.Read(r, le, &s.ContextHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (s *REnumServicesStatusWReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for REnumServicesStatusWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(s.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	if (s.ServiceType & 0x33) == 0 {
		return nil, fmt.Errorf("Invalid ServiceType. Must be one or a combination of values from MS-SCMR dwServiceType")
	}

	if (s.ServiceState > 0x3) || (s.ServiceState == 0) {
		return nil, fmt.Errorf("Invalid ServiceState value")
	}

	_, err = w.Write(s.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ServiceState)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ResumeIndex)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *REnumServicesStatusWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of REnumServicesStatusWReq")
}

func (s *REnumServicesStatusWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of REnumServicesStatusWRes")
}

func (s *REnumServicesStatusWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for REnumServicesStatusWRes")
	if len(buf) < 16 {
		return fmt.Errorf("Buffer to small for REnumServicesStatusWRes")
	}

	r := bytes.NewReader(buf)
	// First read last 16 bytes to get return code and the other fixed size fields
	_, err = r.Seek(-16, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ServicesReturned)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ResumeIndex)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.ReturnCode > 0 {
		// Likely no more data we care about in this packet
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	var bufferSize uint32
	err = binary.Read(r, le, &bufferSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	padd := bufferSize % 4                            // alignment
	if len(buf) < int((bufferSize + padd + 4 + 16)) { // 4 bytes bufferSize field, 16 bytes for the other fields
		err = fmt.Errorf("Invalid response! BufferSize indicated value larger that packet")
		log.Errorln(err)
		return
	}

	s.Services = make([]EnumServiceStatusW, 0, s.ServicesReturned)
	for i := 0; i < int(s.ServicesReturned); i++ {
		service := EnumServiceStatusW{ServiceStatus: &ServiceStatus{}}
		var offsetServiceName uint32
		var offsetDisplayName uint32
		err = binary.Read(r, le, &offsetServiceName)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &offsetDisplayName)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Read(r, le, &service.ServiceStatus.ServiceType)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.CurrentState)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.ControlsAccepted)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.Win32ExitCode)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.ServiceSpecificExitCode)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.CheckPoint)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &service.ServiceStatus.WaitHint)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Save current position
		var lastOffset int64
		lastOffset, err = r.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Read DisplayName
		_, err = r.Seek(int64(offsetDisplayName+4), io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}
		var unicodeBuffer []byte
		readBuff := make([]byte, 2)
		var n int
		for {
			n, err = r.Read(readBuff)
			if err != nil {
				log.Errorln(err)
				return
			}
			if n < 2 {
				err = fmt.Errorf("Failed to read 2 bytes from packet buffer")
				log.Errorln(err)
				return
			}
			if bytes.Compare(readBuff, []byte{0, 0}) == 0 {
				break
			}
			unicodeBuffer = append(unicodeBuffer, readBuff...)
		}
		service.DisplayName, err = msdtyp.FromUnicodeString(unicodeBuffer)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Read ServiceName
		_, err = r.Seek(int64(offsetServiceName+4), io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}
		unicodeBuffer = nil
		readBuff = make([]byte, 2)
		for {
			n, err = r.Read(readBuff)
			if err != nil {
				log.Errorln(err)
				return
			}
			if n < 2 {
				err = fmt.Errorf("Failed to read 2 bytes from packet buffer")
				log.Errorln(err)
				return
			}
			if bytes.Compare(readBuff, []byte{0, 0}) == 0 {
				break
			}
			unicodeBuffer = append(unicodeBuffer, readBuff...)
		}
		service.ServiceName, err = msdtyp.FromUnicodeString(unicodeBuffer)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Go back to previous position
		_, err = r.Seek(lastOffset, io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}

		s.Services = append(s.Services, service)
	}

	return nil
}

func (s *ConfigInfoW) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for ConfigInfoW")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// MS-SCMR Section 2.2.22 SC_RPC_CONFIG_INFOW
	// Encode dwInfoLevel value
	err = binary.Write(w, le, s.InfoLevel)
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := s.Data.MarshalBinary()
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

	return w.Bytes(), nil
}

func (s *ServiceDescription) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for ServiceDescription")

	// MS-SCMR Section 2.2.22 SC_RPC_CONFIG_INFOW
	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, ServiceConfigDescription)
	// then encode the Level once more
	err = binary.Write(w, le, ServiceConfigDescription)

	// finally, encode the actual struct that was selected
	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, s.Description, &refId, true)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}
