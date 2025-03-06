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

package dcerpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	MSRPCSvcCtlPipe                = "svcctl"
	MSRPCUuidSvcCtl                = "367ABB81-9844-35F1-AD32-98F038001003"
	MSRPCSvcCtlMajorVersion uint16 = 2
	MSRPCSvcCtlMinorVersion uint16 = 0
)

// MS-SCMR Operations OP Codes
const (
	SvcCtlRCloseServiceHandle    uint16 = 0
	SvcCtlRControlService        uint16 = 1
	SvcCtlRDeleteService         uint16 = 2
	SvcCtlRQueryServiceStatus    uint16 = 6
	SvcCtlRChangeServiceConfigW  uint16 = 11
	SvcCtlRCreateServiceW        uint16 = 12
	SvcCtlREnumServicesStatusW   uint16 = 14
	SvcCtlROpenSCManagerW        uint16 = 15
	SvcCtlROpenServiceW          uint16 = 16
	SvcCtlRQueryServiceConfigW   uint16 = 17
	SvcCtlRStartServiceW         uint16 = 19
	SvcCtlRChangeServiceConfig2W uint16 = 37
	SvcCtlRQueryServiceConfig2W  uint16 = 39
)

// MS-SCMR (svcctl) Section 2.2.15 ServiceType merged with Section 2.2.47 dwServiceType
const (
	ServiceKernelDriver       uint32 = 0x00000001
	ServiceFileSystemDriver   uint32 = 0x00000002
	ServiceWin32OwnProcess    uint32 = 0x00000010
	ServiceWin32ShareProcess  uint32 = 0x00000020
	ServiceInteractiveProcess uint32 = 0x00000100
)

var ServiceTypeStatusMap = map[uint32]string{
	ServiceKernelDriver:                                  "SERVICE_KERNEL_DRIVER",
	ServiceFileSystemDriver:                              "SERVICE_FILE_SYSTEM_DRIVER",
	ServiceWin32OwnProcess:                               "SERVICE_WIN32_OWN_PROCESS",
	ServiceWin32ShareProcess:                             "SERVICE_WIN32_SHARE_PROCESS",
	ServiceInteractiveProcess:                            "SERVICE_INTERACTIVE_PROCESS",
	ServiceWin32OwnProcess | ServiceInteractiveProcess:   "SERVICE_WIN32_OWN_INTERACTIVE",
	ServiceWin32ShareProcess | ServiceInteractiveProcess: "SERVICE_WIN32_SHARE_INTERACTIVE",
}

var ServiceTypeMap = map[string]uint32{
	"SERVICE_KERNEL_DRIVER":           ServiceKernelDriver,
	"SERVICE_FILE_SYSTEM_DRIVER":      ServiceFileSystemDriver,
	"SERVICE_WIN32_OWN_PROCESS":       ServiceWin32OwnProcess,
	"SERVICE_WIN32_SHARE_PROCESS":     ServiceWin32ShareProcess,
	"SERVICE_INTERACTIVE_PROCESS":     ServiceInteractiveProcess,
	"SERVICE_WIN32_OWN_INTERACTIVE":   ServiceWin32OwnProcess | ServiceInteractiveProcess,
	"SERVICE_WIN32_SHARE_INTERACTIVE": ServiceWin32ShareProcess | ServiceInteractiveProcess,
}

// MS-SCMR (svcctl) Table 2.2.15 StartType
const (
	ServiceBootStart   uint32 = 0x00000000
	ServiceSystemStart uint32 = 0x00000001
	ServiceAutoStart   uint32 = 0x00000002
	ServiceDemandStart uint32 = 0x00000003
	ServiceDisabled    uint32 = 0x00000004
)

var StartTypeStatusMap = map[uint32]string{
	ServiceBootStart:   "SERVICE_BOOT_START",
	ServiceSystemStart: "SERVICE_SYSTEM_START",
	ServiceAutoStart:   "SERIVCE_AUTO_START",
	ServiceDemandStart: "SERVICE_DEMAND_START",
	ServiceDisabled:    "SERVICE_DISABLED",
}

var StartTypeMap = map[string]uint32{
	"SERVICE_BOOT_START":   ServiceBootStart,
	"SERVICE_SYSTEM_START": ServiceSystemStart,
	"SERIVCE_AUTO_START":   ServiceAutoStart,
	"SERVICE_DEMAND_START": ServiceDemandStart,
	"SERVICE_DISABLED":     ServiceDisabled,
}

// MS-SCMR (svcctl) Table 2.2.15 ErrorControl
const (
	ServiceErrorIgnore   uint32 = 0x00000000
	ServiceErrorNormal   uint32 = 0x00000001
	ServiceErrorSevere   uint32 = 0x00000002
	ServiceErrorCritical uint32 = 0x00000003
)

var ErrorControlStatusMap = map[uint32]string{
	ServiceErrorIgnore:   "SERVICE_ERROR_IGNORE",
	ServiceErrorNormal:   "SERVICE_ERROR_NORMAL",
	ServiceErrorSevere:   "SERIVCE_ERROR_SEVERE",
	ServiceErrorCritical: "SERVICE_ERROR_CRITICAL",
}

var ErrorControlMap = map[string]uint32{
	"SERVICE_ERROR_IGNORE":   ServiceErrorIgnore,
	"SERVICE_ERROR_NORMAL":   ServiceErrorNormal,
	"SERIVCE_ERROR_SEVERE":   ServiceErrorSevere,
	"SERVICE_ERROR_CRITICAL": ServiceErrorCritical,
}

// MS-SCMR (svcctl) Table 3.1.4
const (
	ServiceAllAccess           uint32 = 0x000F01FF //In addition to all access rights in this table, SERVICE_ALL_ACCESS includes Delete (DE), Read Control (RC), Write DACL (WD), and Write Owner (WO) access, as specified in ACCESS_MASK (section 2.4.3) of [MS-DTYP].
	ServiceChangeConfig        uint32 = 0x00000002 //Required to change the configuration of a service.
	ServiceEnumerateDependents uint32 = 0x00000008 //Required to enumerate the services installed on the server.
	ServiceInterrogate         uint32 = 0x00000080 //Required to request immediate status from the service.
	ServicePauseContinue       uint32 = 0x00000040 //Required to pause or continue the service.
	ServiceQueryConfig         uint32 = 0x00000001 //Required to query the service configuration.
	ServiceQueryStatus         uint32 = 0x00000004 //Required to request the service status.
	ServiceStart               uint32 = 0x00000010 //Required to start the service.
	ServiceStop                uint32 = 0x00000020 //Required to stop the service
	ServiceUserDefinedControl  uint32 = 0x00000100 //Required to specify a user-defined control code.
	ServiceSetStatus           uint32 = 0x00008000 //Required for a service to set its status.

	SCManagerLock             uint32 = 0x00000008 //Required to lock the SCM database.
	SCManagerCreateService    uint32 = 0x00000002 //Required for a service to be created.
	SCManagerEnumerateService uint32 = 0x00000004 //Required to enumerate a service.
	SCManagerConnect          uint32 = 0x00000001 //Required to connect to the SCM.
	SCManagerQueryLockStatus  uint32 = 0x00000010 //Required to query the lock status of the SCM database.
	SCManagerModifyBootConfig uint32 = 0x0020     //Required to call the RNotifyBootConfigStatus method.
)

// MS-SCMR Section 2.2.47 dwCurrentState
const (
	ServiceContinuePending uint32 = 0x00000005
	ServicePausePending    uint32 = 0x00000006
	ServicePaused          uint32 = 0x00000007
	ServiceRunning         uint32 = 0x00000004
	ServiceStartPending    uint32 = 0x00000002
	ServiceStopPending     uint32 = 0x00000003
	ServiceStopped         uint32 = 0x00000001
)

var ServiceStatusMap = map[uint32]string{
	ServiceContinuePending: "SERVICE_CONTINUE_PENDING",
	ServicePausePending:    "SERVICE_PAUSE_PENDING",
	ServicePaused:          "SERVICE_PAUSED",
	ServiceRunning:         "SERVICE_RUNNING",
	ServiceStartPending:    "SERVICE_START_PENDING",
	ServiceStopPending:     "SERVICE_STOP_PENDING",
	ServiceStopped:         "SERVICE_STOPPED",
}

// MS-SCMR Section 3.1.4.2 dwControl
const (
	ServiceControlContinue       uint32 = 0x00000003
	ServiceControlInterrogate    uint32 = 0x00000004
	ServiceControlNetbindadd     uint32 = 0x00000007
	ServiceControlNetbinddisable uint32 = 0x0000000A
	ServiceControlNetbindenable  uint32 = 0x00000009
	ServiceControlNetbindremove  uint32 = 0x00000008
	ServiceControlParamChange    uint32 = 0x00000006
	ServiceControlPause          uint32 = 0x00000002
	ServiceControlStop           uint32 = 0x00000001
)

// MS-SCMR Section 3.1.4.11 RChangeServiceConfigW
const (
	ServiceNoChange uint32 = 0xffffffff
)

// MS-SCMR Response codes from multiple sections: 3.1.4.2, 3.1.4.11, 3.1.4.17, 3.1.4.19
const (
	ErrorSuccess                    uint32 = 0  // Successfully started the service
	ErrorFileNotFound               uint32 = 2  // The system cannot find the file specified.
	ErrorPathNotFound               uint32 = 3  // The system cannot find the path specified.
	ErrorAccessDenied               uint32 = 5  // The SERVICE_START access right had not been granted to the caller when the RPC context handle to the service record was created.
	ErrorInvalidHandle              uint32 = 6  // The handle is no longer valid.
	ErrorInvalidParameter           uint32 = 87 // A parameter that was specified is invalid.
	ErrorInsufficientBuffer         uint32 = 122
	ErrorMoreData                   uint32 = 234
	ErrorDependentServicesRunning   uint32 = 1051
	ErrorInvalidServiceControl      uint32 = 1052
	ErrorServiceRequestTimeout      uint32 = 1053 // The process for the service was started, but it did not respond within an implementation-specific time-out.
	ErrorServiceNoThread            uint32 = 1054 // A thread could not be created for the service.
	ErrorServiceDatabaseLocked      uint32 = 1055 // The service database is locked by the call to the BlockServiceDatabase method.
	ErrorServiceAlreadyRunning      uint32 = 1056 // The ServiceStatus.dwCurrentState in the service record is not set to SERVICE_STOPPED.
	ErrorInvalidServiceAccount      uint32 = 1057 // The user account name specified in the lpServiceStartName parameter does not exist.
	ErrorServiceDisabled            uint32 = 1058 // The service cannot be started because the Start field in the service record is set to SERVICE_DISABLED.
	ErrorCircularDependency         uint32 = 1059 // A circular dependency was specified.
	ErrorServiceDoesNotExist        uint32 = 1060 // The service record with a specified display name does not exist in the SCM database
	ErrorServiceCannotAcceptControl uint32 = 1061
	ErrorServiceNotActive           uint32 = 1062
	ErrorServiceDependencyFail      uint32 = 1068 // The specified service depends on another service that has failed to start.
	ErrorServiceLogonFailed         uint32 = 1069 // The service did not start due to a logon failure.
	ErrorServiceMarkedForDelete     uint32 = 1072 // The RDeleteService method has been called for the service record identified by the hService parameter.
	ErrorServiceDependencyDeleted   uint32 = 1075 // The specified service depends on a service that does not exist or has been marked for deletion.
	ErrorDuplicateServiceName       uint32 = 1078 // The lpDisplayName matches either the ServiceName or the DisplayName of another service record in the service control manager database.
	ErrorShutdownInProgress         uint32 = 1115 // The system is shutting down.
)

var ServiceResponseCodeMap = map[uint32]error{
	ErrorSuccess:                    fmt.Errorf("Successfully started the service"),
	ErrorFileNotFound:               fmt.Errorf("The system cannot find the file specified."),
	ErrorPathNotFound:               fmt.Errorf("The system cannot find the path specified."),
	ErrorAccessDenied:               fmt.Errorf("ERROR_ACCESS_DENIED"),
	ErrorInvalidHandle:              fmt.Errorf("The handle is no longer valid."),
	ErrorInvalidParameter:           fmt.Errorf("A parameter that was specified is invalid."),
	ErrorInsufficientBuffer:         fmt.Errorf("ERROR_INSUFFICIENT_BUFFER"),
	ErrorMoreData:                   fmt.Errorf("More data is available"),
	ErrorDependentServicesRunning:   fmt.Errorf("ERROR_DEPENDENT_SERVICES_RUNNING"),
	ErrorInvalidServiceControl:      fmt.Errorf("ERROR_INVALID_SERVICE_CONTROL"),
	ErrorServiceRequestTimeout:      fmt.Errorf("Error service request timeout"),
	ErrorServiceNoThread:            fmt.Errorf("A thread could not be created for the service."),
	ErrorServiceDatabaseLocked:      fmt.Errorf("The service database is locked by the call to the BlockServiceDatabase method."),
	ErrorServiceAlreadyRunning:      fmt.Errorf("Service already running!"),
	ErrorInvalidServiceAccount:      fmt.Errorf("ERROR_INVALID_SERVICE_ACCOUNT"),
	ErrorServiceDisabled:            fmt.Errorf("ERROR_SERVICE_DISABLED"),
	ErrorCircularDependency:         fmt.Errorf("ERROR_CIRCULAR_DEPENDENCY"),
	ErrorServiceDoesNotExist:        fmt.Errorf("ERROR_SERVICE_DOES_NOT_EXIST"),
	ErrorServiceCannotAcceptControl: fmt.Errorf("ERROR_SERVICE_CANNOT_ACCEPT_CONTROL"),
	ErrorServiceNotActive:           fmt.Errorf("ERROR_SERVICE_NOT_ACTIVE"),
	ErrorServiceDependencyFail:      fmt.Errorf("The specified service depends on another service that has failed to start."),
	ErrorServiceLogonFailed:         fmt.Errorf("The service did not start due to a logon failure."),
	ErrorServiceMarkedForDelete:     fmt.Errorf("Service marked for delete."),
	ErrorServiceDependencyDeleted:   fmt.Errorf("The specified service depends on a service that does not exist or has been marked for deletion."),
	ErrorDuplicateServiceName:       fmt.Errorf("ERROR_DUPLICATE_SERVICE_NAME"),
	ErrorShutdownInProgress:         fmt.Errorf("The system is shutting down."),
}

// MS-SCMR Section 3.1.4.37 RQueryServiceConfig2W (Opnum 39) dwInfoLevel
const (
	ServiceConfigDescription              uint32 = 0x1
	ServiceConfigFailure_actions          uint32 = 0x2
	ServiceConfigDelayed_auto_start_info  uint32 = 0x3
	ServiceConfigFailure_actions_flag     uint32 = 0x4
	ServiceConfigService_sid_info         uint32 = 0x5
	ServiceConfigRequired_privileges_info uint32 = 0x6
	ServiceConfigPreshutdown_info         uint32 = 0x7
	ServiceConfigPreferred_node           uint32 = 0x9
)

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

func (self *ROpenSCManagerWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for ROpenSCManagerWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = writeConformantVaryingStringPtr(w, self.MachineName, refId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	if self.MachineName != "" {
		refId++
	}

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = writeConformantVaryingStringPtr(w, self.DatabaseName, refId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	if self.DatabaseName != "" {
		refId++
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *ROpenSCManagerWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of ROpenSCManagerWReq")
}

func (self *ROpenSCManagerWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of ROpenSCManagerWRes")
}

func (self *ROpenSCManagerWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for ROpenSCManagerWRes")

	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &self.ContextHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *ROpenServiceWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for ROpenServiceWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	_, err = w.Write(self.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}
	// Pointer to a conformant and varying string, so include MaxCount
	// Skip ReferentId ptr because this is not a unique ptr
	_, err = writeConformantVaryingString(w, self.ServiceName)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *ROpenServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of ROpenServiceWReq")
}

func (self *ROpenServiceWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of ROpenServiceWReq")
}

func (self *ROpenServiceWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for ROpenServiceWRes")

	self.ContextHandle = make([]byte, 20)
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &self.ContextHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *RCloseServiceHandleReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RCloseServiceHandleReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RCloseServiceHandleReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RCloseServiceHandleReq")
}

func (self *RCloseServiceHandleRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RCloseServiceHandleRes")
}

func (self *RCloseServiceHandleRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RCloseServiceHandleRes")

	self.ContextHandle = make([]byte, 20)
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &self.ContextHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *RQueryServiceStatusReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RQueryServiceStatusReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ContextHandle!")
	}

	_, err = w.Write(self.ContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RQueryServiceStatusReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceStatusReq")
}

func (self *RQueryServiceStatusRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceStatusRes")
}

func (self *RQueryServiceStatusRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RQueryServiceStatusRes")
	r := bytes.NewReader(buf)

	// Not sure why there is no RefId Ptr for the ServiceStatus struct ptr

	self.ServiceStatus = &ServiceStatus{}
	err = binary.Read(r, le, &self.ServiceStatus.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.CurrentState)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.ControlsAccepted)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.Win32ExitCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.ServiceSpecificExitCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.CheckPoint)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ServiceStatus.WaitHint)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *RQueryServiceConfigWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RQueryServiceConfigWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RQueryServiceConfigWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceConfigWReq")
}

func (self *RQueryServiceConfigWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceConfigWRes")
}

func (self *RQueryServiceConfigWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RQueryServiceConfigWRes")
	if len(buf) < 44 {
		return fmt.Errorf("Buffer to small for RQueryServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	conf := QueryServiceConfigW{}
	self.ServiceConfig = &conf

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

		err = binary.Read(r, le, &self.BytesNeeded)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &self.ErrorCode)
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

	conf.BinaryPathName, err = readConformantVaryingString(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.LoadOrderGroup, err = readConformantVaryingString(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.Dependencies, err = readConformantVaryingString(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.ServiceStartName, err = readConformantVaryingString(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	conf.DisplayName, err = readConformantVaryingString(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ErrorCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (self *RChangeServiceConfig2WReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RChangeServiceConfig2WReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.Info.MarshalBinary()
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

func (self *RChangeServiceConfig2WReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RChangeServiceConfig2WReq")
}

func (self *RQueryServiceConfig2WReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RQueryServiceConfig2WReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.InfoLevel)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RQueryServiceConfig2WReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RQueryServiceConfig2WReq")
}

func (self *RQueryServiceConfig2WRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RQueryServiceConfig2WRes")
}

func (self *RQueryServiceConfig2WRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RQueryServiceConfig2WRes")
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

	err = binary.Read(r, le, &self.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ErrorCode)
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

	self.Buffer = make([]byte, maxCount)
	n, err := r.Read(self.Buffer)
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

func (self *RChangeServiceConfigWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RChangeServiceConfigWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.StartType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ErrorControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = writeConformantVaryingStringPtr(w, self.BinaryPathName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	_, err = writeConformantVaryingStringPtr(w, self.LoadOrderGroup, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	if self.TagId != 0 {
		err = binary.Write(w, le, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++
		err = binary.Write(w, le, self.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		err = binary.Write(w, le, self.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if self.Dependencies != "" {
		uncDependencies := ToUnicode(self.Dependencies + "\x00")
		_, err = writeConformantArrayPtr(w, uncDependencies, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++

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

	_, err = writeConformantVaryingStringPtr(w, self.ServiceStartName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	if self.Password != nil {
		_, err = writeConformantArrayPtr(w, self.Password, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++

		err = binary.Write(w, le, uint32(len(self.Password)))
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

	_, err = writeConformantVaryingStringPtr(w, self.DisplayName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RChangeServiceConfigWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RChangeServiceConfigWReq")
}

func (self *RChangeServiceConfigWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RChangeServiceConfigWRes")
}

func (self *RChangeServiceConfigWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RChangeServiceConfigWRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for RchangeServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.TagId > 0 {
		// First 4 bytes was Referent ID when tag is non-zero
		err = binary.Read(r, le, &self.TagId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (self *RControlServiceReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RControlServiceReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Control)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RControlServiceReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RControlServiceReq")
}

func (self *RControlServiceRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RControlServiceRes")
}

func (self *RControlServiceRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RControlServiceRes")

	// Skip implementing the same decoding function twice
	res := &RQueryServiceStatusRes{}
	err = res.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.ReturnValue = res.ReturnCode
	self.ServiceStatus = res.ServiceStatus

	return
}

func (self *RDeleteServiceReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RDeleteServiceReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.ServiceHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of ServiceHandle!")
	}

	_, err = w.Write(self.ServiceHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *RDeleteServiceReq) UnmarshalBinary(buf []byte) error {
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
		_, err = writeConformantVaryingString(w, s.Argv[i])
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (self *RStartServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RStartServiceWReq")
}

func (self *RCreateServiceWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for RCreateServiceWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	if len(self.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	if self.ServiceName == "" {
		return nil, fmt.Errorf("Invalid ServiceName. Cannot be empty!")
	}

	_, err = w.Write(self.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentId ptr because this is not a unique ptr
	_, err = writeConformantVaryingString(w, self.ServiceName)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = writeConformantVaryingStringPtr(w, self.DisplayName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.StartType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ErrorControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentId ptr because this is not a unique ptr
	_, err = writeConformantVaryingString(w, self.BinaryPathName)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = writeConformantVaryingStringPtr(w, self.LoadOrderGroup, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	err = binary.Write(w, le, self.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.Dependencies != "" {
		uncDependencies := ToUnicode(self.Dependencies + "\x00")
		_, err = writeConformantArrayPtr(w, uncDependencies, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++

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

	_, err = writeConformantVaryingStringPtr(w, self.ServiceStartName, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	if self.Password != nil {
		_, err = writeConformantArrayPtr(w, self.Password, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		refId++

		err = binary.Write(w, le, uint32(len(self.Password)))
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

func (self *RCreateServiceWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RCreateServiceWReq")
}

func (self *RCreateServiceWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of RCreateServiceWRes")
}

func (self *RCreateServiceWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RCreateServiceWRes")
	if len(buf) < 28 {
		return fmt.Errorf("Buffer to small for RchangeServiceConfigWRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.TagId)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ContextHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.ContextHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (self *REnumServicesStatusWReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for REnumServicesStatusWReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	if len(self.SCContextHandle) != 20 {
		return nil, fmt.Errorf("Invalid size of SCContextHandle!")
	}

	if (self.ServiceType & 0x33) == 0 {
		return nil, fmt.Errorf("Invalid ServiceType. Must be one or a combination of values from MS-SCMR dwServiceType")
	}

	if (self.ServiceState > 0x3) || (self.ServiceState == 0) {
		return nil, fmt.Errorf("Invalid ServiceState value")
	}

	_, err = w.Write(self.SCContextHandle[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ServiceType)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ServiceState)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.BufSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ResumeIndex)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *REnumServicesStatusWReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of REnumServicesStatusWReq")
}

func (self *REnumServicesStatusWRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of REnumServicesStatusWRes")
}

func (self *REnumServicesStatusWRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for REnumServicesStatusWRes")
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

	err = binary.Read(r, le, &self.BytesNeeded)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ServicesReturned)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ResumeIndex)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.ReturnCode > 0 {
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

	self.Services = make([]EnumServiceStatusW, 0, self.ServicesReturned)
	for i := 0; i < int(self.ServicesReturned); i++ {
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
		service.DisplayName, err = FromUnicodeString(unicodeBuffer)
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
		service.ServiceName, err = FromUnicodeString(unicodeBuffer)
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

		self.Services = append(self.Services, service)
	}

	return nil
}

func decodeServiceConfig(config *QueryServiceConfigW) (res ServiceConfig, err error) {
	log.Debugln("In decodeServiceConfig")
	if _, ok := ServiceTypeStatusMap[config.ServiceType]; !ok {
		log.Infof("Could not identify returned service type for (%s): %d\n", config.DisplayName, config.ServiceType)
		res.ServiceType = fmt.Sprintf("Unknown type 0x%x (%d)", config.ServiceType, config.ServiceType)
	} else {
		res.ServiceType = ServiceTypeStatusMap[config.ServiceType]
	}

	if _, ok := StartTypeStatusMap[config.StartType]; !ok {
		err = fmt.Errorf("Could not identify returned start type: %d\n", config.StartType)
		log.Errorln(err)
	}
	res.StartType = StartTypeStatusMap[config.StartType]

	if _, ok := ErrorControlStatusMap[config.ErrorControl]; !ok {
		err = fmt.Errorf("Could not identify returned start type: %d\n", config.ErrorControl)
		log.Errorln(err)
	}
	res.ErrorControl = ErrorControlStatusMap[config.ErrorControl]

	res.BinaryPathName = config.BinaryPathName
	res.LoadOrderGroup = config.LoadOrderGroup
	res.TagId = config.TagId
	res.Dependencies = config.Dependencies
	res.ServiceStartName = config.ServiceStartName
	res.DisplayName = config.DisplayName

	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		log.Errorln(err)
	}

	return
}

// NOTE That currently the config Dependencies cannot be modified
func (sb *ServiceBind) ChangeServiceConfigExt(serviceName string, config *ServiceConfig) (err error) {
	log.Debugln("In ChangeServiceConfigExt")
	var binaryPathName, serviceStartName, displayName string
	var serviceType, startType, errorControl uint32

	if _, ok := ServiceTypeMap[config.ServiceType]; !ok {
		if strings.HasPrefix(config.ServiceType, "Unknown type 0x") {
			parts := strings.Split(config.ServiceType, " ")
			val, err2 := strconv.ParseUint(parts[2][2:], 16, 32)
			if err2 != nil {
				log.Errorln(err2)
				err = err2
				return
			}
			serviceType = uint32(val)
		} else {
			err = fmt.Errorf("Could not identify service type: %s\n", config.ServiceType)
			log.Errorln(err)
			return
		}
	} else {
		serviceType = ServiceTypeMap[config.ServiceType]
	}

	if _, ok := StartTypeMap[config.StartType]; !ok {
		err = fmt.Errorf("Could not identify start type: %s\n", config.StartType)
		log.Errorln(err)
		return
	}
	startType = StartTypeMap[config.StartType]

	if _, ok := ErrorControlMap[config.ErrorControl]; !ok {
		err = fmt.Errorf("Could not identify start type: %s\n", config.ErrorControl)
		log.Errorln(err)
		return
	}
	errorControl = ErrorControlMap[config.ErrorControl]
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		log.Errorln(err)
		return
	}

	binaryPathName = config.BinaryPathName
	serviceStartName = config.ServiceStartName
	displayName = config.DisplayName

	return sb.ChangeServiceConfig(serviceName, serviceType, startType, errorControl, binaryPathName, serviceStartName, "", displayName, config.LoadOrderGroup, "", config.TagId)
}

func (sb *ServiceBind) openSCManager(desiredAccess uint32) (handle []byte, err error) {
	log.Debugln("In openSCManager")
	scReq := ROpenSCManagerWReq{
		MachineName:   "DUMMY",
		DatabaseName:  "ServicesActive",
		DesiredAccess: desiredAccess,
	}
	scBuf, err := scReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlROpenSCManagerW, scBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Retrieve context handle from response
	res := ROpenSCManagerWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for ROpenSCManagerW: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return nil, status
	}

	handle = res.ContextHandle[:]
	return
}

func (sb *ServiceBind) openService(scHandle []byte, serviceName string, desiredAccess uint32) (handle []byte, err error) {
	log.Debugln("In openService")
	serviceReq := ROpenServiceWReq{
		SCContextHandle: scHandle,
		ServiceName:     serviceName,
		DesiredAccess:   desiredAccess,
	}

	serviceBuf, err := serviceReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlROpenServiceW, serviceBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := ROpenServiceWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for ROpenServiceW: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return nil, status
	}

	handle = res.ContextHandle
	return
}

func (sb *ServiceBind) GetServiceStatus(serviceName string) (status uint32, err error) {
	log.Debugln("In GetServiceStatus")
	handle, err := sb.openSCManager(ServiceQueryStatus)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)

	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryStatus)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	ssReq := RQueryServiceStatusReq{ContextHandle: serviceHandle}
	ssBuf, err := ssReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRQueryServiceStatus, ssBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := RQueryServiceStatusRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ReturnCode != ErrorSuccess {
		msg, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RQueryServiceStatus: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return 0, msg
	}

	status = res.ServiceStatus.CurrentState
	return
}

func (sb *ServiceBind) StartService(serviceName string, args []string) (err error) {
	log.Debugln("In StartService")
	handle, err := sb.openSCManager(ServiceStart)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceStart)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	ssReq := RStartServiceWReq{ServiceHandle: serviceHandle}
	if args == nil || len(args) == 0 {
		ssReq.Argc = 0
		ssReq.Argv = nil
	} else {
		ssReq.Argc = uint32(len(args))
		ssReq.Argv = args
	}

	ssBuf, err := ssReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRStartServiceW, ssBuf)
	if err != nil {
		return
	}

	returnValue := binary.LittleEndian.Uint32(buffer)
	if returnValue != ErrorSuccess {
		status, found := ServiceResponseCodeMap[returnValue]
		if !found {
			err = fmt.Errorf("Received unknown return code for RStartServiceWReq: 0x%x\n", returnValue)
			log.Errorln(err)
			return err
		}
		return status
	}

	return
}

func (sb *ServiceBind) ControlService(serviceName string, control uint32) (err error) {
	log.Debugln("In ControlService")
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServicePauseContinue|ServiceInterrogate|ServiceStop)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	csReq := RControlServiceReq{
		ServiceHandle: serviceHandle,
		Control:       control,
	}
	csBuf, err := csReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		return
	}

	// Parse ServiceStatus
	res := RControlServiceRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	if res.ReturnValue != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnValue]
		if !found {
			err = fmt.Errorf("Received unknown return code for RControlService: 0x%x\n", res.ReturnValue)
			log.Errorln(err)
			return
		}
		return status
	}

	return
}

func (sb *ServiceBind) GetServiceConfig(serviceName string) (config ServiceConfig, err error) {
	log.Debugln("In GetServiceConfig")
	handle, err := sb.openSCManager(ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	innerReq := RQueryServiceConfigWReq{
		ServiceHandle: serviceHandle,
		BufSize:       0,
	}
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfigW, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	res := RQueryServiceConfigWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorInsufficientBuffer {
		status, found := ServiceResponseCodeMap[res.ErrorCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RQueryServiceConfigW: 0x%x\n", res.ErrorCode)
			log.Errorln(err)
			return
		}
		return config, status
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err = sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfigW, innerBuf2)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res = RQueryServiceConfigWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ErrorCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RQueryServiceConfigW: 0x%x\n", res.ErrorCode)
			log.Errorln(err)
			return
		}
		return config, status
	}

	return decodeServiceConfig(res.ServiceConfig)
}

func (sb *ServiceBind) GetServiceConfig2(serviceName string, infoLevel uint32) (result []byte, err error) {
	log.Debugln("In GetServiceConfig2")
	handle, err := sb.openSCManager(ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	innerReq := RQueryServiceConfig2WReq{
		ServiceHandle: serviceHandle,
		InfoLevel:     infoLevel,
		BufSize:       0,
	}
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfig2W, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	res := RQueryServiceConfig2WRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorInsufficientBuffer {
		status, found := ServiceResponseCodeMap[res.ErrorCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RQueryServiceConfig2W: 0x%x\n", res.ErrorCode)
			log.Errorln(err)
			return
		}
		return nil, status
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err = sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfig2W, innerBuf2)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res = RQueryServiceConfig2WRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ErrorCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RQueryServiceConfig2W: 0x%x\n", res.ErrorCode)
			log.Errorln(err)
			return
		}
		return nil, status
	}

	result = res.Buffer
	return
}

// NOTE that currently, dependencies cannot be modified
func (sb *ServiceBind) ChangeServiceConfig(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName, password, displayName, loadOrderGroup, dependencies string, tagId uint32) (err error) {

	log.Debugln("In ChangeServiceConfig")
	if dependencies != "" {
		return fmt.Errorf("Specifying dependencies when changing a service config is currently unsupported.")
	}

	handle, err := sb.openSCManager(SCManagerEnumerateService)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceChangeConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	//TODO Add support for modifying Dependencies
	// Figure out how to properly marshal the request with dependencies included
	innerReq := RChangeServiceConfigWReq{
		ServiceHandle:    serviceHandle,
		ServiceType:      serviceType,
		StartType:        startType,
		ErrorControl:     errorControl,
		BinaryPathName:   binaryPathName,
		LoadOrderGroup:   loadOrderGroup,
		TagId:            tagId, //NOTE that tag cannot be set. A value > 0 means: ask server for a tag id.
		Dependencies:     "",
		ServiceStartName: serviceStartName,
		DisplayName:      displayName,
	}

	/*
	   MS-SCMR Section 3.1.4.12 explains that in RPC over TCP, the password should be plaintext,
	   but over SMB it must be encrypted
	*/
	if password != "" {
		uncPassword := ToUnicode(password + "\x00")
		encPassword, err := encryptSecret(sb.f.GetSessionKey(), uncPassword)
		if err != nil {
			log.Errorln(err)
			return err
		}
		innerReq.Password = encPassword
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRChangeServiceConfigW, innerBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Parse ServiceConfig
	res := RChangeServiceConfigWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RChangeServiceConfigW: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return err
		}
		return status
	}

	return
}

func (sb *ServiceBind) ChangeServiceConfig2(serviceName string, info *ConfigInfoW) (err error) {
	log.Debugln("In ChangeServiceConfig2")
	handle, err := sb.openSCManager(ServiceChangeConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceChangeConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	innerReq := RChangeServiceConfig2WReq{
		ServiceHandle: serviceHandle,
		Info:          *info,
	}
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeIoCtlRequest(SvcCtlRChangeServiceConfig2W, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	if len(buffer) < 4 {
		err = fmt.Errorf("Response too small for RChangeServiceConfig2W")
		return
	}
	errorCode := binary.LittleEndian.Uint32(buffer[:4])

	if errorCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[errorCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RChangeServiceConfig2W: 0x%x\n", errorCode)
			log.Errorln(err)
			return
		}
		return status
	}

	return
}

func (sb *ServiceBind) CreateService(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName, password, displayName string, startService bool) (err error) {

	log.Debugln("In CreateService")

	scHandle, err := sb.openSCManager(SCManagerCreateService)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.CloseServiceHandle(scHandle)

	innerReq := RCreateServiceWReq{
		SCContextHandle:  scHandle,
		ServiceName:      serviceName,
		DisplayName:      displayName,
		DesiredAccess:    ServiceAllAccess,
		ServiceType:      serviceType,
		StartType:        startType,
		ErrorControl:     errorControl,
		BinaryPathName:   binaryPathName,
		ServiceStartName: serviceStartName,
	}

	/*
	   MS-SCMR Section 3.1.4.12 explains that in RPC over TCP, the password should be plaintext,
	   but over SMB it must be encrypted
	*/
	if password != "" {
		uncPassword := ToUnicode(password + "\x00")
		encPassword, err := encryptSecret(sb.f.GetSessionKey(), uncPassword)
		if err != nil {
			log.Errorln(err)
			return err
		}
		innerReq.Password = encPassword
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRCreateServiceW, innerBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Parse ServiceConfig
	res := RCreateServiceWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RCreateServiceW: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return err
		}
		return status
	}

	defer sb.CloseServiceHandle(res.ContextHandle)

	if startService {
		ssReq := RStartServiceWReq{ServiceHandle: res.ContextHandle}
		ssReq.Argc = 0
		// When Argc is 0 I need to marshal 0x00000000 for Argc and same for Argv e.g., 4 bytes combined of 0s

		ssBuf, err2 := ssReq.MarshalBinary()
		if err != nil {
			return err2
		}

		buffer, err2 := sb.MakeIoCtlRequest(SvcCtlRStartServiceW, ssBuf)
		if err != nil {
			return err2
		}

		returnValue := binary.LittleEndian.Uint32(buffer)
		if returnValue != ErrorSuccess {
			status, found := ServiceResponseCodeMap[returnValue]
			if !found {
				err = fmt.Errorf("Received unknown return code for RStartServiceW: 0x%x\n", returnValue)
				log.Errorln(err)
				return err
			}
			return status
		}
	}

	return
}

func (sb *ServiceBind) DeleteService(serviceName string) (err error) {
	scHandle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(scHandle)
	handle, err := sb.openService(scHandle, serviceName, ServiceAllAccess)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)

	// Attempt to stop the service before deletion
	csReq := RControlServiceReq{
		ServiceHandle: handle,
		Control:       ServiceControlStop,
	}
	csBuf, err := csReq.MarshalBinary()
	if err != nil {
		return
	}

	_, err = sb.MakeIoCtlRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		log.Errorln(err)
		// Continue with deletion even if stop failed for some reason
	}

	innerReq := RDeleteServiceReq{
		ServiceHandle: handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRDeleteService, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("Invalid response to RDeleteServiceReq")
		log.Errorln(err)
		return
	}

	returnCode := le.Uint32(buffer[:4])

	if returnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code for RDeleteServiceReq: 0x%x\n", returnCode)
			log.Errorln(err)
			return err
		}
		return status
	}

	return
}

func (sb *ServiceBind) EnumServicesStatus(serviceType, serviceState uint32) (result []EnumServiceStatusW, err error) {
	log.Debugln("In EnumServicesStatus")

	scHandle, err := sb.openSCManager(SCManagerEnumerateService)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.CloseServiceHandle(scHandle)

	enumSSReq := REnumServicesStatusWReq{
		SCContextHandle: scHandle,
		ServiceType:     serviceType,
		ServiceState:    serviceState,
		BufSize:         0,
		ResumeIndex:     0,
	}

	enumSSBuf, err := enumSSReq.MarshalBinary()
	if err != nil {
		log.Errorf("Failed to encode EnumServicesStatus request with error: %v\n", err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlREnumServicesStatusW, enumSSBuf)
	if err != nil {
		log.Errorf("Failed to EnumServicesStatus with error: %v\n", err)
		return
	}

	res := REnumServicesStatusWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorf("Failed to unmarshal response of enumerate services status with error: %v\n", err)
		return
	}

	if res.ReturnCode != ErrorMoreData {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			log.Errorf("Received unknown return code for REnumServicesStatus: 0x%x\n", res.ReturnCode)
			return
		}
		log.Errorf("Failed to enumerate services status with error (return value: 0x%x): %v\n", res.ReturnCode, status)
		return
	}

	log.Debugf("Bytes needed: %d\n", res.BytesNeeded)

	enumSSReq.BufSize = res.BytesNeeded

	enumSSBuf, err = enumSSReq.MarshalBinary()
	if err != nil {
		log.Errorf("Failed to encode EnumServicesStatus request with error: %v\n", err)
		return
	}

	log.Debugln("Attempting to list all services")
	buffer, err = sb.MakeIoCtlRequest(SvcCtlREnumServicesStatusW, enumSSBuf)
	if err != nil {
		log.Errorf("Failed to EnumServicesStatus with error: %v\n", err)
		return
	}

	res = REnumServicesStatusWRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorf("Failed to unmarshal response of enumerate services status with error: %v\n", err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			log.Errorf("Received unknown return code for REnumServicesStatus: 0x%x\n", res.ReturnCode)
			return
		}
		log.Errorf("Failed to enumerate services status with error (return value: 0x%x): %v\n", res.ReturnCode, status)
		return
	}

	log.Debugf("Bytes needed: %d\n", res.BytesNeeded)
	log.Debugf("Services returned: %d\n", res.ServicesReturned)
	result = res.Services

	return
}

func (sb *ServiceBind) CloseServiceHandle(serviceHandle []byte) {
	//log.Debugln("In CloseServiceHandle")
	closeReq := RCloseServiceHandleReq{
		ServiceHandle: serviceHandle,
	}
	closeBuf, err := closeReq.MarshalBinary()
	if err != nil {
		log.Errorf("Failed to encode close service handle request with error: %v\n", err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRCloseServiceHandle, closeBuf)
	if err != nil {
		log.Errorf("Failed to close service handle with error: %v\n", err)
		return
	}
	res := RCloseServiceHandleRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorf("Failed to unmarshal response of close service handle with error: %v\n", err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		status, found := ServiceResponseCodeMap[res.ReturnCode]
		if !found {
			log.Errorf("Received unknown return code for RCloseService: 0x%x\n", res.ReturnCode)
			return
		}
		log.Errorf("Failed to close service handle with error (return value: 0x%x): %v\n", res.ReturnCode, status)
		return
	}

	return
}

func (self *ConfigInfoW) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for ConfigInfoW")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// MS-SCMR Section 2.2.22 SC_RPC_CONFIG_INFOW
	// Encode dwInfoLevel value
	err = binary.Write(w, le, self.InfoLevel)
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := self.Data.MarshalBinary()
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

func (self *ServiceDescription) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for ServiceDescription")

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
	_, err = writeConformantVaryingStringPtr(w, self.Description, refId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}
