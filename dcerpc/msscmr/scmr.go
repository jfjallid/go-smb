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

package msscmr

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/msscmr").SetDisplayName("msscmr")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCSvcCtlPipe                = "svcctl"
	MSRPCUuidSvcCtl                = "367ABB81-9844-35F1-AD32-98F038001003"
	MSRPCSvcCtlMajorVersion uint16 = 2
	MSRPCSvcCtlMinorVersion uint16 = 0
)

// MS-SCMR Operations OP Codes
const (
	SvcCtlRCloseServiceHandle         uint16 = 0
	SvcCtlRControlService             uint16 = 1
	SvcCtlRDeleteService              uint16 = 2
	SvcCtlRQueryServiceObjectSecurity uint16 = 4
	SvcCtlRSetServiceObjectSecurity   uint16 = 5
	SvcCtlRQueryServiceStatus         uint16 = 6
	SvcCtlRChangeServiceConfigW       uint16 = 11
	SvcCtlRCreateServiceW             uint16 = 12
	SvcCtlREnumServicesStatusW        uint16 = 14
	SvcCtlROpenSCManagerW             uint16 = 15
	SvcCtlROpenServiceW               uint16 = 16
	SvcCtlRQueryServiceConfigW        uint16 = 17
	SvcCtlRStartServiceW              uint16 = 19
	SvcCtlRChangeServiceConfig2W      uint16 = 37
	SvcCtlRQueryServiceConfig2W       uint16 = 39
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

const (
	// From MS-DTYP
	ServiceDelete uint32 = 0x00010000 //Required to delete a service
)

// MS-DTYP Section 2.4.3 ACCESS_MASK standard access rights. The service access
// rights above are object-specific; these are the standard rights required to
// open a service handle for reading or writing its security descriptor.
const (
	ReadControl          uint32 = 0x00020000 // Required to read OWNER, GROUP, and DACL from the security descriptor.
	WriteDac             uint32 = 0x00040000 // Required to modify the DACL.
	WriteOwner           uint32 = 0x00080000 // Required to modify the OWNER and GROUP.
	AccessSystemSecurity uint32 = 0x01000000 // Required to read or modify the SACL (needs SeSecurityPrivilege).
)

// MS-DTYP Section 2.4.7 SECURITY_INFORMATION. Selects which parts of a security
// descriptor to query or set via RQueryServiceObjectSecurity (Opnum 4) and
// RSetServiceObjectSecurity (Opnum 5).
const (
	OwnerSecurityInformation uint32 = 0x00000001
	GroupSecurityInformation uint32 = 0x00000002
	DaclSecurityInformation  uint32 = 0x00000004
	SaclSecurityInformation  uint32 = 0x00000008
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
	ErrorServiceExists              uint32 = 1073
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
	ErrorServiceExists:              fmt.Errorf("The service already exists!"),
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

// MS-SCMR Section 2.2.39 SC_ACTION_TYPE
const (
	ScActionNone       uint32 = 0
	ScActionRestart    uint32 = 1
	ScActionReboot     uint32 = 2
	ScActionRunCommand uint32 = 3
)

var ScFailureActionMap = map[uint32]string{
	ScActionNone:       "ActionNone",
	ScActionRestart:    "ActionRestart",
	ScActionReboot:     "ActionReboot",
	ScActionRunCommand: "ActionRunCommand",
}

// MS-SCMR Section 2.2.46 dwServiceSidType
const (
	ServiceSidTypeNone         uint32 = 0x00000000
	ServiceSidTypeUnrestricted uint32 = 0x00000001
	ServiceSidTypeRestricted   uint32 = 0x00000003
)

var ServiceSidTypeMap = map[uint32]string{
	ServiceSidTypeNone:         "SidTypeNone",
	ServiceSidTypeUnrestricted: "SidTypeUnrestricted",
	ServiceSidTypeRestricted:   "SidTypeRestricted",
}

// checkReturnCode maps a non-zero SCMR return code to a *dcerpc.StatusError
// carrying op, the raw code, and the mapped sentinel from
// ServiceResponseCodeMap (nil when unmapped). Codes in okCodes are treated
// as success in addition to ErrorSuccess. The raw code field varies by RPC
// method (ReturnCode / ReturnValue / ErrorCode), so callers pass the right
// one.
func checkReturnCode(op string, code uint32, okCodes ...uint32) error {
	if code == ErrorSuccess {
		return nil
	}
	for _, ok := range okCodes {
		if code == ok {
			return nil
		}
	}
	return &dcerpc.StatusError{Op: op, Code: code, Err: ServiceResponseCodeMap[code]}
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

func decodeServiceConfig(config *QueryServiceConfigW) (res ServiceConfig, err error) {
	log.Traceln("In decodeServiceConfig")
	if _, ok := ServiceTypeStatusMap[config.ServiceType]; !ok {
		log.Infof("Could not identify returned service type for (%s): %d\n", config.DisplayName, config.ServiceType)
		res.ServiceType = fmt.Sprintf("Unknown type 0x%x (%d)", config.ServiceType, config.ServiceType)
	} else {
		res.ServiceType = ServiceTypeStatusMap[config.ServiceType]
	}

	if _, ok := StartTypeStatusMap[config.StartType]; !ok {
		err = fmt.Errorf("could not identify returned start type: %d", config.StartType)
	}
	res.StartType = StartTypeStatusMap[config.StartType]

	if _, ok := ErrorControlStatusMap[config.ErrorControl]; !ok {
		err = fmt.Errorf("could not identify returned error control: %d", config.ErrorControl)
	}
	res.ErrorControl = ErrorControlStatusMap[config.ErrorControl]

	res.BinaryPathName = config.BinaryPathName
	res.LoadOrderGroup = config.LoadOrderGroup
	res.TagId = config.TagId
	res.Dependencies = config.Dependencies
	res.ServiceStartName = config.ServiceStartName
	res.DisplayName = config.DisplayName

	if err != nil {
		err = fmt.Errorf("decode service config: %w", err)
	}

	return
}

func (sb *RPCCon) ChangeServiceConfigExt(serviceName string, config *ServiceConfig) (err error) {
	log.Traceln("In ChangeServiceConfigExt")
	var binaryPathName, serviceStartName, displayName string
	var serviceType, startType, errorControl uint32

	if _, ok := ServiceTypeMap[config.ServiceType]; !ok {
		if strings.HasPrefix(config.ServiceType, "Unknown type 0x") {
			parts := strings.Split(config.ServiceType, " ")
			val, err2 := strconv.ParseUint(parts[2][2:], 16, 32)
			if err2 != nil {
				err = err2
				return
			}
			serviceType = uint32(val)
		} else {
			err = fmt.Errorf("could not identify service type: %s", config.ServiceType)
			return
		}
	} else {
		serviceType = ServiceTypeMap[config.ServiceType]
	}

	if _, ok := StartTypeMap[config.StartType]; !ok {
		err = fmt.Errorf("could not identify start type: %s", config.StartType)
		return
	}
	startType = StartTypeMap[config.StartType]

	if _, ok := ErrorControlMap[config.ErrorControl]; !ok {
		err = fmt.Errorf("could not identify error control: %s", config.ErrorControl)
		return
	}
	errorControl = ErrorControlMap[config.ErrorControl]
	if err != nil {
		err = fmt.Errorf("decode service config: %w", err)
		return
	}

	binaryPathName = config.BinaryPathName
	serviceStartName = config.ServiceStartName
	displayName = config.DisplayName

	//TODO Verify all string pointers passed here that they are correct
	return sb.ChangeServiceConfig(serviceName, serviceType, startType, errorControl, &binaryPathName, &serviceStartName, "", &displayName, &config.LoadOrderGroup, config.Dependencies, config.TagId)
}

func (sb *RPCCon) openSCManager(desiredAccess uint32) (handle []byte, err error) {
	log.Traceln("In openSCManager")
	scReq := ROpenSCManagerWReq{
		MachineName:   "DUMMY",
		DatabaseName:  "ServicesActive",
		DesiredAccess: desiredAccess,
	}
	scBuf, err := scReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlROpenSCManagerW, scBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := ROpenSCManagerWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("ROpenSCManagerW", res.ReturnCode); err != nil {
		return nil, err
	}

	handle = res.ContextHandle[:]
	return
}

func (sb *RPCCon) openService(scHandle []byte, serviceName string, desiredAccess uint32) (handle []byte, err error) {
	log.Traceln("In openService")
	var ctxHandle [20]byte
	copy(ctxHandle[:], scHandle)
	serviceReq := ROpenServiceWReq{
		SCContextHandle: ctxHandle,
		ServiceName:     serviceName,
		DesiredAccess:   desiredAccess,
	}

	serviceBuf, err := serviceReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlROpenServiceW, serviceBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := ROpenServiceWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("ROpenServiceW", res.ReturnCode); err != nil {
		return nil, err
	}

	handle = res.ContextHandle[:]
	return
}

func (sb *RPCCon) GetServiceStatus(serviceName string) (status uint32, err error) {
	log.Traceln("In GetServiceStatus")
	// Opening a named service only needs SC_MANAGER_CONNECT on the SCM
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)

	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryStatus)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var ssHandle [20]byte
	copy(ssHandle[:], serviceHandle)
	ssReq := RQueryServiceStatusReq{ContextHandle: ssHandle}
	ssBuf, err := ssReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRQueryServiceStatus, ssBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := RQueryServiceStatusRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("RQueryServiceStatus", res.ReturnCode); err != nil {
		return
	}

	status = res.ServiceStatus.CurrentState
	return
}

func (sb *RPCCon) StartService(serviceName string, args []string) (err error) {
	log.Traceln("In StartService")
	// Opening a named service only needs SC_MANAGER_CONNECT on the SCM
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceStart)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var startHandle [20]byte
	copy(startHandle[:], serviceHandle)
	ssReq := RStartServiceWReq{ServiceHandle: startHandle}
	if len(args) > 0 {
		ssReq.Argc = uint32(len(args))
		argv := make([]LPWStr, len(args))
		for i, a := range args {
			argv[i] = LPWStr{S: a}
		}
		ssReq.Argv = &argv
	}

	ssBuf, err := ssReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRStartServiceW, ssBuf)
	if err != nil {
		return
	}

	returnValue := binary.LittleEndian.Uint32(buffer)
	if err = checkReturnCode("RStartServiceWReq", returnValue); err != nil {
		return err
	}

	return
}

func (sb *RPCCon) ControlService(serviceName string, control uint32) (err error) {
	log.Traceln("In ControlService")
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

	var csHandle [20]byte
	copy(csHandle[:], serviceHandle)
	csReq := RControlServiceReq{
		ServiceHandle: csHandle,
		Control:       control,
	}
	csBuf, err := csReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		return
	}

	// Parse ServiceStatus
	res := RControlServiceRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	if err = checkReturnCode("RControlService", res.ReturnValue); err != nil {
		return err
	}

	return
}

func (sb *RPCCon) GetServiceConfig(serviceName string) (config ServiceConfig, err error) {
	log.Traceln("In GetServiceConfig")
	// Opening a named service only needs SC_MANAGER_CONNECT on the SCM
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var qHandle [20]byte
	copy(qHandle[:], serviceHandle)
	innerReq := RQueryServiceConfigWReq{
		ServiceHandle: qHandle,
		BufSize:       0,
	}
	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeRequest(SvcCtlRQueryServiceConfigW, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	res := RQueryServiceConfigWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	// The size probe (empty buffer) is expected to fail with
	// ERROR_INSUFFICIENT_BUFFER; any other code is a real error.
	if res.ErrorCode != ErrorInsufficientBuffer {
		if err = checkReturnCode("RQueryServiceConfigW", res.ErrorCode); err != nil {
			return config, err
		}
		return config, fmt.Errorf("RQueryServiceConfigW: unexpected success on size probe")
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err = sb.MakeRequest(SvcCtlRQueryServiceConfigW, innerBuf2)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res = RQueryServiceConfigWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("RQueryServiceConfigW", res.ErrorCode); err != nil {
		return config, err
	}

	return decodeServiceConfig(&res.ServiceConfig)
}

func (sb *RPCCon) queryServiceConfig2(serviceName string, infoLevel uint32) (result []byte, err error) {
	log.Traceln("In queryServiceConfig2")
	// Opening a named service only needs SC_MANAGER_CONNECT on the SCM
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceQueryConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var svcHandle [20]byte
	copy(svcHandle[:], serviceHandle)

	innerReq := RQueryServiceConfig2WReq{
		ServiceHandle: svcHandle,
		InfoLevel:     infoLevel,
		BufSize:       0,
	}
	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeRequest(SvcCtlRQueryServiceConfig2W, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	res := RQueryServiceConfig2WRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	// The size probe (empty buffer) is expected to fail with
	// ERROR_INSUFFICIENT_BUFFER; any other code is a real error.
	if res.ErrorCode != ErrorInsufficientBuffer {
		if err = checkReturnCode("RQueryServiceConfig2W", res.ErrorCode); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("RQueryServiceConfig2W: unexpected success on size probe")
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err = sb.MakeRequest(SvcCtlRQueryServiceConfig2W, innerBuf2)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res = RQueryServiceConfig2WRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("RQueryServiceConfig2W", res.ErrorCode); err != nil {
		return nil, err
	}

	result = res.Buffer
	return
}

// GetServiceConfig2 queries optional configuration parameters for a service
// and returns the raw buffer. For typed results, use the specific methods:
// GetServiceDescription, GetServiceFailureActions, etc.
func (sb *RPCCon) GetServiceConfig2(serviceName string, infoLevel uint32) ([]byte, error) {
	return sb.queryServiceConfig2(serviceName, infoLevel)
}

func (sb *RPCCon) GetServiceDescription(serviceName string) (string, error) {
	log.Traceln("In GetServiceDescription")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigDescription)
	if err != nil {
		return "", err
	}
	return parseServiceDescription(buf)
}

func (sb *RPCCon) GetServiceFailureActions(serviceName string) (*ServiceFailureActions, error) {
	log.Traceln("In GetServiceFailureActions")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigFailure_actions)
	if err != nil {
		return nil, err
	}
	return parseFailureActions(buf)
}

func (sb *RPCCon) GetServiceDelayedAutoStartInfo(serviceName string) (bool, error) {
	log.Traceln("In GetServiceDelayedAutoStartInfo")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigDelayed_auto_start_info)
	if err != nil {
		return false, err
	}
	return parseDelayedAutoStartInfo(buf)
}

func (sb *RPCCon) GetServiceFailureActionsFlag(serviceName string) (bool, error) {
	log.Traceln("In GetServiceFailureActionsFlag")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigFailure_actions_flag)
	if err != nil {
		return false, err
	}
	return parseFailureActionsFlag(buf)
}

func (sb *RPCCon) GetServiceSIDInfo(serviceName string) (uint32, error) {
	log.Traceln("In GetServiceSIDInfo")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigService_sid_info)
	if err != nil {
		return 0, err
	}
	return parseServiceSIDInfo(buf)
}

func (sb *RPCCon) GetServiceRequiredPrivileges(serviceName string) ([]string, error) {
	log.Traceln("In GetServiceRequiredPrivileges")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigRequired_privileges_info)
	if err != nil {
		return nil, err
	}
	return parseRequiredPrivileges(buf)
}

func (sb *RPCCon) GetServicePreshutdownInfo(serviceName string) (uint32, error) {
	log.Traceln("In GetServicePreshutdownInfo")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigPreshutdown_info)
	if err != nil {
		return 0, err
	}
	return parsePreshutdownInfo(buf)
}

func (sb *RPCCon) GetServicePreferredNode(serviceName string) (*ServicePreferredNodeInfo, error) {
	log.Traceln("In GetServicePreferredNode")
	buf, err := sb.queryServiceConfig2(serviceName, ServiceConfigPreferred_node)
	if err != nil {
		return nil, err
	}
	return parsePreferredNode(buf)
}

func (sb *RPCCon) SetServiceDescription(serviceName, description string) error {
	log.Traceln("In SetServiceDescription")
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:   ServiceConfigDescription,
		Description: &ServiceDescriptionW{Description: &description},
	})
}

func (sb *RPCCon) SetServiceFailureActions(serviceName string, fa *ServiceFailureActions) error {
	log.Traceln("In SetServiceFailureActions")
	w := &ServiceFailureActionsW{
		ResetPeriod: fa.ResetPeriod,
		RebootMsg:   fa.RebootMsg,
		Command:     fa.Command,
		CActions:    uint32(len(fa.Actions)),
		Actions:     fa.Actions,
	}
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:      ServiceConfigFailure_actions,
		FailureActions: w,
	})
}

func (sb *RPCCon) SetServiceDelayedAutoStartInfo(serviceName string, enabled bool) error {
	log.Traceln("In SetServiceDelayedAutoStartInfo")
	var val uint32
	if enabled {
		val = 1
	}
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:            ServiceConfigDelayed_auto_start_info,
		DelayedAutoStartInfo: &ServiceDelayedAutoStartInfoW{DelayedAutoStart: val},
	})
}

func (sb *RPCCon) SetServiceFailureActionsFlag(serviceName string, enabled bool) error {
	log.Traceln("In SetServiceFailureActionsFlag")
	var val uint32
	if enabled {
		val = 1
	}
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:          ServiceConfigFailure_actions_flag,
		FailureActionsFlag: &ServiceFailureActionsFlagW{Flag: val},
	})
}

func (sb *RPCCon) SetServiceSIDInfo(serviceName string, sidType uint32) error {
	log.Traceln("In SetServiceSIDInfo")
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:      ServiceConfigService_sid_info,
		ServiceSIDInfo: &ServiceSIDInfoW{ServiceSidType: sidType},
	})
}

func (sb *RPCCon) SetServiceRequiredPrivileges(serviceName string, privileges []string) error {
	log.Traceln("In SetServiceRequiredPrivileges")
	// RequiredPrivileges should be a sequence of null-terminated strings, terminated by an empty string (\0)
	multiSz := ""
	for _, str := range privileges {
		multiSz += msdtyp.NullTerminate(str)
	}
	multiSz += "\x00\x00" // Add empty null terminated string
	multiSzBuf := msdtyp.ToUnicode(multiSz)
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel: ServiceConfigRequired_privileges_info,
		RequiredPrivilegesInfo: &ServiceRequiredPrivilegesInfoW{
			CbRequiredPrivileges: uint32(len(multiSzBuf)),
			RequiredPrivileges:   multiSzBuf,
		},
	})
}

func (sb *RPCCon) SetServicePreshutdownInfo(serviceName string, timeout uint32) error {
	log.Traceln("In SetServicePreshutdownInfo")
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel:       ServiceConfigPreshutdown_info,
		PreshutdownInfo: &ServicePreshutdownInfoW{PreshutdownTimeout: timeout},
	})
}

func (sb *RPCCon) SetServicePreferredNode(serviceName string, info *ServicePreferredNodeInfo) error {
	log.Traceln("In SetServicePreferredNode")
	return sb.ChangeServiceConfig2(serviceName, &ConfigInfoW{
		InfoLevel: ServiceConfigPreferred_node,
		PreferredNodeInfo: &ServicePreferredNodeInfoW{
			PreferredNode: info.PreferredNode,
			Delete:        info.Delete,
		},
	})
}

func (sb *RPCCon) ChangeServiceConfig(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName *string, password string, displayName *string, loadOrderGroup *string, dependencies string, tagId uint32) (err error) {

	log.Traceln("In ChangeServiceConfig")
	multiSz := ""
	parts := strings.Split(dependencies, "/")
	for _, str := range parts {
		if str == "" {
			continue
		}
		multiSz += msdtyp.NullTerminate(str)
	}
	multiSz += "\x00\x00"
	multiSzBuf := msdtyp.ToUnicode(multiSz)

	// Opening a named service only needs SC_MANAGER_CONNECT on the SCM
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, ServiceChangeConfig)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var svcHandle [20]byte
	copy(svcHandle[:], serviceHandle)

	innerReq := RChangeServiceConfigWReq{
		ServiceHandle:    svcHandle,
		ServiceType:      serviceType,
		StartType:        startType,
		ErrorControl:     errorControl,
		BinaryPathName:   binaryPathName,
		LoadOrderGroup:   loadOrderGroup,
		ServiceStartName: serviceStartName,
		DisplayName:      displayName,
		DependSize:       uint32(len(multiSzBuf)),
	}
	if multiSzBuf != nil {
		innerReq.Dependencies = &multiSzBuf
	}

	//NOTE that tag cannot be set. A value > 0 means: ask server for a tag id.
	if tagId != 0 {
		innerReq.TagId = &tagId
	}

	/*
	   MS-SCMR Section 3.1.4.12 explains that in RPC over TCP, the password should be plaintext,
	   but over SMB it must be encrypted
	*/
	if password != "" {
		uncPassword := msdtyp.ToUnicode(password + "\x00")
		encPassword, err := dcerpc.EncryptSecretDes(sb.GetSessionKey(), uncPassword)
		if err != nil {
			return err
		}
		innerReq.Password = &encPassword
		innerReq.PwSize = uint32(len(encPassword))
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRChangeServiceConfigW, innerBuf)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res := RChangeServiceConfigWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}
	if err = checkReturnCode("RChangeServiceConfigW", res.ReturnCode); err != nil {
		return err
	}

	return
}

func (sb *RPCCon) ChangeServiceConfig2(serviceName string, info *ConfigInfoW) (err error) {
	log.Traceln("In ChangeServiceConfig2")
	// Opening the SCM needs only SC_MANAGER_CONNECT. The service handle needs
	// SERVICE_CHANGE_CONFIG, plus SERVICE_START when the change configures an
	// SC_ACTION_RESTART failure action (see ConfigInfoW.RequiredServiceAccess).
	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, info.RequiredServiceAccess())
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var svcHandle [20]byte
	copy(svcHandle[:], serviceHandle)

	innerReq := RChangeServiceConfig2WReq{
		ServiceHandle: svcHandle,
		Info:          *info,
	}
	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeRequest(SvcCtlRChangeServiceConfig2W, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	if len(buffer) < 4 {
		err = fmt.Errorf("response too small for RChangeServiceConfig2W")
		return
	}
	errorCode := binary.LittleEndian.Uint32(buffer[:4])

	if err = checkReturnCode("RChangeServiceConfig2W", errorCode); err != nil {
		return err
	}

	return
}

func (sb *RPCCon) CreateService(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName, password, displayName string, startService bool) (err error) {

	log.Traceln("In CreateService")

	scHandle, err := sb.openSCManager(SCManagerCreateService)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(scHandle)

	var ctxHandle [20]byte
	copy(ctxHandle[:], scHandle)

	innerReq := RCreateServiceWReq{
		SCContextHandle: ctxHandle,
		ServiceName:     serviceName,
		DesiredAccess:   ServiceAllAccess,
		ServiceType:     serviceType,
		StartType:       startType,
		ErrorControl:    errorControl,
		BinaryPathName:  binaryPathName,
	}
	if displayName != "" {
		innerReq.DisplayName = &displayName
	}
	if serviceStartName != "" {
		innerReq.ServiceStartName = &serviceStartName
	}

	/*
	   MS-SCMR Section 3.1.4.12 explains that in RPC over TCP, the password should be plaintext,
	   but over SMB it must be encrypted
	*/
	if password != "" {
		uncPassword := msdtyp.ToUnicode(password + "\x00")
		encPassword, err := dcerpc.EncryptSecretDes(sb.GetSessionKey(), uncPassword)
		if err != nil {
			return err
		}
		innerReq.Password = &encPassword
		innerReq.PwSize = uint32(len(encPassword))
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRCreateServiceW, innerBuf)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res := RCreateServiceWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}
	if err = checkReturnCode("RCreateServiceW", res.ReturnCode); err != nil {
		return err
	}

	defer sb.CloseServiceHandle(res.ContextHandle[:])

	if startService {
		ssHandle := res.ContextHandle
		ssReq := RStartServiceWReq{ServiceHandle: ssHandle}

		ssBuf, err2 := ssReq.Marshal()
		if err != nil {
			return err2
		}

		buffer, err2 := sb.MakeRequest(SvcCtlRStartServiceW, ssBuf)
		if err != nil {
			return err2
		}

		returnValue := binary.LittleEndian.Uint32(buffer)
		if err = checkReturnCode("RStartServiceW", returnValue); err != nil {
			return err
		}
	}

	return
}

func (sb *RPCCon) DeleteService(serviceName string) (err error) {
	scHandle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(scHandle)
	handle, err := sb.openService(scHandle, serviceName, ServiceDelete)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)

	// Attempt to stop the service before deletion
	var stopHandle [20]byte
	copy(stopHandle[:], handle)
	csReq := RControlServiceReq{
		ServiceHandle: stopHandle,
		Control:       ServiceControlStop,
	}
	csBuf, err := csReq.Marshal()
	if err != nil {
		return
	}

	_, err = sb.MakeRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		log.Warningln(err)
		// Continue with deletion even if stop failed for some reason
	}

	var delHandle [20]byte
	copy(delHandle[:], handle)
	innerReq := RDeleteServiceReq{
		ServiceHandle: delHandle,
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRDeleteService, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("invalid response to RDeleteServiceReq")
		return
	}

	returnCode := le.Uint32(buffer[:4])

	if err = checkReturnCode("RDeleteServiceReq", returnCode); err != nil {
		return err
	}

	return
}

// queryObjectSecurity issues RQueryServiceObjectSecurity (Opnum 4) against an
// already-open SC_RPC_HANDLE — either a service handle from openService or the
// SCM database handle from openSCManager — and returns the raw self-relative
// SECURITY_DESCRIPTOR bytes for the requested SECURITY_INFORMATION. It issues
// the call twice: once with a zero buffer to learn the required size, then again
// with the size reported by the server.
func (sb *RPCCon) queryObjectSecurity(handle []byte, securityInformation uint32) (result []byte, err error) {
	log.Traceln("In queryObjectSecurity")

	var objHandle [20]byte
	copy(objHandle[:], handle)

	innerReq := RQueryServiceObjectSecurityReq{
		ServiceHandle:       objHandle,
		SecurityInformation: securityInformation,
		BufSize:             0,
	}
	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeRequest(SvcCtlRQueryServiceObjectSecurity, innerBuf)
	if err != nil {
		return
	}

	res := RQueryServiceObjectSecurityRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	// The size probe (empty buffer) is expected to fail with
	// ERROR_INSUFFICIENT_BUFFER; any other code is a real error.
	if res.ErrorCode != ErrorInsufficientBuffer {
		if err = checkReturnCode("RQueryServiceObjectSecurity", res.ErrorCode); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("RQueryServiceObjectSecurity: unexpected success on size probe")
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err = sb.MakeRequest(SvcCtlRQueryServiceObjectSecurity, innerBuf2)
	if err != nil {
		return
	}

	res = RQueryServiceObjectSecurityRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("RQueryServiceObjectSecurity", res.ErrorCode); err != nil {
		return nil, err
	}

	result = res.SecurityDescriptor
	return
}

// queryServiceObjectSecurity reads the requested portions of a service's
// security descriptor and returns the raw self-relative SECURITY_DESCRIPTOR
// bytes. The service handle is opened with the least privilege required to read
// the requested SECURITY_INFORMATION: READ_CONTROL for OWNER/GROUP/DACL plus
// ACCESS_SYSTEM_SECURITY only when the SACL is requested.
func (sb *RPCCon) queryServiceObjectSecurity(serviceName string, securityInformation uint32) (result []byte, err error) {
	log.Traceln("In queryServiceObjectSecurity")

	var desiredAccess uint32 = ReadControl
	if securityInformation&SaclSecurityInformation != 0 {
		desiredAccess |= AccessSystemSecurity
	}

	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, desiredAccess)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	return sb.queryObjectSecurity(serviceHandle, securityInformation)
}

// querySCManagerObjectSecurity reads the requested portions of the SCM
// database's own security descriptor and returns the raw self-relative
// SECURITY_DESCRIPTOR bytes. Unlike queryServiceObjectSecurity it queries the
// SCM handle directly without opening a service, and so the SCM handle itself is
// opened with the least privilege required to read the requested
// SECURITY_INFORMATION: READ_CONTROL for OWNER/GROUP/DACL plus
// ACCESS_SYSTEM_SECURITY only when the SACL is requested.
func (sb *RPCCon) querySCManagerObjectSecurity(securityInformation uint32) (result []byte, err error) {
	log.Traceln("In querySCManagerObjectSecurity")

	var desiredAccess uint32 = ReadControl
	if securityInformation&SaclSecurityInformation != 0 {
		desiredAccess |= AccessSystemSecurity
	}

	handle, err := sb.openSCManager(desiredAccess)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)

	return sb.queryObjectSecurity(handle, securityInformation)
}

// GetServiceSecurityBytes reads the requested SECURITY_INFORMATION of a service
// and returns the raw self-relative SECURITY_DESCRIPTOR bytes. For a parsed
// result, use GetServiceSecurity.
func (sb *RPCCon) GetServiceSecurityBytes(serviceName string, securityInformation uint32) ([]byte, error) {
	return sb.queryServiceObjectSecurity(serviceName, securityInformation)
}

// GetServiceSecurity reads the requested SECURITY_INFORMATION of a service and
// returns the parsed security descriptor.
func (sb *RPCCon) GetServiceSecurity(serviceName string, securityInformation uint32) (*msdtyp.SecurityDescriptor, error) {
	log.Traceln("In GetServiceSecurity")
	buf, err := sb.queryServiceObjectSecurity(serviceName, securityInformation)
	if err != nil {
		return nil, err
	}
	sd := &msdtyp.SecurityDescriptor{}
	if err = sd.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return sd, nil
}

// GetSCManagerSecurityBytes reads the requested SECURITY_INFORMATION of the SCM
// database itself and returns the raw self-relative SECURITY_DESCRIPTOR bytes.
// For a parsed result, use GetSCManagerSecurity.
func (sb *RPCCon) GetSCManagerSecurityBytes(securityInformation uint32) ([]byte, error) {
	return sb.querySCManagerObjectSecurity(securityInformation)
}

// GetSCManagerSecurity reads the requested SECURITY_INFORMATION of the SCM
// database itself and returns the parsed security descriptor.
func (sb *RPCCon) GetSCManagerSecurity(securityInformation uint32) (*msdtyp.SecurityDescriptor, error) {
	log.Traceln("In GetSCManagerSecurity")
	buf, err := sb.querySCManagerObjectSecurity(securityInformation)
	if err != nil {
		return nil, err
	}
	sd := &msdtyp.SecurityDescriptor{}
	if err = sd.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return sd, nil
}

// setServiceObjectSecurity writes the requested portions of a service's
// security descriptor from the raw self-relative SECURITY_DESCRIPTOR bytes. The
// service handle is opened with the least privilege required to set the
// requested SECURITY_INFORMATION: WRITE_DAC for the DACL, WRITE_OWNER for the
// OWNER/GROUP, and ACCESS_SYSTEM_SECURITY for the SACL.
func (sb *RPCCon) setServiceObjectSecurity(serviceName string, securityInformation uint32, sd []byte) (err error) {
	log.Traceln("In setServiceObjectSecurity")

	var desiredAccess uint32
	if securityInformation&DaclSecurityInformation != 0 {
		desiredAccess |= WriteDac
	}
	if securityInformation&(OwnerSecurityInformation|GroupSecurityInformation) != 0 {
		desiredAccess |= WriteOwner
	}
	if securityInformation&SaclSecurityInformation != 0 {
		desiredAccess |= AccessSystemSecurity
	}
	if desiredAccess == 0 {
		err = fmt.Errorf("setServiceObjectSecurity: invalid SecurityInformation, no OWNER, GROUP, DACL, or SACL bit set")
		return
	}

	handle, err := sb.openSCManager(SCManagerConnect)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(handle)
	serviceHandle, err := sb.openService(handle, serviceName, desiredAccess)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(serviceHandle)

	var svcHandle [20]byte
	copy(svcHandle[:], serviceHandle)

	innerReq := RSetServiceObjectSecurityReq{
		ServiceHandle:       svcHandle,
		SecurityInformation: securityInformation,
		SecurityDescriptor:  sd,
		BufSize:             uint32(len(sd)),
	}
	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRSetServiceObjectSecurity, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("invalid response to RSetServiceObjectSecurity")
		return
	}

	returnCode := le.Uint32(buffer[:4])
	if err = checkReturnCode("RSetServiceObjectSecurity", returnCode); err != nil {
		return err
	}

	return
}

// SetServiceSecurityBytes writes the requested SECURITY_INFORMATION of a service
// from the raw self-relative SECURITY_DESCRIPTOR bytes. For a typed input, use
// SetServiceSecurity.
func (sb *RPCCon) SetServiceSecurityBytes(serviceName string, securityInformation uint32, sd []byte) error {
	return sb.setServiceObjectSecurity(serviceName, securityInformation, sd)
}

// SetServiceSecurity writes the requested SECURITY_INFORMATION of a service from
// the provided security descriptor.
func (sb *RPCCon) SetServiceSecurity(serviceName string, securityInformation uint32, sd *msdtyp.SecurityDescriptor) error {
	log.Traceln("In SetServiceSecurity")
	buf, err := sd.MarshalBinary()
	if err != nil {
		return err
	}
	return sb.setServiceObjectSecurity(serviceName, securityInformation, buf)
}

func (sb *RPCCon) EnumServicesStatus(serviceType, serviceState uint32) (result []EnumServiceStatusW, err error) {
	log.Traceln("In EnumServicesStatus")

	scHandle, err := sb.openSCManager(SCManagerEnumerateService)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(scHandle)

	var ctxHandle [20]byte
	copy(ctxHandle[:], scHandle)

	enumSSReq := REnumServicesStatusWReq{
		SCContextHandle: ctxHandle,
		ServiceType:     serviceType,
		ServiceState:    serviceState,
		BufSize:         0,
		ResumeIndex:     0,
	}

	enumSSBuf, err := enumSSReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlREnumServicesStatusW, enumSSBuf)
	if err != nil {
		return
	}

	res := REnumServicesStatusWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	// The size probe is expected to fail with ERROR_MORE_DATA so the server
	// reports the required buffer size; any other code is a real error.
	if res.ReturnCode != ErrorMoreData {
		if err = checkReturnCode("REnumServicesStatusW", res.ReturnCode); err != nil {
			return
		}
		return
	}

	log.Debugf("Bytes needed: %d\n", res.BytesNeeded)

	enumSSReq.BufSize = res.BytesNeeded

	enumSSBuf, err = enumSSReq.Marshal()
	if err != nil {
		return
	}

	log.Debugln("Attempting to list all services")
	buffer, err = sb.MakeRequest(SvcCtlREnumServicesStatusW, enumSSBuf)
	if err != nil {
		return
	}

	res = REnumServicesStatusWRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		return
	}

	if err = checkReturnCode("REnumServicesStatusW", res.ReturnCode); err != nil {
		return
	}

	log.Debugf("Bytes needed: %d\n", res.BytesNeeded)
	log.Debugf("Services returned: %d\n", res.ServicesReturned)
	result = res.Services

	return
}

func (sb *RPCCon) CloseServiceHandle(serviceHandle []byte) {
	log.Traceln("In CloseServiceHandle")
	var handle [20]byte
	copy(handle[:], serviceHandle)
	closeReq := RCloseServiceHandleReq{
		ServiceHandle: handle,
	}
	closeBuf, err := closeReq.Marshal()
	if err != nil {
		log.Errorf("failed to encode close service handle request: %v", err)
		return
	}

	buffer, err := sb.MakeRequest(SvcCtlRCloseServiceHandle, closeBuf)
	if err != nil {
		log.Errorf("failed to close service handle: %v", err)
		return
	}
	res := RCloseServiceHandleRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorf("failed to unmarshal close service handle response: %v", err)
		return
	}

	// CloseServiceHandle has no error return, so a non-success status can
	// only be surfaced by logging it here.
	if err := checkReturnCode("RCloseServiceHandle", res.ReturnCode); err != nil {
		log.Errorln(err)
	}
}
