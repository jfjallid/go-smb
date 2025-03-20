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

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/msscmr")
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

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
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
func (sb *RPCCon) ChangeServiceConfigExt(serviceName string, config *ServiceConfig) (err error) {
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

func (sb *RPCCon) openSCManager(desiredAccess uint32) (handle []byte, err error) {
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

func (sb *RPCCon) openService(scHandle []byte, serviceName string, desiredAccess uint32) (handle []byte, err error) {
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

func (sb *RPCCon) GetServiceStatus(serviceName string) (status uint32, err error) {
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

func (sb *RPCCon) StartService(serviceName string, args []string) (err error) {
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

func (sb *RPCCon) ControlService(serviceName string, control uint32) (err error) {
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

func (sb *RPCCon) GetServiceConfig(serviceName string) (config ServiceConfig, err error) {
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

func (sb *RPCCon) GetServiceConfig2(serviceName string, infoLevel uint32) (result []byte, err error) {
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
func (sb *RPCCon) ChangeServiceConfig(
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
		uncPassword := msdtyp.ToUnicode(password + "\x00")
		encPassword, err := dcerpc.EncryptSecretDes(sb.GetSessionKey(), uncPassword)
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

func (sb *RPCCon) ChangeServiceConfig2(serviceName string, info *ConfigInfoW) (err error) {
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

func (sb *RPCCon) CreateService(
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
		uncPassword := msdtyp.ToUnicode(password + "\x00")
		encPassword, err := dcerpc.EncryptSecretDes(sb.GetSessionKey(), uncPassword)
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

func (sb *RPCCon) DeleteService(serviceName string) (err error) {
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

func (sb *RPCCon) EnumServicesStatus(serviceType, serviceState uint32) (result []EnumServiceStatusW, err error) {
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

func (sb *RPCCon) CloseServiceHandle(serviceHandle []byte) {
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
