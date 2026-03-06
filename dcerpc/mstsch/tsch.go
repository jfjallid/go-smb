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
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/mstsch")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidTsch                = "86D35949-83C9-4044-B424-DB363231FD0C"
	MSRPCTschPipe                = "atsvc"
	MSRPCTschMajorVersion uint16 = 1
	MSRPCTschMinorVersion uint16 = 0
)

// MS-TSCH Operations OP Codes
const (
	TschRpcRegisterTask   uint16 = 1
	TschRpcRetrieveTask   uint16 = 2
	TschRpcEnumInstances  uint16 = 8
	TschRpcStop           uint16 = 11
	TschRpcRun            uint16 = 12
	TschRpcDelete         uint16 = 13
	TschRpcGetLastRunInfo uint16 = 16
)

// SchRpcRegisterTask Flags (MS-TSCH Section 3.2.5.4.2)
const (
	TaskCreate                     uint32 = 0x00000000
	TaskUpdate                     uint32 = 0x00000004
	TaskCreateOrUpdate             uint32 = 0x00000006
	TaskDisable                    uint32 = 0x00000008
	TaskDontAddPrincipalAce        uint32 = 0x00000010
	TaskIgnoreRegistrationTriggers uint32 = 0x00000020
	TaskValidateOnly               uint32 = 0x00000040
)

// Logon Types (MS-TSCH Section 2.3.9)
const (
	TaskLogonNone                          uint32 = 0
	TaskLogonPassword                      uint32 = 1
	TaskLogonS4U                           uint32 = 2
	TaskLogonInteractiveToken              uint32 = 3
	TaskLogonGroup                         uint32 = 4
	TaskLogonServiceAccount                uint32 = 5
	TaskLogonInteractiveTokenOrPassword    uint32 = 6
)

// SchRpcRun Flags (MS-TSCH Section 3.2.5.4.7)
const (
	TaskRunNoFlags          uint32 = 0x00000000
	TaskRunAsSelf           uint32 = 0x00000001
	TaskRunIgnoreConstraints uint32 = 0x00000002
	TaskRunUseSessionId     uint32 = 0x00000004
	TaskRunUserSid          uint32 = 0x00000008
)

// HRESULT error codes for MS-TSCH
const (
	SOk                           uint32 = 0x00000000
	SchedSTaskReady               uint32 = 0x00041300
	SchedSTaskRunning             uint32 = 0x00041301
	SchedSTaskDisabled            uint32 = 0x00041302
	SchedSTaskHasNotRun           uint32 = 0x00041303
	SchedSTaskNoMoreRuns          uint32 = 0x00041304
	SchedSTaskNotScheduled        uint32 = 0x00041305
	SchedSTaskTerminated          uint32 = 0x00041306
	SchedSTaskNoValidTriggers     uint32 = 0x00041307
	SchedSEventTrigger            uint32 = 0x00041308
	SchedETaskNotReady            uint32 = 0x8004130A
	SchedETaskNotRunning          uint32 = 0x8004130B
	SchedEServiceNotInstalled     uint32 = 0x8004130C
	SchedECannotOpenTask          uint32 = 0x8004130D
	SchedEInvalidTask             uint32 = 0x8004130E
	SchedEAccountInformationNotSet uint32 = 0x8004130F
	SchedEAccountNameNotFound     uint32 = 0x80041310
	SchedEAccountDbaseCorrupt     uint32 = 0x80041311
	SchedENoSecurityServices      uint32 = 0x80041312
	SchedEUnknownObjectVersion    uint32 = 0x80041313
	SchedEAlreadyRunning          uint32 = 0x8004131F
	SchedETaskNotV1Compatible     uint32 = 0x80041327
	ErrorInvalidAccess            uint32 = 0x0000000C
	EAccessDenied                 uint32 = 0x80070005
	EInvalidArg                   uint32 = 0x80070057
	EFileNotFound                 uint32 = 0x80070002
	EAlreadyExists                uint32 = 0x800700B7
	RpcEInvalidBound              uint32 = 0x6C000008
)

var TschResponseCodeMap = map[uint32]error{
	SOk:                            nil,
	SchedSTaskReady:                fmt.Errorf("SCHED_S_TASK_READY: task is ready to run"),
	SchedSTaskRunning:              fmt.Errorf("SCHED_S_TASK_RUNNING: task is currently running"),
	SchedSTaskDisabled:             fmt.Errorf("SCHED_S_TASK_DISABLED: task is disabled"),
	SchedSTaskHasNotRun:            fmt.Errorf("SCHED_S_TASK_HAS_NOT_RUN: task has not yet run"),
	SchedSTaskNoMoreRuns:           fmt.Errorf("SCHED_S_TASK_NO_MORE_RUNS: no more scheduled runs"),
	SchedSTaskNotScheduled:         fmt.Errorf("SCHED_S_TASK_NOT_SCHEDULED: task is not scheduled"),
	SchedSTaskTerminated:           fmt.Errorf("SCHED_S_TASK_TERMINATED: task was terminated"),
	SchedSTaskNoValidTriggers:      fmt.Errorf("SCHED_S_TASK_NO_VALID_TRIGGERS: task has no valid triggers"),
	SchedSEventTrigger:             fmt.Errorf("SCHED_S_EVENT_TRIGGER: event trigger fired"),
	SchedETaskNotReady:             fmt.Errorf("SCHED_E_TASK_NOT_READY"),
	SchedETaskNotRunning:           fmt.Errorf("SCHED_E_TASK_NOT_RUNNING"),
	SchedEServiceNotInstalled:      fmt.Errorf("SCHED_E_SERVICE_NOT_INSTALLED"),
	SchedECannotOpenTask:           fmt.Errorf("SCHED_E_CANNOT_OPEN_TASK"),
	SchedEInvalidTask:              fmt.Errorf("SCHED_E_INVALID_TASK"),
	SchedEAccountInformationNotSet: fmt.Errorf("SCHED_E_ACCOUNT_INFORMATION_NOT_SET"),
	SchedEAccountNameNotFound:      fmt.Errorf("SCHED_E_ACCOUNT_NAME_NOT_FOUND"),
	SchedEAccountDbaseCorrupt:      fmt.Errorf("SCHED_E_ACCOUNT_DBASE_CORRUPT"),
	SchedENoSecurityServices:       fmt.Errorf("SCHED_E_NO_SECURITY_SERVICES"),
	SchedEUnknownObjectVersion:     fmt.Errorf("SCHED_E_UNKNOWN_OBJECT_VERSION"),
	SchedEAlreadyRunning:           fmt.Errorf("SCHED_E_ALREADY_RUNNING"),
	SchedETaskNotV1Compatible:      fmt.Errorf("SCHED_E_TASK_NOT_V1_COMPAT"),
	ErrorInvalidAccess:             fmt.Errorf("ERROR_INVALID_ACCESS: logon type incompatible with task principal"),
	EAccessDenied:                  fmt.Errorf("E_ACCESSDENIED"),
	EInvalidArg:                    fmt.Errorf("E_INVALIDARG"),
	EFileNotFound:                  fmt.Errorf("E_FILE_NOT_FOUND"),
	EAlreadyExists:                 fmt.Errorf("E_ALREADY_EXISTS"),
	RpcEInvalidBound:               fmt.Errorf("RPC_X_INVALID_BOUND"),
}

// TaskResultCodeMap maps well-known task last-run result codes to
// human-readable descriptions. These codes appear as the lastReturnCode
// from SchRpcGetLastRunInfo, combining SCHED_S/SCHED_E status values
// and common Win32 exit codes.
var TaskResultCodeMap = map[uint32]string{
	// Success / standard Win32
	0x00000000: "The operation completed successfully",
	0x00000001: "Incorrect function called",
	0x00000002: "File not found",
	0x00000005: "Access is denied",
	0x0000000A: "The environment is incorrect",
	0x00000041: "Network access is denied",
	0x00000057: "The parameter is incorrect",

	// SCHED_S informational
	0x00041300: "Task is ready to run at its next scheduled time",
	0x00041301: "Task is currently running",
	0x00041302: "Task is disabled",
	0x00041303: "Task has not yet run",
	0x00041304: "There are no more runs scheduled for this task",
	0x00041305: "One or more of the properties needed to run this task have not been set",
	0x00041306: "The last run of the task was terminated by the user",
	0x00041307: "Either the task has no triggers or the existing triggers are disabled or not set",
	0x00041308: "Event triggers do not have set run times",
	0x00041309: "A task's trigger was not found",
	0x0004130A: "One or more of the properties required to run this task have not been set",
	0x0004130B: "There is no running instance of the task",
	0x0004130C: "The Task Scheduler service is not installed on this computer",
	0x0004130D: "The task object could not be opened",
	0x0004130E: "The object is either an invalid task object or is not a task object",
	0x0004130F: "No account information could be found in the Task Scheduler security database for the task indicated",
	0x00041310: "Unable to establish existence of the account specified",
	0x00041311: "Corruption was detected in the Task Scheduler security database",
	0x00041312: "Task Scheduler security services are available only on Windows NT",
	0x00041313: "The task object version is either unsupported or invalid",
	0x00041314: "The task has been configured with an unsupported combination of account settings and run time options",
	0x00041315: "The Task Scheduler service is not running",
	0x00041316: "The task XML contains an unexpected node",
	0x00041317: "The task XML contains an element or attribute from an unexpected namespace",
	0x00041318: "The task XML contains a value which is incorrectly formatted or out of range",
	0x00041319: "The task XML is missing a required element or attribute",
	0x0004131A: "The task XML is malformed",
	0x0004131B: "The task is registered, but not all specified triggers will start the task",
	0x0004131C: "The task is registered, but may fail to start. Batch logon privilege needs to be enabled",
	0x0004131D: "The task XML contains too many nodes of the same type",
	0x0004131F: "The task is already running",
	0x00041320: "The task will not run because the user is not logged on",
	0x00041321: "The task image is corrupt or has been tampered with",
	0x00041322: "The Task Scheduler service is not available",
	0x00041323: "The Task Scheduler service is too busy to handle your request",
	0x00041324: "The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition",
	0x00041325: "The Task Scheduler service has asked the task to run",
	0x00041326: "The task is disabled",
	0x00041327: "The task has properties that are not compatible with earlier versions of Windows",
	0x00041328: "The task settings do not allow the task to start on demand",

	// Common HRESULT errors
	0x80010002: "Call was canceled by the message filter",
	0x80040154: "Class not registered",
	0x80070002: "The system cannot find the file specified",
	0x80070005: "Access is denied",
	0x8007000D: "The data is invalid",
	0x8007000E: "Not enough storage is available to complete this operation",
	0x80070057: "The parameter is incorrect",
	0x800700B7: "Cannot create a file when that file already exists",
	0x800704DD: "The service is not active, task not started",
	0x800710E0: "The operator or administrator has refused the request",
	0xC000013A: "The application terminated as a result of CTRL+C",
}

// TaskResultToString resolves a task last-run result code to a
// human-readable description. Returns the description and true if
// the code is known, or an empty string and false otherwise.
func TaskResultToString(code uint32) (string, bool) {
	desc, ok := TaskResultCodeMap[code]
	return desc, ok
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

func (r *RPCCon) RegisterTask(path, xml string, flags, logonType uint32) (actualPath string, err error) {
	log.Traceln("In RegisterTask")

	req := SchRpcRegisterTaskReq{
		Path:      path,
		Xml:       xml,
		Flags:     flags,
		Sddl:      "",
		LogonType: logonType,
		CCreds:    0,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcRegisterTask, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := SchRpcRegisterTaskRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != SOk {
		status, found := TschResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("SchRpcRegisterTask returned unknown error code: 0x%x", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return "", status
	}

	actualPath = res.ActualPath
	return
}

func (r *RPCCon) DeleteTask(path string, flags uint32) (err error) {
	log.Traceln("In DeleteTask")

	req := SchRpcDeleteReq{
		Path:  path,
		Flags: flags,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcDelete, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("Response too small for SchRpcDelete")
		log.Errorln(err)
		return
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode != SOk {
		status, found := TschResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("SchRpcDelete returned unknown error code: 0x%x", returnCode)
			log.Errorln(err)
			return
		}
		return status
	}

	return
}

func (r *RPCCon) RunTask(path string, flags, sessionId uint32, user string) (guid [16]byte, err error) {
	log.Traceln("In RunTask")

	req := SchRpcRunReq{
		Path:      path,
		Flags:     flags,
		SessionId: sessionId,
		User:      user,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcRun, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := SchRpcRunRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != SOk {
		status, found := TschResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("SchRpcRun returned unknown error code: 0x%x", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return guid, status
	}

	guid = res.GUID
	return
}

func (r *RPCCon) GetLastRunInfo(path string) (lastRunTime SYSTEMTIME, lastReturnCode uint32, err error) {
	log.Traceln("In GetLastRunInfo")

	req := SchRpcGetLastRunInfoReq{
		Path: path,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcGetLastRunInfo, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := SchRpcGetLastRunInfoRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != SOk {
		status, found := TschResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("SchRpcGetLastRunInfo returned unknown error code: 0x%x", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return lastRunTime, 0, status
	}

	lastRunTime = res.LastRunTime
	lastReturnCode = res.LastReturnCode
	return
}

func (r *RPCCon) EnumInstances(path string, flags uint32) (guids [][16]byte, err error) {
	log.Traceln("In EnumInstances")

	req := SchRpcEnumInstancesReq{
		Path:  path,
		Flags: flags,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcEnumInstances, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := SchRpcEnumInstancesRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != SOk {
		status, found := TschResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("SchRpcEnumInstances returned unknown error code: 0x%x", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return nil, status
	}

	guids = res.Guids
	return
}

func (r *RPCCon) StopTask(path string, flags uint32) (err error) {
	log.Traceln("In StopTask")

	req := SchRpcStopReq{
		Path:  path,
		Flags: flags,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcStop, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("Response too small for SchRpcStop")
		log.Errorln(err)
		return
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode != SOk {
		status, found := TschResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("SchRpcStop returned unknown error code: 0x%x", returnCode)
			log.Errorln(err)
			return
		}
		return status
	}

	return
}

func (r *RPCCon) RetrieveTask(path string) (xml string, err error) {
	log.Traceln("In RetrieveTask")

	req := SchRpcRetrieveTaskReq{
		Path: path,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(TschRpcRetrieveTask, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := SchRpcRetrieveTaskRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != SOk {
		status, found := TschResponseCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("SchRpcRetrieveTask returned unknown error code: 0x%x", res.ReturnCode)
			log.Errorln(err)
			return
		}
		return "", status
	}

	xml = res.Definition
	return
}

func GUIDToString(guid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		le.Uint32(guid[0:4]),
		le.Uint16(guid[4:6]),
		le.Uint16(guid[6:8]),
		guid[8:10],
		guid[10:16],
	)
}

func BuildExecTaskXML(command string, args string) string {
	argsElement := ""
	if args != "" {
		argsElement = fmt.Sprintf("\n        <Arguments>%s</Arguments>", args)
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description></Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2099-07-15T20:35:13.2757294</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>%s</Command>%s
    </Exec>
  </Actions>
</Task>`, command, argsElement)
}
