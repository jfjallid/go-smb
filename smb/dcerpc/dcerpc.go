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
package dcerpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc")

var (
	MSRPCSvcCtlPipe                       = "svcctl"
	MSRPCUuidSvcCtl                       = "367ABB81-9844-35F1-AD32-98F038001003"
	MSRPCSvcCtlMajorVersion uint16        = 2
	MSRPCSvcCtlMinorVersion uint16        = 0
	MSRPCUuidSrvSvc                       = "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	MSRPCSrvSvcMajorVersion uint16        = 3
	MSRPCSrvSvcMinorVersion uint16        = 0
	MSRPCUuidNdr                          = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	re                      regexp.Regexp = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)
	ContextItemLen                        = 44
	ContextResItemLen                     = 24
)

// MSRPC Packet Types
const (
	PacketTypeRequest  uint8 = 0
	PacketTypeResponse uint8 = 2
	PacketTypeBind     uint8 = 11
	PacketTypeBindAck  uint8 = 12
)

// MSRPC Server Service (srvsvc) Operations
const (
	SrvSvcOpNetShareEnumAll uint16 = 15
)

// MS-SCMR Operations OP Codes
const (
	SvcCtlRCloseServiceHandle   uint16 = 0
	SvcCtlRControlService       uint16 = 1
	SvcCtlRDeleteService        uint16 = 2
	SvcCtlRQueryServiceStatus   uint16 = 6
	SvcCtlRChangeServiceConfigW uint16 = 11
	SvcCtlRCreateServiceW       uint16 = 12
	SvcCtlROpenSCManagerW       uint16 = 15
	SvcCtlROpenServiceW         uint16 = 16
	SvcCtlRQueryServiceConfigW  uint16 = 17
	SvcCtlRStartServiceW        uint16 = 19
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
	ServiceKernelDriver:       "SERVICE_KERNEL_DRIVER",
	ServiceFileSystemDriver:   "SERVICE_FILE_SYSTEM_DRIVER",
	ServiceWin32OwnProcess:    "SERIVCE_WIN32_OWN_PROCESS",
	ServiceWin32ShareProcess:  "SERVICE_WIN32_SHARE_PROCESS",
	ServiceInteractiveProcess: "SERVICE_INTERACTIVE_PROCESS",
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

const (
	StypeDisktree    uint32 = 0x00000000 // Disk drive
	StypePrintq      uint32 = 0x00000001 // Print queue
	StypeDevice      uint32 = 0x00000002 // Communication device
	StypeIPC         uint32 = 0x00000003 // Interprocess communication (IPC)
	StypeClusterFS   uint32 = 0x02000000 // A cluster share
	StypeClusterSOFS uint32 = 0x04000000 // A Scale-Out cluster share
	StypeClusterDFS  uint32 = 0x08000000 // A DFS share in a cluster
	StypeSpecial     uint32 = 0x80000000 // Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth.
	StypeTemporary   uint32 = 0x40000000 // A temporary share that is not persisted for creation each time the file server initializes.
)

var ShareTypeMap = map[uint32]string{
	StypeDisktree:    "Disk Drive",
	StypePrintq:      "Print Queue",
	StypeDevice:      "Communication Device",
	StypeIPC:         "IPC",
	StypeClusterFS:   "Cluster Share",
	StypeClusterSOFS: "Scale-Out cluster share",
	StypeClusterDFS:  "DFS Share in cluster",
	StypeSpecial:     "Hidden",
	StypeTemporary:   "Temp",
}

// Unused
//type RPCClient interface {
//	Bind(interface_uuid, transfer_uuid string) (bool, error)
//	//Write()
//}

type ServiceBind struct {
	f *smb.File
}

type Header struct { // 16 bytes
	MajorVersion   byte
	MinorVersion   byte
	Type           byte
	Flags          byte
	Representation uint32
	FragLength     uint16
	AuthLength     uint16
	CallId         uint32
}

func newHeader() Header {
	return Header{
		MajorVersion:   5,
		MinorVersion:   0,
		Type:           0,
		Flags:          0x01 | 0x02,
		Representation: 0x00000010, // 0x10000000, // Little-endian, char = ASCII, float = IEEE
		FragLength:     72,         // Always 72
		AuthLength:     0,
		CallId:         0,
	}
}

type ContextItem struct { // 44 bytes size
	Id               uint16
	Count            byte
	Reserved         byte
	AbstractUUID     []byte `smb:"fixed:16"`
	BindMajorVersion uint16
	BindMinVersion   uint16
	TransferUUID     []byte `smb:"fixed:16"`
	TransferVersion  uint32
}

type ContextResItem struct { // 24 bytes size
	Result          uint32 // Perhaps only uint16 with 2 bytes padding after?
	TransferUUID    []byte `smb:"fixed:16"`
	TransferVersion uint32
}

type ContextItems []ContextItem
type ContextResItems []ContextResItem

type BindReq struct { // 28 bytes before Context list
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32
	CtxCount        byte   `smb:"count:Context"`
	Reserved        byte   // Alignment
	Reserved2       uint16 // Alignment
	Context         *ContextItems
}

type BindRes struct { // 28 bytes before Context list
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32
	SecAddrLen      uint16 `smb:"len:SecAddr"`
	SecAddr         []byte
	Align           []byte `smb:"align:4"`
	CtxCount        byte   `smb:"count:Context"`
	Reserved        byte   // Alignment
	Reserved2       uint16 // Alignment
	Context         *ContextResItems
}

type RequestReq struct { // 24 + len of Buffer
	Header    // 16 bytes
	AllocHint uint32
	ContextId uint16
	Opnum     uint16
	Buffer    []byte // Always start at an 8-byte boundary
}

type RequestRes struct {
	Header             // 16 bytes
	AllocHint   uint32 `smb:"len:Buffer"` // Not sure this field is guaranteed to contain buffer length
	ContextId   uint16
	CancelCount byte
	Reserved    byte
	Buffer      []byte // Always start at an 8-byte boundary
}

type UnicodeStr struct {
	ReferentIdPtr uint32 `smb:"omitempty:0"`
	MaxCount      uint32
	Offset        uint32 // Defaults to 0
	ActualCount   uint32
	EncodedString []byte //utf16le encoded string
	Padd          []byte `smb:"align:4"`
}

type Level struct {
	Lvl uint32
}

type TotalEntries struct {
	Padd []byte `smb:"align:4"`
	Lvl  uint32
}

type ShareName struct {
	UnicodeStr
}

type NetShareInfo1 struct {
	ReferentId uint32
	MaxCount   uint32
}

type ShareInfo1 struct {
	Name    *UnicodeStr
	Type    uint32
	Comment *UnicodeStr
}

type NetShare struct {
	Name    string
	Comment string
	Type    string
	TypeId  uint32
	Hidden  bool
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

type NetShareCtr1 struct {
	Count   uint32
	Info    NetShareInfo1
	Pointer []ShareInfo1
}

type NetShareCtr struct {
	Ctr     uint32 // Type of Ctr struct in Pointer
	Pointer interface{}
}

type ResumeHandle struct {
	ReferentId uint32
	Handle     uint32
}

type NetShareEnumAllRequest struct {
	ServerName *UnicodeStr
	Level
	NetShareCtr
	MaxBuffer uint32
	ResumeHandle
}

type NetShareEnumAllResponse struct {
	Level        uint32
	NetShareCtr  *NetShareCtr
	TotalEntries uint32
	*ResumeHandle
	WindowsError uint32
}

type ROpenSCManagerWRequest struct {
	MachineName   UnicodeStr
	DatabaseName  UnicodeStr
	DesiredAccess uint32
}

type ROpenSCManagerWResponse struct {
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type ROpenServiceWRequest struct {
	SCContextHandle []byte `smb:"fixed:20"`
	ServiceName     *UnicodeStr
	DesiredAccess   uint32
}

type ROpenServiceWResponse struct {
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

/*24 bytes between ErrorControl and BinaryPathName seems to contain
  Maximum counts of 4 bytes for All the dimensions of the array.
  That would be if the array contains 6 members (2 strings, 1 DWORD and then 3 more strings.
  That would account for 6*4 bytes = 24. The values would be:
  0x00020000, 0x00020004, 0x00000000, 0x00020008, 0x0002000c, 0x00020010
  Not sure why this is so but the only Theory that seems to fit the data.*/

// MS-SCMR Section 2.2.15
type QueryServiceConfigW struct {
	ServiceType   uint32
	StartType     uint32
	ErrorControl  uint32
	ArrayMaxSizes []uint32 `smb:"count:6"` // The data after this is a complex structure
	// and I simplify parsing here by ignoring the preceeding array max counts before each array
	// item since this seems to be a Structure containing a Conformant and variying array.
	BinaryPathName   UnicodeStr
	LoadOrderGroup   UnicodeStr
	TagId            uint32
	Dependencies     UnicodeStr
	ServiceStartName UnicodeStr
	DisplayName      UnicodeStr
}

type RQueryServiceConfigWRequest struct {
	ServiceHandle []byte `smb:"fixed:20"`
	BufSize       uint32
}

type RQueryServiceConfigWResponse struct {
	ServiceConfig *QueryServiceConfigW
	BytesNeeded   uint32
	ErrorCode     uint32
}

/*
NOTE If A value is empty e.g. NULL, that is represented by 4 null bytes
e.g., Don't specifying a BinaryPathName? Just put 0x00 0x00 0x00 0x00 as a null pointer
*/
type RChangeServiceConfigWRequest struct {
	ServiceHandle    []byte `smb:"fixed:20"`
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *UnicodeStr
	LoadOrderGroup   *UnicodeStr
	TagId            uint32
	Dependencies     *UnicodeStr // Not sure this is the correct type
	DependSize       uint32
	ServiceStartName *UnicodeStr
	Password         *UnicodeStr // Not sure this is the correct type
	PwSize           uint32
	DisplayName      *UnicodeStr
}

type RChangeServiceConfigWResponse struct {
	TagId      uint32
	ReturnCode uint32
}

type RCreateServiceRequest struct {
	SCContextHandle  []byte `smb:"fixed:20"`
	ServiceName      *UnicodeStr
	DisplayName      *UnicodeStr
	DesiredAccess    uint32
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *UnicodeStr
	LoadOrderGroup   *UnicodeStr
	TagId            uint32
	Dependencies     *UnicodeStr
	DependSize       uint32
	ServiceStartName *UnicodeStr
	Password         *UnicodeStr
	PwSize           uint32
}

type RCreateServiceResponse struct {
	TagId         uint32
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

type RQueryServiceStatusRequest struct {
	ContextHandle []byte `smb:"fixed:20"`
}

type RQueryServiceStatusResponse struct {
	ServiceStatus
	ReturnCode uint32
}

type ServiceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type RStartServiceWRequest struct {
	ServiceHandle []byte `smb:"fixed:20"`
	Argc          uint32 `smb:"count:Argv"`
	Argv          []UnicodeStr
}

type RControlServiceRequest struct {
	ServiceHandle []byte `smb:"fixed:20"`
	Control       uint32
}

type RControlServiceResponse struct {
	ServiceStatus
	ReturnValue uint32
}

type RDeleteServiceRequest struct {
	ServiceHandle []byte `smb:"fixed:20"`
}

type RDeleteServiceResponse struct {
	ReturnCode uint32
}

type RCloseServiceHandleReq struct {
	ServiceHandle []byte `smb:"fixed:20"`
}

type RCloseServiceHandleRes struct {
	ContextHandle []byte `smb:"fixed:20"`
	ReturnCode    uint32
}

func (s *ContextItems) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for ContextItems")
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, item := range *s {
		buf, err := encoder.Marshal(item)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *ContextItems) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for ContextItems")

	slice := []ContextItem{}
	c, ok := meta.Counts[meta.CurrField]
	if !ok {
		return fmt.Errorf("Cannot unmarshal field '%s'. Missing count\n", meta.CurrField)
	}
	for i := 0; i < int(c); i++ {
		var item ContextItem
		err := encoder.Unmarshal(buf[i*ContextItemLen:(i+1)*ContextItemLen], &item)
		if err != nil {
			return err
		}
		slice = append(slice, item)
	}

	*s = slice
	return nil
}

func (s *ContextResItems) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for ContextResItems")
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, item := range *s {
		buf, err := encoder.Marshal(item)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *ContextResItems) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for ContextResItems")

	slice := []ContextResItem{}
	c, ok := meta.Counts[meta.CurrField]
	if !ok {
		return fmt.Errorf("Cannot unmarshal field '%s'. Missing count\n", meta.CurrField)
	}
	for i := 0; i < int(c); i++ {
		var item ContextResItem
		err := encoder.Unmarshal(buf[i*ContextResItemLen:(i+1)*ContextResItemLen], &item)
		if err != nil {
			return err
		}
		slice = append(slice, item)
	}

	res := ContextResItems(slice)
	*s = res
	return nil
}

func (self *ContextItem) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for ContextItem")
	buf := make([]byte, 0, 43)
	buf = binary.LittleEndian.AppendUint16(buf, self.Id)
	buf = append(buf, self.Count)
	buf = append(buf, self.AbstractUUID...)
	buf = binary.LittleEndian.AppendUint16(buf, self.BindMajorVersion)
	buf = binary.LittleEndian.AppendUint16(buf, self.BindMinVersion)
	buf = append(buf, self.TransferUUID...)
	buf = binary.LittleEndian.AppendUint32(buf, self.TransferVersion)
	return buf, nil
}

func (self *ContextItem) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for ContextItem")
	self.Id = binary.LittleEndian.Uint16(buf)
	self.Count = buf[2]
	self.Reserved = buf[3]
	self.AbstractUUID = buf[4:20]
	self.BindMajorVersion = binary.LittleEndian.Uint16(buf[20:22])
	self.BindMinVersion = binary.LittleEndian.Uint16(buf[22:24])
	self.TransferUUID = buf[24:40]
	self.TransferVersion = binary.LittleEndian.Uint32(buf[40:44])
	return nil
}

func (self *RQueryServiceConfigWResponse) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Errorln("NOT IMPLEMENTED MarshalBinary of RQueryServiceConfigWResponse")
	return nil, nil
}

func (self *RQueryServiceConfigWResponse) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for RQueryServiceconfigWResponse")
	if len(buf) < 44 {
		return fmt.Errorf("Buffer to small for RQueryServiceConfigWResponse")
	}

	conf := QueryServiceConfigW{
		ServiceType:  binary.LittleEndian.Uint32(buf),
		StartType:    binary.LittleEndian.Uint32(buf[4:]),
		ErrorControl: binary.LittleEndian.Uint32(buf[8:]),
	}

	if len(buf) > 44 { // Perhaps full response
		conf.ArrayMaxSizes = make([]uint32, 6)
		conf.ArrayMaxSizes[0] = binary.LittleEndian.Uint32(buf[12:])
		conf.ArrayMaxSizes[1] = binary.LittleEndian.Uint32(buf[16:])
		conf.ArrayMaxSizes[2] = binary.LittleEndian.Uint32(buf[20:])
		conf.ArrayMaxSizes[3] = binary.LittleEndian.Uint32(buf[24:])
		conf.ArrayMaxSizes[4] = binary.LittleEndian.Uint32(buf[28:])
		conf.ArrayMaxSizes[5] = binary.LittleEndian.Uint32(buf[32:])
		//fmt.Printf("Array sizes: 0: %d, 1: %d, 2: %d, 3: %d, 4: %d, 5: %d\n", conf.ArrayMaxSizes[0], conf.ArrayMaxSizes[1], conf.ArrayMaxSizes[2], conf.ArrayMaxSizes[3], conf.ArrayMaxSizes[4], conf.ArrayMaxSizes[5])
		offset := uint32(36)

		us := UnicodeStr{
			MaxCount:    binary.LittleEndian.Uint32(buf[offset:]),
			Offset:      binary.LittleEndian.Uint32(buf[offset+4:]),
			ActualCount: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		us.EncodedString = make([]byte, us.ActualCount*2)
		copy(us.EncodedString, buf[offset+12:offset+12+us.ActualCount*2])
		padd := (us.ActualCount * 2) % 4
		if padd != 0 {
			padd = 4 - padd
			us.Padd = make([]byte, padd)
		}
		offset += 12 + us.ActualCount*2 + padd
		conf.BinaryPathName = us

		us = UnicodeStr{
			MaxCount:    binary.LittleEndian.Uint32(buf[offset:]),
			Offset:      binary.LittleEndian.Uint32(buf[offset+4:]),
			ActualCount: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		us.EncodedString = make([]byte, us.ActualCount*2)
		copy(us.EncodedString, buf[offset+12:offset+12+us.ActualCount*2])
		padd = (us.ActualCount * 2) % 4
		if padd != 0 {
			padd = 4 - padd
			us.Padd = make([]byte, padd)
		}
		offset += 12 + us.ActualCount*2 + padd
		conf.LoadOrderGroup = us

		if conf.ArrayMaxSizes[2] > 0 {
			//TODO Fix this part if I ever see a response with a non-zero TagId
			return fmt.Errorf("NOT IMPLEMENTED parsing of TagID from response when non-zero")

			//fmt.Printf("Before tagId. Offset: %d\n", offset)
			//tagMaxCount := binary.LittleEndian.Uint32(buf[offset:])
			////tagOffset := binary.LittleEndian.Uint32(buf[offset+4:])
			//tagActualCount := binary.LittleEndian.Uint32(buf[offset+8:])
			//tagLength := 4*tagActualCount
			//conf.TagId = binary.LittleEndian.Uint32(buf[offset+12:offset+12+tagLength])
			//fmt.Printf("After tagid before offset bump. Offset: %d, tagActualCount: %d, tagMaxCount: %d\n", offset, tagActualCount, tagMaxCount)
			//offset += 12+tagLength
		}

		//fmt.Printf("After tagId. Offset: %d, tagLength: %d\n", offset, tagLength)
		// Dependencies
		us = UnicodeStr{
			MaxCount:    binary.LittleEndian.Uint32(buf[offset:]),
			Offset:      binary.LittleEndian.Uint32(buf[offset+4:]),
			ActualCount: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		us.EncodedString = make([]byte, us.ActualCount*2)
		copy(us.EncodedString, buf[offset+12:offset+12+us.ActualCount*2])
		padd = (us.ActualCount * 2) % 4
		if padd != 0 {
			padd = 4 - padd
			us.Padd = make([]byte, padd)
		}
		offset += 12 + us.ActualCount*2 + padd
		conf.Dependencies = us

		// ServiceStartName
		us = UnicodeStr{
			MaxCount:    binary.LittleEndian.Uint32(buf[offset:]),
			Offset:      binary.LittleEndian.Uint32(buf[offset+4:]),
			ActualCount: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		us.EncodedString = make([]byte, us.ActualCount*2)
		copy(us.EncodedString, buf[offset+12:offset+12+us.ActualCount*2])
		padd = (us.ActualCount * 2) % 4
		if padd != 0 {
			padd = 4 - padd
			us.Padd = make([]byte, padd)
		}
		offset += 12 + us.ActualCount*2 + padd
		conf.ServiceStartName = us

		// DisplayName
		us = UnicodeStr{
			MaxCount:    binary.LittleEndian.Uint32(buf[offset:]),
			Offset:      binary.LittleEndian.Uint32(buf[offset+4:]),
			ActualCount: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		us.EncodedString = make([]byte, us.ActualCount*2)
		copy(us.EncodedString, buf[offset+12:offset+12+us.ActualCount*2])
		padd = (us.ActualCount * 2) % 4
		if padd != 0 {
			padd = 4 - padd
			us.Padd = make([]byte, padd)
		}
		offset += 12 + us.ActualCount*2 + padd
		conf.DisplayName = us
		self.BytesNeeded = binary.LittleEndian.Uint32(buf[len(buf)-8:])
		self.ErrorCode = binary.LittleEndian.Uint32(buf[len(buf)-4:])
	} else {
		// Empty Arrays
		self.BytesNeeded = binary.LittleEndian.Uint32(buf[36:])
		self.ErrorCode = binary.LittleEndian.Uint32(buf[40:])
	}
	self.ServiceConfig = &conf
	return nil
}

func (s *NetShareEnumAllRequest) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for NetShareEnumAllRequest")

	var ret []byte
	w := bytes.NewBuffer(ret)
	serverName, err := encoder.Marshal(s.ServerName)
	if err != nil {
		return nil, err
	}
	w.Write(serverName)
	binary.Write(w, binary.LittleEndian, s.Level.Lvl)
	binary.Write(w, binary.LittleEndian, s.NetShareCtr.Ctr)
	// TODO Do this properly e.g., check type of ctr and serialize it.
	binary.Write(w, binary.LittleEndian, uint32(2))
	binary.Write(w, binary.LittleEndian, make([]byte, 8))

	binary.Write(w, binary.LittleEndian, s.MaxBuffer)
	binary.Write(w, binary.LittleEndian, s.ResumeHandle.ReferentId)
	binary.Write(w, binary.LittleEndian, s.ResumeHandle.Handle)

	return w.Bytes(), nil
}

func (s *NetShareEnumAllRequest) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetShareEnumAllRequest")
}

func (s *NetShareEnumAllResponse) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshaBinary of NetShareEnumAllResponse")
}

func parseNetShareCtr1(buf []byte) (*NetShareCtr1, error) {
	log.Debugln("In parseNetShareCtr1")
	offset := 0
	res := &NetShareCtr1{
		Count: binary.LittleEndian.Uint32(buf[offset+4:]), // Skip over ReferentId
		Info: NetShareInfo1{
			MaxCount: binary.LittleEndian.Uint32(buf[offset+12:]),
		},
	}
	offset += 16
	arr := make([]ShareInfo1, res.Count)
	for i := 0; i < int(res.Count); i++ {
		arr[i].Name = &UnicodeStr{
			ReferentIdPtr: binary.LittleEndian.Uint32(buf[offset:]),
		}
		arr[i].Type = binary.LittleEndian.Uint32(buf[offset+4:])
		arr[i].Comment = &UnicodeStr{
			ReferentIdPtr: binary.LittleEndian.Uint32(buf[offset+8:]),
		}
		offset += 12
	}
	for i := 0; i < int(res.Count); i++ {
		arr[i].Name.MaxCount = binary.LittleEndian.Uint32(buf[offset:])
		arr[i].Name.Offset = binary.LittleEndian.Uint32(buf[offset+4:])
		arr[i].Name.ActualCount = binary.LittleEndian.Uint32(buf[offset+8:])
		nameLen := int(arr[i].Name.ActualCount)
		arr[i].Name.EncodedString = buf[offset+12 : offset+12+nameLen*2]
		paddLen := (nameLen * 2) % 4
		if paddLen != 0 {
			paddLen = 4 - paddLen
		}
		offset += 12 + nameLen*2 + paddLen

		arr[i].Comment.MaxCount = binary.LittleEndian.Uint32(buf[offset:])
		arr[i].Comment.Offset = binary.LittleEndian.Uint32(buf[offset+4:])
		arr[i].Comment.ActualCount = binary.LittleEndian.Uint32(buf[offset+8:])
		commentLen := int(arr[i].Comment.ActualCount)
		arr[i].Comment.EncodedString = buf[offset+12 : offset+12+commentLen*2]
		paddLen = (commentLen * 2) % 4
		if paddLen != 0 {
			paddLen = 4 - paddLen
		}
		offset += 12 + commentLen*2 + paddLen
	}
	res.Pointer = arr

	return res, nil
}

func (s *NetShareEnumAllResponse) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for NetShareEnumAllResponse")

	res := NetShareEnumAllResponse{
		Level: binary.LittleEndian.Uint32(buf),
	}
	if res.Level != 1 {
		return fmt.Errorf("Unrecognized ShareInfo level %d\n", res.Level)
	}
	offset := 4

	ctrType := binary.LittleEndian.Uint32(buf[offset:])
	var ctrPtr interface{}
	var err error
	switch ctrType {
	case 1:
		offset += 4
		ctrPtr, err = parseNetShareCtr1(buf[offset:])
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("NOT IMPLEMENTED NetShareEnumAllResponse CtrType %d\n", ctrType)
	}

	res.NetShareCtr = &NetShareCtr{
		Ctr:     ctrType,
		Pointer: ctrPtr,
	}

	totalLen := len(buf)
	res.TotalEntries = binary.LittleEndian.Uint32(buf[totalLen-16:])
	res.ResumeHandle = &ResumeHandle{
		Handle: binary.LittleEndian.Uint32(buf[totalLen-8:]),
	}
	res.WindowsError = binary.LittleEndian.Uint32(buf[totalLen-4:])

	*s = res
	return nil
}

func NewUnicodeStr(referentId uint32, s string) *UnicodeStr {
	log.Debugln("In NewUnicodeStr")
	us := UnicodeStr{}
	if referentId != 0 {
		us.ReferentIdPtr = referentId
	}
	data := s + "\x00"
	unc := encoder.ToUnicode(data)
	count := (len(unc) / 2)
	us.MaxCount = uint32(count)
	us.Offset = 0
	us.ActualCount = uint32(count)

	us.EncodedString = make([]byte, len(unc))
	copy(us.EncodedString, unc)
	padd := (len(unc) % 4) //Got to be 4 byte aligned
	if padd != 0 {
		padd = 4 - padd
	}
	us.Padd = make([]byte, padd)
	return &us
}

func uuid_to_bin(uuid string) ([]byte, error) {
	log.Debugln("In uuid_to_bin")

	if !strings.ContainsRune(uuid, '-') {
		return hex.DecodeString(uuid)
	}

	// Assume Variant 2 UUID
	matches := re.FindAllStringSubmatch(uuid, -1)
	if (len(matches) == 0) || (len(matches[0]) != 7) {
		return nil, fmt.Errorf("Failed to parse UUID v2 string")
	}
	uuid1, uuid2, uuid3, uuid4, uuid5, uuid6 := matches[0][1], matches[0][2], matches[0][3], matches[0][4], matches[0][5], matches[0][6]
	buf := make([]byte, 0)
	n, err := strconv.ParseUint(uuid1, 16, 32)
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n))
	n, err = strconv.ParseUint(uuid2, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid3, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid4, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid5, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid6, 16, 32)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint32(buf, uint32(n))

	return buf, nil
}

func NewBindReq(callId uint32, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string) (*BindReq, error) {
	log.Debugln("In NewBindReq")

	srsv_uuid, err := uuid_to_bin(interface_uuid)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	ndr_uuid, err := uuid_to_bin(transfer_uuid)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	header := newHeader()
	header.Type = PacketTypeBind
	header.CallId = callId

	return &BindReq{
		Header:          header,
		MaxSendFragSize: 4280,
		MaxRecvFragSize: 4280,
		Association:     0,
		CtxCount:        1,
		Context: &ContextItems{
			{
				Id:               0,
				Count:            1,
				AbstractUUID:     srsv_uuid,
				BindMajorVersion: majorVersion,
				BindMinVersion:   minorVersion,
				TransferUUID:     ndr_uuid,
				TransferVersion:  2,
			},
		},
	}, nil
}

func NewBindRes() BindRes {
	return BindRes{
		Header:  newHeader(),
		Context: new(ContextResItems),
	}
}

func NewRequestReq(callId uint32, op uint16) (*RequestReq, error) {
	header := newHeader()
	header.Type = PacketTypeRequest
	header.CallId = callId

	return &RequestReq{
		Header:    header,
		AllocHint: 0,
		ContextId: 0,
		Opnum:     op,
	}, nil
}

func NewNetShareEnumAllRequest(serverName string) *NetShareEnumAllRequest {
	nr := NetShareEnumAllRequest{
		ServerName: NewUnicodeStr(0x20000, serverName),
		Level:      Level{Lvl: 1},
		NetShareCtr: NetShareCtr{
			Ctr:     1,
			Pointer: make([]byte, 8),
		},
		MaxBuffer: 0xffffffff,
		ResumeHandle: ResumeHandle{
			ReferentId: 0x00020008,
			Handle:     0,
		},
	}

	return &nr
}

func Bind(f *smb.File, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string) (bind *ServiceBind, err error) {
	log.Debugln("In Bind")
	callId := rand.Uint32()
	bindReq, err := NewBindReq(callId, interface_uuid, majorVersion, minorVersion, transfer_uuid)
	if err != nil {
		return
	}

	buf, err := encoder.Marshal(bindReq)
	if err != nil {
		return
	}

	ioCtlReq, err := f.NewIoCTLReq(smb.FsctlPipeTransceive, buf)
	if err != nil {
		return
	}

	ioCtlRes, err := f.WriteIoCtlReq(ioCtlReq)
	if err != nil {
		return
	}

	bindRes := NewBindRes()
	err = encoder.Unmarshal(ioCtlRes.Buffer, &bindRes)
	if err != nil {
		return
	}

	// Check if Bind was successful
	var contextRes ContextResItems
	contextRes = *bindRes.Context
	if bindRes.CallId != bindReq.CallId {
		return nil, fmt.Errorf("Received invalid callId: %d\n", bindRes.CallId)
	}
	if bindRes.Type != PacketTypeBindAck {
		return nil, fmt.Errorf("Invalid response from server: %v\n", bindRes)
	}
	if contextRes[0].Result != 0 {
		return nil, fmt.Errorf("Server did not approve bind request: %v\n", contextRes)
	}

	return &ServiceBind{f: f}, nil
}

func roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func decodeServiceConfig(config *QueryServiceConfigW) (res ServiceConfig, err error) {
	log.Debugln("In decodeServiceConfig")
	if _, ok := ServiceTypeStatusMap[config.ServiceType]; !ok {
		err = fmt.Errorf("Could not identify returned service type: %d\n", config.ServiceType)
		fmt.Println(err)
	}
	res.ServiceType = ServiceTypeStatusMap[config.ServiceType]

	if _, ok := StartTypeStatusMap[config.StartType]; !ok {
		err = fmt.Errorf("Could not identify returned start type: %d\n", config.StartType)
		fmt.Println(err)
	}
	res.StartType = StartTypeStatusMap[config.StartType]

	if _, ok := ErrorControlStatusMap[config.ErrorControl]; !ok {
		err = fmt.Errorf("Could not identify returned start type: %d\n", config.ErrorControl)
		fmt.Println(err)
	}
	res.ErrorControl = ErrorControlStatusMap[config.ErrorControl]

	res.BinaryPathName, err = encoder.FromUnicodeString(config.BinaryPathName.EncodedString)
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		fmt.Println(err)
	}

	res.LoadOrderGroup, err = encoder.FromUnicodeString(config.LoadOrderGroup.EncodedString)
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		fmt.Println(err)
	}

	res.TagId = config.TagId

	res.Dependencies, err = encoder.FromUnicodeString(config.Dependencies.EncodedString)
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		fmt.Println(err)
	}

	res.ServiceStartName, err = encoder.FromUnicodeString(config.ServiceStartName.EncodedString)
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		fmt.Println(err)
	}

	res.DisplayName, err = encoder.FromUnicodeString(config.DisplayName.EncodedString)
	if err != nil {
		err = fmt.Errorf("Error decoding service config: %s\n", err)
		fmt.Println(err)
	}

	return
}

func (sb *ServiceBind) NetShareEnumAll(host string) (res []NetShare, err error) {
	log.Debugln("In NetShareEnumAll")
	netReq := NewNetShareEnumAllRequest(host)
	netBuf, err := encoder.Marshal(netReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SrvSvcOpNetShareEnumAll, netBuf)
	if err != nil {
		return
	}

	var response NetShareEnumAllResponse
	err = encoder.Unmarshal(buffer, &response)
	if err != nil {
		return
	}
	res = make([]NetShare, response.TotalEntries)
	var ctr1 *NetShareCtr1
	ctr1 = response.NetShareCtr.Pointer.(*NetShareCtr1)
	for i := 0; i < int(response.TotalEntries); i++ {
		res[i].Name, err = encoder.FromUnicodeString(ctr1.Pointer[i].Name.EncodedString)
		if err != nil {
			return
		}

		res[i].Comment, err = encoder.FromUnicodeString(ctr1.Pointer[i].Comment.EncodedString)

		// Parse the TYPE
		t := ""
		if (ctr1.Pointer[i].Type & StypeClusterDFS) == StypeClusterDFS {
			t += ShareTypeMap[StypeClusterDFS]
			res[i].TypeId = StypeClusterDFS
		} else if (ctr1.Pointer[i].Type & StypeClusterSOFS) == StypeClusterSOFS {
			t += ShareTypeMap[StypeClusterSOFS]
			res[i].TypeId = StypeClusterSOFS
		} else if (ctr1.Pointer[i].Type & StypeClusterFS) == StypeClusterFS {
			t += ShareTypeMap[StypeClusterFS]
			res[i].TypeId = StypeClusterFS
		} else if (ctr1.Pointer[i].Type & StypeIPC) == StypeIPC {
			t += ShareTypeMap[StypeIPC]
			res[i].TypeId = StypeIPC
		} else if (ctr1.Pointer[i].Type & StypeDevice) == StypeDevice {
			t += ShareTypeMap[StypeDevice]
			res[i].TypeId = StypeDevice
		} else if (ctr1.Pointer[i].Type & StypePrintq) == StypePrintq {
			t += ShareTypeMap[StypePrintq]
			res[i].TypeId = StypePrintq
		} else {
			t += ShareTypeMap[StypeDisktree]
			res[i].TypeId = StypeDisktree
		}

		if (ctr1.Pointer[i].Type & StypeSpecial) == StypeSpecial {
			t += "_" + ShareTypeMap[StypeSpecial]
			res[i].Hidden = true
		} else if (ctr1.Pointer[i].Type & StypeTemporary) == StypeTemporary {
			t += "_" + ShareTypeMap[StypeTemporary]
		}
		res[i].Type = t
	}

	return res, nil
}

func (sb *ServiceBind) openSCManager(desiredAccess uint32) (handle []byte, err error) {
	log.Debugln("In openSCManager")
	scReq := ROpenSCManagerWRequest{
		MachineName:   *NewUnicodeStr(1, "DUMMY"),
		DatabaseName:  *NewUnicodeStr(2, "ServicesActive"),
		DesiredAccess: desiredAccess,
	}
	scBuf, err := encoder.Marshal(scReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlROpenSCManagerW, scBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := ROpenSCManagerWResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ReturnCode]
	}

	handle = res.ContextHandle
	return
}

func (sb *ServiceBind) openService(scHandle []byte, serviceName string, desiredAccess uint32) (handle []byte, err error) {
	log.Debugln("In openService")
	serviceReq := ROpenServiceWRequest{
		SCContextHandle: scHandle,
		ServiceName:     NewUnicodeStr(0, serviceName),
		DesiredAccess:   desiredAccess,
	}

	serviceBuf, err := encoder.Marshal(serviceReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlROpenServiceW, serviceBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := ROpenServiceWResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ReturnCode]
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

	ssReq := RQueryServiceStatusRequest{ContextHandle: serviceHandle}
	ssBuf, err := encoder.Marshal(ssReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRQueryServiceStatus, ssBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	res := RQueryServiceStatusResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ReturnCode]
		return
	}

	status = res.ServiceStatus.CurrentState
	return
}

func (sb *ServiceBind) StartService(serviceName string) (err error) {
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

	ssReq := RStartServiceWRequest{ServiceHandle: serviceHandle}
	ssReq.Argc = 0
	ssReq.Argv = make([]UnicodeStr, 0) // Marshal of an empty pointer or like this doesn't create any bytes.
	// When Argc is 0 I need to marshal 0x00000000 for Argc and same for Argv e.g., 4 bytes combined of 0s

	ssBuf, err := encoder.Marshal(ssReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRStartServiceW, ssBuf)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	returnValue := binary.LittleEndian.Uint32(buffer)
	if returnValue != ErrorSuccess {
		return ServiceResponseCodeMap[returnValue]
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

	csReq := RControlServiceRequest{
		ServiceHandle: serviceHandle,
		Control:       control,
	}
	csBuf, err := encoder.Marshal(csReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		return
	}

	// Parse ServiceStatus
	res := RControlServiceResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	// Retrieve context handle from response
	if res.ReturnValue != ErrorSuccess {
		return ServiceResponseCodeMap[res.ReturnValue]
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

	innerReq := RQueryServiceConfigWRequest{
		ServiceHandle: serviceHandle,
		BufSize:       0,
	}
	innerBuf, err := encoder.Marshal(innerReq)
	if err != nil {
		return
	}

	// Make request to figure out buffer size
	buffer, err := sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfigW, innerBuf)
	if err != nil {
		return
	}

	// Parse response
	res := RQueryServiceConfigWResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorInsufficientBuffer {
		err = ServiceResponseCodeMap[res.ErrorCode]
		return
	}

	// Repeat request with allocated buffer size
	innerReq.BufSize = res.BytesNeeded
	innerBuf2, err := encoder.Marshal(innerReq)
	if err != nil {
		return
	}

	buffer, err = sb.MakeIoCtlRequest(SvcCtlRQueryServiceConfigW, innerBuf2)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res = RQueryServiceConfigWResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}

	if res.ErrorCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ErrorCode]
		return
	}

	return decodeServiceConfig(res.ServiceConfig)
}

func (sb *ServiceBind) ChangeServiceConfig(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName, displayName string) (err error) {

	log.Debugln("In ChangeServiceConfig")

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

	innerReq := RChangeServiceConfigWRequest{
		ServiceHandle:  serviceHandle,
		ServiceType:    serviceType,
		StartType:      startType,
		ErrorControl:   errorControl,
		LoadOrderGroup: nil,
		Dependencies:   nil,
		DependSize:     0,
		Password:       nil,
		PwSize:         0,
	}

	if len(binaryPathName) > 0 {
		innerReq.BinaryPathName = NewUnicodeStr(0x00000001, binaryPathName)
	} else {
		innerReq.BinaryPathName = nil
	}

	if len(serviceStartName) > 0 {
		innerReq.ServiceStartName = NewUnicodeStr(0x00000002, serviceStartName)
	} else {
		innerReq.ServiceStartName = nil
	}

	if len(displayName) > 0 {
		innerReq.DisplayName = NewUnicodeStr(0x00000003, displayName)
	} else {
		innerReq.DisplayName = nil
	}
	innerBuf, err := encoder.Marshal(innerReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRChangeServiceConfigW, innerBuf)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res := RChangeServiceConfigWResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}
	if res.ReturnCode != ErrorSuccess {
		return ServiceResponseCodeMap[res.ReturnCode]
	}

	return
}

// func (sb *ServiceBind) CreateService(
//
//	serviceName string,
//	serviceType, startType, errorControl uint32,
//	binaryPathName, serviceStartName, password, displayName string, startService bool) (err error) {
func (sb *ServiceBind) CreateService(
	serviceName string,
	serviceType, startType, errorControl uint32,
	binaryPathName, serviceStartName, displayName string, startService bool) (err error) {

	log.Debugln("In CreateService")

	scHandle, err := sb.openSCManager(SCManagerCreateService)
	if err != nil {
		return
	}
	defer sb.CloseServiceHandle(scHandle)

	innerReq := RCreateServiceRequest{
		SCContextHandle:  scHandle,
		ServiceName:      NewUnicodeStr(0, serviceName),
		DisplayName:      NewUnicodeStr(1, displayName),
		DesiredAccess:    ServiceAllAccess,
		ServiceType:      serviceType,
		StartType:        startType,
		ErrorControl:     errorControl,
		BinaryPathName:   NewUnicodeStr(0, binaryPathName),
		LoadOrderGroup:   nil,
		TagId:            0,
		Dependencies:     nil,
		DependSize:       0,
		ServiceStartName: NewUnicodeStr(2, serviceStartName),
	}

	log.Debugf("ServiceName: %s\n", innerReq.ServiceName.EncodedString)
	// To support specifying a password I must figure out how the encryption is
	// performed as thisI paramter expects an encrypted passphrase with some
	// session key
	//if password != "" {
	//    innerReq.Password = NewUnicodeStr(0, password)
	//    innerReq.PwSize = uint32((len(password)+1) * 2) // Null-terminated unicode string
	//}

	innerBuf, err := encoder.Marshal(innerReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRCreateServiceW, innerBuf)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res := RCreateServiceResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}
	if res.ReturnCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ReturnCode]
		return
	}
	defer sb.CloseServiceHandle(res.ContextHandle)

	if startService {
		ssReq := RStartServiceWRequest{ServiceHandle: res.ContextHandle}
		ssReq.Argc = 0
		ssReq.Argv = make([]UnicodeStr, 0) // Marshal of an empty pointer or like this doesn't create any bytes.
		// When Argc is 0 I need to marshal 0x00000000 for Argc and same for Argv e.g., 4 bytes combined of 0s

		ssBuf, err2 := encoder.Marshal(ssReq)
		if err != nil {
			return err2
		}

		buffer, err2 := sb.MakeIoCtlRequest(SvcCtlRStartServiceW, ssBuf)
		if err != nil {
			return err2
		}

		returnValue := binary.LittleEndian.Uint32(buffer)
		if returnValue != ErrorSuccess {
			return ServiceResponseCodeMap[returnValue]
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
	csReq := RControlServiceRequest{
		ServiceHandle: handle,
		Control:       ServiceControlStop,
	}
	csBuf, err := encoder.Marshal(csReq)
	if err != nil {
		return
	}

	_, err = sb.MakeIoCtlRequest(SvcCtlRControlService, csBuf)
	if err != nil {
		log.Errorln(err)
		// Continue with deletion even if stop failed for some reason
	}

	innerReq := RDeleteServiceRequest{
		ServiceHandle: handle,
	}

	innerBuf, err := encoder.Marshal(innerReq)
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRDeleteService, innerBuf)
	if err != nil {
		return
	}

	// Parse ServiceConfig
	res := RDeleteServiceResponse{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		return
	}
	if res.ReturnCode != ErrorSuccess {
		err = ServiceResponseCodeMap[res.ReturnCode]
		return
	}
	return
}

func (sb *ServiceBind) MakeIoCtlRequest(opcode uint16, innerBuf []byte) (result []byte, err error) {
	log.Debugln("In MakeIoCtlRequest")
	callId := rand.Uint32()
	req, err := NewRequestReq(callId, opcode)
	if err != nil {
		return
	}

	req.Buffer = make([]byte, len(innerBuf))
	copy(req.Buffer, innerBuf)

	req.AllocHint = uint32(len(innerBuf))
	req.FragLength = uint16(req.AllocHint + 24) // Includes header size

	// Encode DCERPC Request
	buf, err := encoder.Marshal(req)
	if err != nil {
		return
	}

	ioCtlReq, err := sb.f.NewIoCTLReq(smb.FsctlPipeTransceive, buf)
	if err != nil {
		return
	}

	// Send DCERPC request inside SMB IoCTL Request
	ioCtlRes, err := sb.f.WriteIoCtlReq(ioCtlReq)
	if err != nil {
		return
	}

	// Unmarshal DCERPC Request response
	var reqRes RequestRes
	err = encoder.Unmarshal(ioCtlRes.Buffer, &reqRes)
	if err != nil {
		return
	}

	if reqRes.CallId != callId {
		err = fmt.Errorf("Incorrect CallId on response. Sent %d and received %d\n", callId, reqRes.CallId)
		return
	}

	// Return response data
	return reqRes.Buffer, err
}

func (sb *ServiceBind) CloseServiceHandle(serviceHandle []byte) {
	log.Debugln("In CloseServiceHandle")
	closeReq := RCloseServiceHandleReq{
		ServiceHandle: serviceHandle,
	}
	closeBuf, err := encoder.Marshal(closeReq)
	if err != nil {
		fmt.Printf("Failed to encode close service handle request")
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SvcCtlRCloseServiceHandle, closeBuf)
	if err != nil {
		fmt.Printf("Failed to close service handle with error: %s\n", err)
		return
	}
	res := RCloseServiceHandleRes{}
	err = encoder.Unmarshal(buffer, &res)
	if err != nil {
		fmt.Printf("Failed to unmarshal response of close service handle")
		return
	}

	// Retrieve context handle from response
	//returnValue := binary.LittleEndian.Uint32(buffer)
	if res.ReturnCode != ErrorSuccess {
		log.Errorf("Failed to close service handle with error (return value: 0x%x): %v\n", res.ReturnCode, ServiceResponseCodeMap[res.ReturnCode])
	}

	return
}
