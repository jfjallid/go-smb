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
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/ndr"
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

// ServiceFailureActions represents the SERVICE_FAILURE_ACTIONSW structure (MS-SCMR 2.2.40)
type ServiceFailureActions struct {
	ResetPeriod uint32 // Seconds after which to reset the failure count to zero
	RebootMsg   *string
	Command     *string
	Actions     []SCAction
}

// SCAction represents an SC_ACTION structure (MS-SCMR 2.2.39)
type SCAction struct {
	Type  uint32 // ScActionNone=0, ScActionRestart=1, ScActionReboot=2, ScActionRunCommand=3
	Delay uint32 // Milliseconds to wait before performing the action
}

// ServicePreferredNodeInfo represents the SERVICE_PREFERRED_NODE_INFO structure (MS-SCMR 2.2.38)
type ServicePreferredNodeInfo struct {
	PreferredNode uint16
	Delete        bool
}

type ROpenSCManagerWReq struct {
	MachineName   string `ndr:"toplevel,fullpointer,conformant,varying"`
	DatabaseName  string `ndr:"toplevel,fullpointer,conformant,varying"`
	DesiredAccess uint32
}

type ROpenSCManagerWRes struct {
	ContextHandle [20]byte
	ReturnCode    uint32
}

type ROpenServiceWReq struct {
	SCContextHandle [20]byte
	ServiceName     string `ndr:"toplevel,conformant,varying"`
	DesiredAccess   uint32
}

type ROpenServiceWRes struct {
	ContextHandle [20]byte
	ReturnCode    uint32
}

type RCloseServiceHandleReq struct {
	ServiceHandle [20]byte
}

type RCloseServiceHandleRes struct {
	ContextHandle [20]byte
	ReturnCode    uint32
}

type RQueryServiceStatusReq struct {
	ContextHandle [20]byte
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

type RQueryServiceStatusRes struct {
	ServiceStatus ServiceStatus
	ReturnCode    uint32
}

// MS-SCMR Section 2.2.15
type QueryServiceConfigW struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string `ndr:"pointer,conformant,varying"`
	LoadOrderGroup   string `ndr:"pointer,conformant,varying"`
	TagId            uint32
	Dependencies     string `ndr:"pointer,conformant,varying"`
	ServiceStartName string `ndr:"pointer,conformant,varying"`
	DisplayName      string `ndr:"pointer,conformant,varying"`
}

type RQueryServiceConfigWReq struct {
	ServiceHandle [20]byte
	BufSize       uint32
}

type RQueryServiceConfigWRes struct {
	ServiceConfig QueryServiceConfigW `ndr:"toplevel"`
	BytesNeeded   uint32
	ErrorCode     uint32
}

// MS-SCMR Section 2.2.22 SC_RPC_CONFIG_INFOW
type ConfigInfoW struct {
	InfoLevel              uint32                          `ndr:"unionTag"`
	Description            *ServiceDescriptionW            `ndr:"unionField,pointer"`
	FailureActions         *ServiceFailureActionsW         `ndr:"unionField,pointer"`
	DelayedAutoStartInfo   *ServiceDelayedAutoStartInfoW   `ndr:"unionField,pointer"`
	FailureActionsFlag     *ServiceFailureActionsFlagW     `ndr:"unionField,pointer"`
	ServiceSIDInfo         *ServiceSIDInfoW                `ndr:"unionField,pointer"`
	RequiredPrivilegesInfo *ServiceRequiredPrivilegesInfoW `ndr:"unionField,pointer"`
	PreshutdownInfo        *ServicePreshutdownInfoW        `ndr:"unionField,pointer"`
	PreferredNodeInfo      *ServicePreferredNodeInfoW      `ndr:"unionField,pointer"`
}

func (u ConfigInfoW) SwitchFunc(tag interface{}) string {
	t := tag.(uint32)
	switch t {
	case ServiceConfigDescription:
		return "Description"
	case ServiceConfigFailure_actions:
		return "FailureActions"
	case ServiceConfigDelayed_auto_start_info:
		return "DelayedAutoStartInfo"
	case ServiceConfigFailure_actions_flag:
		return "FailureActionsFlag"
	case ServiceConfigService_sid_info:
		return "ServiceSIDInfo"
	case ServiceConfigRequired_privileges_info:
		return "RequiredPrivilegesInfo"
	case ServiceConfigPreshutdown_info:
		return "PreshutdownInfo"
	case ServiceConfigPreferred_node:
		return "PreferredNodeInfo"
	}
	return ""
}

// RequiredServiceAccess returns the minimum service-object access rights the
// handle must be granted for RChangeServiceConfig2W to accept this info level.
//
// Every config2 change requires SERVICE_CHANGE_CONFIG. In practice the SCM
// also requires SERVICE_START for a SERVICE_CONFIG_FAILURE_ACTIONS change that
// contains an SC_ACTION_RESTART action (the SCM will (re)start the service on
// failure, so it checks that the caller holds start rights) — without it the
// call returns ERROR_ACCESS_DENIED. Reboot/run-command/none actions need only
// SERVICE_CHANGE_CONFIG, so SERVICE_START is requested only when it is
// actually needed.
func (info *ConfigInfoW) RequiredServiceAccess() uint32 {
	access := ServiceChangeConfig
	if info.InfoLevel == ServiceConfigFailure_actions && info.FailureActions != nil {
		for _, a := range info.FailureActions.Actions {
			if a.Type == ScActionRestart {
				access |= ServiceStart
				break
			}
		}
	}
	return access
}

// MS-SCMR Section 2.2.35 SERVICE_DESCRIPTIONW
type ServiceDescriptionW struct {
	Description *string `ndr:"fullpointer,conformant,varying"`
}

// MS-SCMR Section 2.2.40 SERVICE_FAILURE_ACTIONSW (NDR encoded for change requests)
type ServiceFailureActionsW struct {
	ResetPeriod uint32
	RebootMsg   *string `ndr:"fullpointer,conformant,varying"`
	Command     *string `ndr:"fullpointer,conformant,varying"`
	CActions    uint32
	Actions     []SCAction `ndr:"fullpointer,conformant"`
}

// MS-SCMR Section 2.2.33 SERVICE_DELAYED_AUTO_START_INFO
type ServiceDelayedAutoStartInfoW struct {
	DelayedAutoStart uint32
}

// MS-SCMR Section 2.2.34 SERVICE_FAILURE_ACTIONS_FLAG
type ServiceFailureActionsFlagW struct {
	Flag uint32
}

// MS-SCMR Section 2.2.46 SERVICE_SID_INFO
type ServiceSIDInfoW struct {
	ServiceSidType uint32
}

// MS-SCMR Section 2.2.48 SERVICE_RPC_REQUIRED_PRIVILEGES_INFO
type ServiceRequiredPrivilegesInfoW struct {
	CbRequiredPrivileges uint32
	RequiredPrivileges   []byte `ndr:"pointer,conformant"`
}

// MS-SCMR Section 2.2.32 SERVICE_PRESHUTDOWN_INFO
type ServicePreshutdownInfoW struct {
	PreshutdownTimeout uint32
}

// MS-SCMR Section 2.2.38 SERVICE_PREFERRED_NODE_INFO
type ServicePreferredNodeInfoW struct {
	PreferredNode uint16
	Delete        bool
}

// MS-SCMR Section 2.2.36 SERVICE_DESCRIPTION_WOW64
type serviceDescriptionWOW64 struct {
	DescriptionOffset uint32
}

// MS-SCMR Section 2.2.37 SERVICE_FAILURE_ACTIONS_WOW64
type serviceFailureActionsWOW64Buf struct {
	ResetPeriod     uint32
	RebootMsgOffset uint32
	CommandOffset   uint32
	CActions        uint32
	ActionsOffset   uint32
}

// MS-SCMR Section 2.2.38 SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64
type serviceRequiredPrivilegesInfoWOW64 struct {
	RequiredPrivilegesOffset uint32
}

type RChangeServiceConfig2WReq struct {
	ServiceHandle [20]byte
	Info          ConfigInfoW
}

type RQueryServiceConfig2WReq struct {
	ServiceHandle [20]byte
	InfoLevel     uint32
	BufSize       uint32
}

type RQueryServiceConfig2WRes struct {
	Buffer      []byte `ndr:"conformant"`
	BytesNeeded uint32
	ErrorCode   uint32
}

type RChangeServiceConfigWReq struct {
	ServiceHandle    [20]byte
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *string `ndr:"toplevel,fullpointer,conformant,varying"`
	LoadOrderGroup   *string `ndr:"toplevel,fullpointer,conformant,varying"`
	TagId            *uint32 `ndr:"toplevel,fullpointer"`
	Dependencies     *[]byte `ndr:"toplevel,fullpointer,conformant"`
	DependSize       uint32
	ServiceStartName *string `ndr:"toplevel,fullpointer,conformant,varying"`
	// RPC over SMB requires password encryption with session key
	// So have to encrypt the password before calling the marshal function
	Password    *[]byte `ndr:"toplevel,fullpointer,conformant"`
	PwSize      uint32
	DisplayName *string `ndr:"toplevel,fullpointer,conformant,varying"`
}

type RChangeServiceConfigWRes struct {
	TagId      uint32 `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

type RControlServiceReq struct {
	ServiceHandle [20]byte
	Control       uint32
}

type RControlServiceRes struct {
	ServiceStatus ServiceStatus
	ReturnValue   uint32
}

type RDeleteServiceReq struct {
	ServiceHandle [20]byte
}

// MS-SCMR Section 3.1.4.4 RQueryServiceObjectSecurity (Opnum 4)
type RQueryServiceObjectSecurityReq struct {
	ServiceHandle       [20]byte
	SecurityInformation uint32
	BufSize             uint32
}

type RQueryServiceObjectSecurityRes struct {
	SecurityDescriptor []byte `ndr:"conformant"`
	BytesNeeded        uint32
	ErrorCode          uint32
}

// MS-SCMR Section 3.1.4.5 RSetServiceObjectSecurity (Opnum 5)
// lpSecurityDescriptor is a [ref] LPBYTE (no unique attribute), so its
// conformant max_count is emitted inline at the field position rather than
// hoisted to the front of the struct; the "toplevel" tag suppresses hoisting.
type RSetServiceObjectSecurityReq struct {
	ServiceHandle       [20]byte
	SecurityInformation uint32
	SecurityDescriptor  []byte `ndr:"toplevel,conformant"`
	BufSize             uint32
}

type LPWStr struct {
	S string `ndr:"pointer,conformant,varying"`
}

type RStartServiceWReq struct {
	ServiceHandle [20]byte
	Argc          uint32
	Argv          *[]LPWStr `ndr:"toplevel,fullpointer,conformant"`
}

type RCreateServiceWReq struct {
	SCContextHandle  [20]byte
	ServiceName      string  `ndr:"toplevel,conformant,varying"`
	DisplayName      *string `ndr:"toplevel,fullpointer,conformant,varying"`
	DesiredAccess    uint32
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   string  `ndr:"toplevel,conformant,varying"`
	LoadOrderGroup   *string `ndr:"toplevel,fullpointer,conformant,varying"`
	TagId            *uint32 `ndr:"toplevel,fullpointer"`
	Dependencies     *[]byte `ndr:"toplevel,fullpointer,conformant"`
	DependSize       uint32
	ServiceStartName *string `ndr:"toplevel,fullpointer,conformant,varying"`
	Password         *[]byte `ndr:"toplevel,fullpointer,conformant"`
	PwSize           uint32
}

type RCreateServiceWRes struct {
	TagId         uint32 `ndr:"toplevel,fullpointer"`
	ContextHandle [20]byte
	ReturnCode    uint32
}

type EnumServiceStatusW struct {
	ServiceName   string
	DisplayName   string
	ServiceStatus *ServiceStatus
}

type REnumServicesStatusWReq struct {
	SCContextHandle [20]byte
	ServiceType     uint32
	ServiceState    uint32
	BufSize         uint32
	ResumeIndex     uint32
}

// Not the wire representation of the server's response
type REnumServicesStatusWRes struct {
	Services         []EnumServiceStatusW
	BytesNeeded      uint32
	ServicesReturned uint32
	ResumeIndex      uint32
	ReturnCode       uint32
}

// Actual format of REnumServicesStatusWRes as the the list of services is
// not encoded using NDR but returned as byte array with self-relative offsets
// for the fields.
type rEnumServicesStatusWEnvelope struct {
	Buffer           []byte `ndr:"conformant"`
	BytesNeeded      uint32
	ServicesReturned uint32
	ResumeIndex      uint32
	ReturnCode       uint32
}

func (s *ROpenSCManagerWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for ROpenSCManagerWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ROpenSCManagerWReq: %v", err)
	}
	return b, nil
}

func (s *ROpenSCManagerWRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for ROpenSCManagerWRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling ROpenSCManagerWRes: %v", err)
	}
	return nil
}

func (s *ROpenServiceWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for ROpenServiceWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ROpenServiceWReq: %v", err)
	}
	return b, nil
}

func (s *ROpenServiceWRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for ROpenServiceWRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling ROpenServiceWRes: %v", err)
	}
	return nil
}

func (s *RCloseServiceHandleReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RCloseServiceHandleReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RCloseServiceHandleReq: %v", err)
	}
	return b, nil
}

func (s *RCloseServiceHandleRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RCloseServiceHandleRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RCloseServiceHandleRes: %v", err)
	}
	return nil
}

func (s *RQueryServiceStatusReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RQueryServiceStatusReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RQueryServiceStatusReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceStatusRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RQueryServiceStatusRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RQueryServiceStatusRes: %v", err)
	}
	return nil
}

func (s *RQueryServiceConfigWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RQueryServiceConfigWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RQueryServiceConfigWReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceConfigWRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RQueryServiceConfigWRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RQueryServiceConfigWRes: %v", err)
	}
	return nil
}

func (s *RChangeServiceConfig2WReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RChangeServiceConfig2WReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RChangeServiceConfig2WReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceConfig2WReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RQueryServiceConfig2WReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RQueryServiceConfig2WReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceConfig2WRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RQueryServiceConfig2WRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RQueryServiceConfig2WRes: %v", err)
	}
	return nil
}

func (s *RChangeServiceConfigWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RChangeServiceConfigWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RChangeServiceConfigWReq: %v", err)
	}
	return b, nil
}

func (s *RChangeServiceConfigWRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RChangeServiceConfigWRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RChangeServiceConfigWRes: %v", err)
	}
	return nil
}

func (s *RControlServiceReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RControlServiceReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RControlServiceReq: %v", err)
	}
	return b, nil
}

func (s *RControlServiceRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RControlServiceRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RControlServiceRes: %v", err)
	}
	return nil
}

func (s *RDeleteServiceReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RDeleteServiceReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RDeleteServiceReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceObjectSecurityReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RQueryServiceObjectSecurityReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RQueryServiceObjectSecurityReq: %v", err)
	}
	return b, nil
}

func (s *RQueryServiceObjectSecurityRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RQueryServiceObjectSecurityRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RQueryServiceObjectSecurityRes: %v", err)
	}
	return nil
}

func (s *RSetServiceObjectSecurityReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RSetServiceObjectSecurityReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RSetServiceObjectSecurityReq: %v", err)
	}
	return b, nil
}

func (s *RStartServiceWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RStartServiceWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RStartServiceWReq: %v", err)
	}
	return b, nil
}

func (s *RCreateServiceWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for RCreateServiceWReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RCreateServiceWReq: %v", err)
	}
	return b, nil
}

func (s *RCreateServiceWRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for RCreateServiceWRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RCreateServiceWRes: %v", err)
	}
	return nil
}

func (s *REnumServicesStatusWReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for REnumServicesStatusWReq")

	if (s.ServiceType & 0x33) == 0 {
		return nil, fmt.Errorf("Invalid ServiceType. Must be one or a combination of values from MS-SCMR dwServiceType")
	}

	if (s.ServiceState > 0x3) || (s.ServiceState == 0) {
		return nil, fmt.Errorf("Invalid ServiceState value")
	}

	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling REnumServicesStatusWReq: %v", err)
	}
	return b, nil
}

func readNullTerminatedUTF16(buf []byte, offset uint32) (string, error) {
	if int(offset) >= len(buf) {
		return "", fmt.Errorf("string offset %d out of bounds (buffer size %d)", offset, len(buf))
	}
	data := buf[offset:]
	var unicodeBuffer []byte
	for i := 0; i+1 < len(data); i += 2 {
		if data[i] == 0 && data[i+1] == 0 {
			break
		}
		unicodeBuffer = append(unicodeBuffer, data[i], data[i+1])
	}
	return msdtyp.FromUnicodeString(unicodeBuffer)
}

func (s *REnumServicesStatusWRes) Unmarshal(buf []byte) (err error) {
	log.Traceln("In Unmarshal for REnumServicesStatusWRes")

	var envelope rEnumServicesStatusWEnvelope
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err = dec.Decode(&envelope); err != nil {
		return fmt.Errorf("error unmarshaling REnumServicesStatusWRes: %v", err)
	}

	s.BytesNeeded = envelope.BytesNeeded
	s.ServicesReturned = envelope.ServicesReturned
	s.ResumeIndex = envelope.ResumeIndex
	s.ReturnCode = envelope.ReturnCode

	if s.ReturnCode > 0 {
		return nil
	}

	lpBuffer := envelope.Buffer
	r := bytes.NewReader(lpBuffer)
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

		service.DisplayName, err = readNullTerminatedUTF16(lpBuffer, offsetDisplayName)
		if err != nil {
			log.Errorln(err)
			return
		}

		service.ServiceName, err = readNullTerminatedUTF16(lpBuffer, offsetServiceName)
		if err != nil {
			log.Errorln(err)
			return
		}

		s.Services = append(s.Services, service)
	}

	return nil
}

func parseServiceDescription(buf []byte) (string, error) {
	if len(buf) == 0 {
		return "", nil
	}
	var d serviceDescriptionWOW64
	_, err := binary.Decode(buf, le, &d)
	if err != nil {
		return "", fmt.Errorf("error parsing SERVICE_DESCRIPTION_WOW64: %v", err)
	}
	if len(buf) < int(d.DescriptionOffset) {
		return "", fmt.Errorf("error parsing SERVICE_DESCRIPTION_WOW64, buffer is too small for string")
	}
	description, err := msdtyp.FromUnicodeString(buf[d.DescriptionOffset:])
	if err != nil {
		return "", fmt.Errorf("error parsing SERVICE_DESCRIPTION_WOW64 unicode string: %v", err)
	}
	return description, nil
}

func parseFailureActions(buf []byte) (*ServiceFailureActions, error) {
	buflen := uint32(len(buf))
	if buflen == 0 {
		return nil, nil
	}
	var fa serviceFailureActionsWOW64Buf
	_, err := binary.Decode(buf, le, &fa)
	if err != nil {
		return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64: %v", err)
	}
	result := &ServiceFailureActions{
		ResetPeriod: fa.ResetPeriod,
	}
	if fa.RebootMsgOffset > 0 {
		if buflen < fa.RebootMsgOffset {
			return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64, buffer is smaller than RebootMsgOffset")
		}
		msg, err := readNullTerminatedUTF16(buf, fa.RebootMsgOffset)
		if err != nil {
			return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64 (RebootMsg): %v", err)
		}
		result.RebootMsg = &msg
	}
	if fa.CommandOffset > 0 {
		if buflen < fa.CommandOffset {
			return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64, buffer is smaller than CommandOffset")
		}
		command, err := readNullTerminatedUTF16(buf, fa.CommandOffset)
		if err != nil {
			return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64 (Command): %v", err)
		}
		result.Command = &command
	}
	if fa.ActionsOffset > 0 {
		if buflen < fa.ActionsOffset {
			return nil, fmt.Errorf("error parsing SERVICE_FAILURE_ACTIONS_WOW64, buffer is smaller than ActionsOffset")
		}
		offset := fa.ActionsOffset
		for i := range fa.CActions {
			var a SCAction
			_, err = binary.Decode(buf[offset:], le, &a)
			if err != nil {
				err = fmt.Errorf("failed to decode ScAction (%d) from SERVICE_FAILURE_ACTIONS_WOW64 struct: %v", i, err)
				return nil, err
			}
			result.Actions = append(result.Actions, a)
			offset += 8
		}
	}
	return result, nil
}

func parseDelayedAutoStartInfo(buf []byte) (bool, error) {
	if len(buf) < 4 {
		return false, fmt.Errorf("buffer too small for SERVICE_DELAYED_AUTO_START_INFO")
	}
	return le.Uint32(buf[:4]) != 0, nil
}

func parseFailureActionsFlag(buf []byte) (bool, error) {
	if len(buf) < 4 {
		return false, fmt.Errorf("buffer too small for SERVICE_FAILURE_ACTIONS_FLAG")
	}
	return le.Uint32(buf[:4]) != 0, nil
}

func parseServiceSIDInfo(buf []byte) (uint32, error) {
	if len(buf) < 4 {
		return 0, fmt.Errorf("buffer too small for SERVICE_SID_INFO")
	}
	return le.Uint32(buf[:4]), nil
}

func parseRequiredPrivileges(buf []byte) ([]string, error) {
	if len(buf) == 0 {
		return nil, nil
	}
	var d serviceRequiredPrivilegesInfoWOW64
	_, err := binary.Decode(buf, le, &d)
	if err != nil {
		return nil, fmt.Errorf("error parsing SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64: %v", err)
	}
	if len(buf) < int(d.RequiredPrivilegesOffset) {
		return nil, fmt.Errorf("error parsing SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64, buffer is too small for string array")
	}

	res, err := msdtyp.FromUnicodeString(buf[d.RequiredPrivilegesOffset:])
	if err != nil {
		return nil, fmt.Errorf("error parsing SERVICE_REQUIRED_PRIVILEGES_INFO_WOW64: %v", err)
	}
	if res == "" {
		return nil, nil
	}
	// MULTI_SZ: split on null characters, filter empty strings
	parts := strings.Split(res, "\x00")
	var result []string
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result, nil
}

func parsePreshutdownInfo(buf []byte) (uint32, error) {
	if len(buf) < 4 {
		return 0, fmt.Errorf("buffer too small for SERVICE_PRESHUTDOWN_INFO")
	}
	return le.Uint32(buf[:4]), nil
}

func parsePreferredNode(buf []byte) (*ServicePreferredNodeInfo, error) {
	if len(buf) < 3 {
		return nil, fmt.Errorf("buffer too small for SERVICE_PREFERRED_NODE_INFO")
	}
	return &ServicePreferredNodeInfo{
		PreferredNode: le.Uint16(buf[:2]),
		Delete:        buf[2] != 0,
	}, nil
}
