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

package mslsad

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/mslsad")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidLsaRpc                = "12345778-1234-ABCD-EF00-0123456789AB"
	MSRPCLsaRpcPipe                = "lsarpc"
	MSRPCLsaRpcMajorVersion uint16 = 0
	MSRPCLsaRpcMinorVersion uint16 = 0
)

// Local Security Authority (Domain Policy) Remote Protocol (lsarpc) Operations
const (
	LsarClose                  uint16 = 0  // This method closes an open handle.
	LsarQueryInformationPolicy uint16 = 7  // This method is invoked to query values representing the server's information policy.
	LsarCreateAccount          uint16 = 10 // This method is invoked to create a new account object in the server's
	LsarEnumerateAccounts      uint16 = 11 // This method is invoked to request a list of account objects in the server's
	LsarOpenAccount            uint16 = 17 // This method is invoked to obtain a handle to an account object.
	LsarGetSystemAccessAccount uint16 = 23 // Retrieves system access flags from the account object.
	LsarSetSystemAccessAccount uint16 = 24 // Sets system access flags on the account object.
	LsarEnumerateAccountRights uint16 = 36 // This method is invoked to retrieve a list of rights that are associated with an existing account.
	LsarAddAccountRights       uint16 = 37 // This method is invoked to add new rights to an account object.
	LsarRemoveAccountRights    uint16 = 38 // This method is invoked to remove rights from an account object.
	LsarOpenPolicy2            uint16 = 44 // This method opens a context handle to the RPC server.
)

// MS-LSAD Section 2.2.3.5
const (
	LsaSecurityAnonymous      uint16 = 0
	LsaSecurityIdentification uint16 = 1
	LsaSecurityImpersonation  uint16 = 2
	LsaSecurityDelegation     uint16 = 3
)

const (
	StatusSuccess             uint32 = 0x0 // The operation completed successfully
	StatusInvalidHandle       uint32 = 0xC0000008
	StatusInvalidParameter    uint32 = 0xC000000D // One of the function parameters is not valid.
	StatusAccessDenied        uint32 = 0xC0000022 // Access is denied
	StatusObjectNameNotFound  uint32 = 0xC0000034
	StatusObjectNameCollision uint32 = 0xC0000035
	StatusInvalidSID          uint32 = 0xC0000078
	StatusNotSupported        uint32 = 0xC00000BB
)

var ResponseCodeMap = map[uint32]error{
	StatusSuccess:             fmt.Errorf("The operation completed successfully"),
	StatusAccessDenied:        fmt.Errorf("Access is denied"),
	StatusInvalidParameter:    fmt.Errorf("One of the function parameters is not valid."),
	StatusObjectNameCollision: fmt.Errorf("Another TDO already exists that matches some of the identifying information of the supplied information"),
	StatusInvalidSID:          fmt.Errorf("The security identifier of the trusted domain is not valid"),
	StatusInvalidHandle:       fmt.Errorf("PolicyHandle is not a valid handle."),
	StatusObjectNameNotFound:  fmt.Errorf("No value has been set for this policy."),
	StatusNotSupported:        fmt.Errorf("The operation is not supported for this object."),
}

// MS-LSAD Section 2.2.1.1 ACCESS_MASK for all objects
const (
	Delete         uint32 = 0x00010000
	ReadControl    uint32 = 0x00020000
	WriteDac       uint32 = 0x00040000
	WriteOwner     uint32 = 0x00080000
	MaximumAllowed uint32 = 0x02000000
	GenericAll     uint32 = 0x10000000
	GenericExecute uint32 = 0x20000000
)

// MS-LSAD Section 2.2.4.1
const (
	PolicyAuditLogInformation           uint16 = 1
	PolicyAuditEventsInformation        uint16 = 2
	PolicyPrimaryDomainInformation      uint16 = 3
	PolicyPdAccountInformation          uint16 = 4
	PolicyAccountDomainInformation      uint16 = 5
	PolicyLsaServerRoleInformation      uint16 = 6
	PolicyReplicaSourceInformation      uint16 = 7
	PolicyInformationNotUsedOnWire      uint16 = 8
	PolicyModificationInformation       uint16 = 9
	PolicyAuditFullSetInformation       uint16 = 10
	PolicyAuditFullQueryInformation     uint16 = 11
	PolicyDnsDomainInformation          uint16 = 12
	PolicyDnsDomainInformationInt       uint16 = 13
	PolicyLocalAccountDomainInformation uint16 = 14
	PolicyMachineAccountInformation     uint16 = 15
)

// MS-LSAD Section 3.1.1.2.2
const (
	SeInteractiveLogonRight           uint32 = 0x00000001
	SeNetworkLogonRight               uint32 = 0x00000002
	SeBatchLogonRight                 uint32 = 0x00000004
	SeServiceLogonRight               uint32 = 0x00000010
	SeDenyInteractiveLogonRight       uint32 = 0x00000040
	SeDenyNetworkLogonRight           uint32 = 0x00000080
	SeDenyBatchLogonRight             uint32 = 0x00000100
	SeDenyServiceLogonRight           uint32 = 0x00000200
	SeRemoteInteractiveLogonRight     uint32 = 0x00000400
	SeDenyRemoteInteractiveLogonRight uint32 = 0x00000800
)

var SystemAccessRightsMap = map[string]uint32{
	"SEINTERACTIVELOGONRIGHT":           0x00000001,
	"SENETWORKLOGONRIGHT":               0x00000002,
	"SEBATCHLOGONRIGHT":                 0x00000004,
	"SESERVICELOGONRIGHT":               0x00000010,
	"SEDENYINTERACTIVELOGONRIGHT":       0x00000040,
	"SEDENYNETWORKLOGONRIGHT":           0x00000080,
	"SEDENYBATCHLOGONRIGHT":             0x00000100,
	"SEDENYSERVICELOGONRIGHT":           0x00000200,
	"SEREMOTEINTERACTIVELOGONRIGHT":     0x00000400,
	"SEDENYREMOTEINTERACTIVELOGONRIGHT": 0x00000800,
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{sb}
}

func (sb *RPCCon) LsarCloseHandle(handle []byte) (err error) {
	log.Debugln("In LsarCloseHandle")

	innerReq := LsarCloseReq{
		ObjectHandle: handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarClose, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return fmt.Errorf("Server response to LsarCloseHandle was too small. Expected at atleast 24 bytes")
	}

	returnCode := le.Uint32(buffer[20:])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarCloseHandle response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) LsarQueryInformationPolicy(policyHandle []byte, informationClass uint16) (res LsaprPolicyInformation, err error) {
	log.Debugln("In LsarQueryInformationPolicy")
	if informationClass != PolicyPrimaryDomainInformation {
		err = fmt.Errorf("Currently, only informationClass PolicyPrimaryDomainInformation (%d) is supported", PolicyPrimaryDomainInformation)
		return
	}

	innerReq := LsarQueryInformationPolicyReq{
		PolicyHandle:     policyHandle,
		InformationClass: informationClass,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarQueryInformationPolicy, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 32 {
		return nil, fmt.Errorf("Server response to LsarQueryInformationPolicy was too small. Expected at atleast 32 bytes")
	}

	var resp LsarQueryInformationPolicyRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	res = resp.PolicyInformation

	return
}

func (sb *RPCCon) LsarCreateAccount(policyHandle []byte, sid string, desiredAccess uint32) (accountHandle []byte, err error) {
	log.Debugln("In LsarCreateAccount")
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := LsarCreateAccountReq{
		PolicyHandle:  policyHandle,
		DesiredAccess: desiredAccess,
	}

	innerReq.AccountSid, err = msdtyp.ConvertStrToSID(sid)
	if err != nil {
		log.Errorln(err)
		return
	}
	fmt.Printf("SID: %s\n", innerReq.AccountSid.ToString())

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarCreateAccount, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to LsarCreateAccount was too small. Expected at atleast 24 bytes")
	}

	var resp LsarCreateAccountRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	accountHandle = resp.AccountHandle

	if resp.ReturnCode > 0 {
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarCreateAccount response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) LsarEnumerateAccounts(policyHandle []byte) (accounts []msdtyp.SID, err error) {
	log.Debugln("In LsarEnumerateAccounts")

	innerReq := LsarEnumerateAccountsReq{
		PolicyHandle:       policyHandle,
		EnumerationContext: 0,
		PreferredMaxLength: 4096,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarEnumerateAccounts, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return nil, fmt.Errorf("Server response to LsarEnumerateAccounts was too small. Expected at atleast 20 bytes")
	}

	var resp LsarEnumerateAccountsRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if resp.ReturnCode > 0 {
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarEnumerateAccounts response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	if resp.EnumerationBuffer == nil {
		err = fmt.Errorf("Unexpected nil value for EnumerationBuffer in response with Status Success")
		return
	}

	for _, item := range resp.EnumerationBuffer.Information {
		accounts = append(accounts, *item.Sid)
	}
	return
}

func (sb *RPCCon) LsarOpenAccount(policyHandle []byte, sid *msdtyp.SID, desiredAccess uint32) (accountHandle []byte, err error) {
	log.Debugln("In LsarOpenAccount")
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := LsarOpenAccountReq{
		PolicyHandle:  policyHandle,
		AccountSid:    *sid,
		DesiredAccess: desiredAccess,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarOpenAccount, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to LsarOpenAccount was too small. Expected at atleast 24 bytes")
	}

	var resp LsarOpenAccountRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if resp.ReturnCode > 0 {
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarOpenAccount response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	accountHandle = resp.AccountHandle
	return
}

func (sb *RPCCon) LsarGetSystemAccessAccount(accountHandle []byte) (systemAccess uint32, err error) {
	log.Debugln("In LsarGetSystemAccessAccount")

	innerReq := LsarGetSystemAccessAccountReq{
		AccountHandle: accountHandle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarGetSystemAccessAccount, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 8 {
		return 0, fmt.Errorf("Server response to LsarGetSystemAccessAccount was too small. Expected at atleast 8 bytes")
	}

	var resp LsarGetSystemAccessAccountRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if resp.ReturnCode > 0 {
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarGetSystemAccessAccount response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	systemAccess = resp.SystemAccess
	return
}

func (sb *RPCCon) LsarSetSystemAccessAccount(accountHandle []byte, systemAccess uint32) (err error) {
	log.Debugln("In LsarSetSystemAccessAccount")

	innerReq := LsarSetSystemAccessAccountReq{
		AccountHandle: accountHandle,
		SystemAccess:  systemAccess,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarSetSystemAccessAccount, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to LsarSetSystemAccessAccount was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarSetSystemAccessAccount response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) LsarEnumerateAccountRights(policyHandle []byte, sid *msdtyp.SID) (rights []string, err error) {
	log.Debugln("In LsarEnumerateAccountRights")

	innerReq := LsarEnumerateAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarEnumerateAccountRights, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 12 {
		return nil, fmt.Errorf("Server response to LsarEnumerateAccountRights was too small. Expected at atleast 12 bytes")
	}

	var resp LsarEnumerateAccountRightsRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if resp.ReturnCode > 0 {
		if (resp.ReturnCode == StatusObjectNameNotFound) && (resp.UserRights.Entries == 0) {
			return []string{}, nil
		}
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarEnumerateAccountRights response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	rights = resp.UserRights.UserRights
	return
}

func (sb *RPCCon) LsarAddAccountRights(policyHandle []byte, sid *msdtyp.SID, rights []string) (err error) {
	log.Debugln("In LsarAddAccountRights")

	innerReq := LsarAddAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
		UserRights:   LsaprUserRightSet{UserRights: rights},
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarAddAccountRights, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to LsarAddAccountRights was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer)
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarAddAccountRights response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) LsarRemoveAccountRights(policyHandle []byte, sid *msdtyp.SID, rights []string, removeAllRights bool) (err error) {
	log.Debugln("In LsarRemoveAccountRights")

	innerReq := LsarRemoveAccountRightsReq{
		PolicyHandle: policyHandle,
		AccountSid:   *sid,
		AllRights:    removeAllRights,
		UserRights:   LsaprUserRightSet{UserRights: rights},
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarRemoveAccountRights, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to LsarRemoveAccountRights was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer)
	if returnCode > 0 {
		if returnCode == StatusObjectNameNotFound {
			err = fmt.Errorf("The specified rights were not present to be removed")
			return
		}
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown LSAD return code for LsarRemoveAccountRights response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) LsarOpenPolicy2(systemName string) (policyHandle []byte, err error) {
	log.Debugln("In LsarOpenPolicy2")

	innerReq := LsarOpenPolicy2Req{
		SystemName: systemName,
		ObjectAttributes: LsaprObjectAttributes{
			Length: 24,
			SecurityQualityOfService: SecurityQualityOfService{
				Length:              12,
				ImpersonationLevel:  LsaSecurityImpersonation,
				ContextTrackingMode: 1,
			},
		},
		DesiredAccess: MaximumAllowed,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(LsarOpenPolicy2, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to LsarOpenPolicy2 was too small. Expected at atleast 24 bytes")
	}

	var resp LsarOpenPolicy2Res
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	policyHandle = resp.PolicyHandle
	return
}

func (sb *RPCCon) ListAccounts() (accounts []msdtyp.SID, err error) {
	log.Debugln("In ListAccounts")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)

	return sb.LsarEnumerateAccounts(policyHandle)
}

func (sb *RPCCon) ListAccountRights(sid string) (rights []string, err error) {
	log.Debugln("In ListAccountRights")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	accountSid, err := msdtyp.ConvertStrToSID(sid)
	if err != nil {
		log.Errorln(err)
		return
	}

	return sb.LsarEnumerateAccountRights(policyHandle, accountSid)
}

func (sb *RPCCon) AddAccountRights(sid string, rights []string) (err error) {
	log.Debugln("In AddAccountRights")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	accountSid, err := msdtyp.ConvertStrToSID(sid)
	if err != nil {
		log.Errorln(err)
		return
	}

	return sb.LsarAddAccountRights(policyHandle, accountSid, rights)
}

func (sb *RPCCon) RemoveAccountRights(sid string, rights []string, removeAllRights bool) (err error) {
	log.Debugln("In RemoveAccountRights")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	accountSid, err := msdtyp.ConvertStrToSID(sid)
	if err != nil {
		log.Errorln(err)
		return
	}

	return sb.LsarRemoveAccountRights(policyHandle, accountSid, rights, removeAllRights)
}

func (sb *RPCCon) GetSystemAccessAccount(accountSid string) (rights []string, err error) {
	log.Debugln("In GetSystemAccessAccount")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	sid, err := msdtyp.ConvertStrToSID(accountSid)
	if err != nil {
		log.Errorln(err)
		return
	}
	accountHandle, err := sb.LsarOpenAccount(policyHandle, sid, 0)
	if err != nil {
		log.Errorln(err)
		return
	}

	systemAccess, err := sb.LsarGetSystemAccessAccount(accountHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	if systemAccess&SeInteractiveLogonRight > 0 {
		rights = append(rights, "SeInteractiveLogonRight")
	}
	if systemAccess&SeNetworkLogonRight > 0 {
		rights = append(rights, "SeNetworkLogonRight")
	}
	if systemAccess&SeBatchLogonRight > 0 {
		rights = append(rights, "SeBatchLogonRight")
	}
	if systemAccess&SeServiceLogonRight > 0 {
		rights = append(rights, "SeServiceLogonRight")
	}
	if systemAccess&SeDenyInteractiveLogonRight > 0 {
		rights = append(rights, "SeDenyInteractiveLogonRight")
	}
	if systemAccess&SeDenyNetworkLogonRight > 0 {
		rights = append(rights, "SeNetworkLogonRight")
	}
	if systemAccess&SeDenyBatchLogonRight > 0 {
		rights = append(rights, "SeDenyBatchLogonRight")
	}
	if systemAccess&SeDenyServiceLogonRight > 0 {
		rights = append(rights, "SeDenyServiceLogonRight")
	}

	return
}

func (sb *RPCCon) SetSystemAccessAccount(accountSid string, rights []string) (err error) {
	log.Debugln("In SetSystemAccessAccount")

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	sid, err := msdtyp.ConvertStrToSID(accountSid)
	if err != nil {
		log.Errorln(err)
		return
	}
	accountHandle, err := sb.LsarOpenAccount(policyHandle, sid, 0)
	if err != nil {
		log.Errorln(err)
		return
	}
	systemAccess := uint32(0)
	for _, item := range rights {
		val, found := SystemAccessRightsMap[strings.ToUpper(item)]
		if !found {
			err = fmt.Errorf("Unknown system access right: %s\n", item)
			log.Errorln(err)
			return
		}
		systemAccess |= val
	}

	err = sb.LsarSetSystemAccessAccount(accountHandle, systemAccess)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) GetPrimaryDomainInfo() (domainInfo *LsaprPolicyPrimaryDomInfo, err error) {
	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	res, err := sb.LsarQueryInformationPolicy(policyHandle, PolicyPrimaryDomainInformation)
	if err != nil {
		log.Errorln(err)
		return
	}
	domainInfo = res.(*LsaprPolicyPrimaryDomInfo)
	return
}
