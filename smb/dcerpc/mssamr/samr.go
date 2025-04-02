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

package mssamr

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/mssamr")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidSamr                = "12345778-1234-abcd-ef00-0123456789ac"
	MSRPCSamrPipe                = "samr"
	MSRPCSamrMajorVersion uint16 = 1
	MSRPCSamrMinorVersion uint16 = 0
)

// MSRPC Security Account Manager (SAM) Remote Protocol Operations
const (
	SamrCloseHandle                uint16 = 1
	SamrLookupDomain               uint16 = 5
	SamrEnumDomains                uint16 = 6
	SamrOpenDomain                 uint16 = 7
	SamrEnumerateGroupsInDomain    uint16 = 11
	SamrCreateUserInDomain         uint16 = 12
	SamrEnumDomainUsers            uint16 = 13
	SamrEnumAliasesInDomain        uint16 = 15
	SamrLookupIdsInDomain          uint16 = 18
	SamrOpenGroup                  uint16 = 19
	SamrAddMemberToGroup           uint16 = 22
	SamrRemoveMemberFromGroup      uint16 = 24
	SamrGetMembersInGroup          uint16 = 25
	SamrOpenAlias                  uint16 = 27
	SamrAddMemberToAlias           uint16 = 31
	SamrRemoveMemberFromAlias      uint16 = 32
	SamrGetMembersInAlias          uint16 = 33
	SamrOpenUser                   uint16 = 34
	SamrDeleteUser                 uint16 = 35
	SamrQueryInformationUser2      uint16 = 47
	SamrUnicodeChangePasswordUser2 uint16 = 55
	SamrSetInformationUser2        uint16 = 58
	SamrConnect5                   uint16 = 64
	SamrRidToSid                   uint16 = 65
)

const (
	SamrHandleTypeServer uint8 = 0
	SamrHandleTypeDomain uint8 = 1
	SamrHandleTypeUser   uint8 = 2
	SamrHandleTypeGroup  uint8 = 3
	SamrHandleTypeAlias  uint8 = 4
)

var SamrHandleTypeMap = map[uint8]string{
	SamrHandleTypeServer: "SamrHandleTypeServer",
	SamrHandleTypeDomain: "SamrHandleTypeDomain",
	SamrHandleTypeUser:   "SamrHandleTypeUser",
	SamrHandleTypeGroup:  "SamrHandleTypeGroup",
	SamrHandleTypeAlias:  "SamrHandleTypeAlias",
}

const (
	ErrorSuccess                uint32 = 0x00000000 // The operation completed successfully
	ErrorAccessDenied           uint32 = 0x00000005 // Access is denied
	ErrorInvalidParameter       uint32 = 0x00000057 // One of the function parameters is not valid.
	StatusMoreEntries           uint32 = 0x00000105
	StatusSomeNotMapped         uint32 = 0x00000107
	StatusNoMoreEntries         uint32 = 0x8000001a
	StatusInvalidParameter      uint32 = 0xc000000d
	StatusAccessDenied          uint32 = 0xc0000022
	StatusObjectTypeMismatch    uint32 = 0xc0000024
	StatusInvalidAccountName    uint32 = 0xc0000062
	StatusUserExists            uint32 = 0xc0000063
	StatusNoSuchUser            uint32 = 0xc0000064
	StatusGroupExists           uint32 = 0xc0000065
	StatusNoSuchGroup           uint32 = 0xc0000066
	StatusMemberInGroup         uint32 = 0xc0000067
	StatusMemberNotInGroup      uint32 = 0xc0000068
	StatusWrongPassword         uint32 = 0xc000006a
	StatusPasswordRestriction   uint32 = 0xc000006c
	StatusNoneMapped            uint32 = 0xc0000073
	StatusNoSuchDomain          uint32 = 0xc00000df
	StatusInsufficientResources uint32 = 0xc000009A
	StatusMembersPrimaryGroup   uint32 = 0xc0000127
	StatusNoSuchAlias           uint32 = 0xc0000151
	StatusMemberNotInAlias      uint32 = 0xc0000152
	StatusMemberInAlias         uint32 = 0xc0000153
	StatusNoSuchMember          uint32 = 0xc000017a
	StatusAccountLockedOut      uint32 = 0xc0000234
)

var ResponseCodeMap = map[uint32]error{
	ErrorSuccess:                fmt.Errorf("The operation completed successfully"),
	ErrorAccessDenied:           fmt.Errorf("Access is denied"),
	ErrorInvalidParameter:       fmt.Errorf("One of the function parameters is not valid"),
	StatusMoreEntries:           fmt.Errorf("More information is available"),
	StatusSomeNotMapped:         fmt.Errorf("Some of the information to be translated has not been translated"),
	StatusNoMoreEntries:         fmt.Errorf("No more information is available"),
	StatusInvalidParameter:      fmt.Errorf("Status Invalid Parameter"),
	StatusAccessDenied:          fmt.Errorf("Client has requested access to an object but has not been granted those access rights."),
	StatusObjectTypeMismatch:    fmt.Errorf("Object type mismatch. Wrong type of handle used?"),
	StatusInvalidAccountName:    fmt.Errorf("Invalid account name"),
	StatusUserExists:            fmt.Errorf("User already exists"),
	StatusNoSuchUser:            fmt.Errorf("User does not exist"),
	StatusGroupExists:           fmt.Errorf("Group already exists"),
	StatusNoSuchGroup:           fmt.Errorf("Group does not exist"),
	StatusMemberInGroup:         fmt.Errorf("User is already in group"),
	StatusMemberNotInGroup:      fmt.Errorf("User not in group"),
	StatusWrongPassword:         fmt.Errorf("Provided password is not correct"),
	StatusPasswordRestriction:   fmt.Errorf("Password Restrictions"),
	StatusNoneMapped:            fmt.Errorf("None of the information to be translated has been translated."),
	StatusNoSuchDomain:          fmt.Errorf("No such domain"),
	StatusInsufficientResources: fmt.Errorf("Insufficient resources to complete the request"),
	StatusMembersPrimaryGroup:   fmt.Errorf("Member's primary group"),
	StatusNoSuchAlias:           fmt.Errorf("No such alias"),
	StatusMemberNotInAlias:      fmt.Errorf("Member is NOT in alias"),
	StatusMemberInAlias:         fmt.Errorf("Member is already in alias"),
	StatusNoSuchMember:          fmt.Errorf("No such member"),
	StatusAccountLockedOut:      fmt.Errorf("Account locked out!"),
}

// MS-SAMR Section 2.2.1.1 Common ACCESS_MASK Values
const (
	Delete               uint32 = 0x00010000 // Specifies access to the ability to delete the object.
	ReadControl          uint32 = 0x00020000 // Specifies access to the ability to read the security descriptor
	WriteDac             uint32 = 0x00040000 // Specifies access to the ability to update the discretionary access control list (DACL) of the security descriptor.
	WriteOwner           uint32 = 0x00080000 // Specifies access to the ability to update the Owner field of the security descriptor.
	AccessSystemSecurity uint32 = 0x01000000 // Specifies access to the system security portion of the security descriptor.
	MaximumAllowed       uint32 = 0x02000000 // Indicates that the caller is requesting the maximum access permissions possible to the object.
)

// MS-SAMR Section 2.2.1.2 Generic ACCESS_MASK Values
const (
	GenericExecute uint32 = 0x20000000 // Specifies access control suitable for executing an action on the object.
	GenericAll     uint32 = 0x10000000 // Specifies all defined access control on the object.
)

// MS-SAMR Section 2.2.1.3 Server ACCESS_MASK Values
const (
	SamServerConnect          uint32 = 0x00000001 // Specifies access control to obtain a server handle.
	SamServerShutdown         uint32 = 0x00000002 // Does not specify any access control.
	SamServerInitialize       uint32 = 0x00000004 // Does not specify any access control.
	SamServerCreateDomain     uint32 = 0x00000008 // Does not specify any access control.
	SamServerEnumerateDomains uint32 = 0x00000010 // Specifies access control to view domain objects.
	SamServerLookupDomain     uint32 = 0x00000020 // Specifies access control to perform SID-to-name translation.
	SamServerAllAccess        uint32 = 0x000F003F // The specified accesses for a GENERIC_ALL request.
	SamServerRead             uint32 = 0x00020010 // The specified accesses for a GENERIC_READ request.
	SamServerWrite            uint32 = 0x0002000E // The specified accesses for a GENERIC_WRITE request.
	SamServerExecute          uint32 = 0x00020021 // The specified accesses for a GENERIC_EXECUTE request
)

// MS-SAMR Section 2.2.1.12
const (
	UserAccountDisabled                    uint32 = 0x00000001 // Specifies that the account is not enabled for authentication.
	UserHomeDirectoryRequired              uint32 = 0x00000002 // Specifies that the homeDirectory attribute is required.
	UserPasswordNotRequired                uint32 = 0x00000004 // Specifies that the password-length policy does not apply to this user.
	UserTempDuplicateAccount               uint32 = 0x00000008 // This bit is ignored by clients and servers.
	UserNormalAccount                      uint32 = 0x00000010 // Specifies that the user is not a computer object.
	UserMnsLogonAccount                    uint32 = 0x00000020 // This bit is ignored by clients and servers.
	UserInterdomainTrustAccount            uint32 = 0x00000040 // Specifies that the object represents a trust object. For more information about trust objects, see [MS-LSAD].
	UserWorkstationTrustAccount            uint32 = 0x00000080 // Specifies that the object is a member workstation or server
	UserServerTrustAccount                 uint32 = 0x00000100 // Specifies that the object is a DC.
	UserDontExpirePassword                 uint32 = 0x00000200 // Specifies that the maximum-password-age policy does not apply to this user.
	UserAccountAutoLocked                  uint32 = 0x00000400 // Specifies that the account has been locked out.
	UserEncryptedTextPasswordAllowed       uint32 = 0x00000800 // Specifies that the cleartext password is to be persisted.
	UserSmartcardRequired                  uint32 = 0x00001000 // Specifies that the user can authenticate only with a smart card.
	UserTrustedForDelegation               uint32 = 0x00002000 // This bit is used by the Kerberos protocol. It indicates that the "OK as Delegate" ticket flag (described in [RFC4120] section 2.8) is to be set.
	UserNotDelegated                       uint32 = 0x00004000 // This bit is used by the Kerberos protocol. It indicates that the ticket-granting tickets (TGTs) of this account and the service tickets obtained by this account are not marked as forwardable or proxiable when the forwardable or proxiable ticket flags are requested. For more information, see [RFC4120].
	UserUseDesKeyOnly                      uint32 = 0x00008000 // This bit is used by the Kerberos protocol. It indicates that only des-cbc-md5 or des-cbc-crc keys (as defined in [RFC3961]) are used in the Kerberos protocol for this account.
	UserDontRequirePreauth                 uint32 = 0x00010000 // This bit is used by the Kerberos protocol. It indicates that the account is not required to present valid pre- authentication data, as described in [RFC4120] section 7.5.2.
	UserPasswordExpired                    uint32 = 0x00020000 // Specifies that the password age on the user has exceeded the maximum password age policy.
	UserTrustedToAuthenticateForDelegation uint32 = 0x00040000 // This bit is used by the Kerberos protocol, as specified in [MS-KILE] section 3.3.1.1.
	UserNoAuthDataRequired                 uint32 = 0x00080000 // This bit is used by the Kerberos protocol. It indicates that when the key distribution center (KDC) is issuing a service ticket for this account, the privilege attribute certificate (PAC) is not to be included. For more information, see [RFC4120].
	UserPartialSecretsAccount              uint32 = 0x00100000 // Specifies that the object is a read-only domain controller (RODC).
	UserUseAesKeys                         uint32 = 0x00200000 // This bit is ignored by clients and servers.
)

// MS-SAMR Section 2.2.2.3 SID_NAME_USE
const (
	SidTypeUser uint32 = iota + 1
	SidTypeGroup
	SidTypeDomain
	SidTypeAlias
	SidTypeWellKnownGroup
	SidTypeDeletedAccount
	SidTypeInvalid
	SidTypeUnknown
	SidTypeComputer
	SidTypeLabel
)

var SidType = map[uint32]string{
	SidTypeUser:           "SidTypeUser",
	SidTypeGroup:          "SidTypeGroup",
	SidTypeDomain:         "SidTypeDomain",
	SidTypeAlias:          "SidTypeAlias",
	SidTypeWellKnownGroup: "SidTypeWellKnownGroup",
	SidTypeDeletedAccount: "SidTypeDeletedAccount",
	SidTypeInvalid:        "SidTypeInvalid",
	SidTypeUnknown:        "SidTypeUnknown",
	SidTypeComputer:       "SidTypeComputer",
	SidTypeLabel:          "SidTypeLabel",
}

// MS-SAMR Section 2.2.6.28 USER_INFORMATION_CLASS
const (
	UserGeneralInformation      uint16 = 1
	UserPreferencesInformation  uint16 = 2
	UserLogonInformation        uint16 = 3
	UserLogonHoursInformation   uint16 = 4
	UserAccountInformation      uint16 = 5
	UserNameInformation         uint16 = 6
	UserAccountNameInformation  uint16 = 7
	UserFullNameInformation     uint16 = 8
	UserPrimaryGroupInformation uint16 = 9
	UserHomeInformation         uint16 = 10
	UserScriptInformation       uint16 = 11
	UserProfileInformation      uint16 = 12
	UserAdminCommentInformation uint16 = 13
	UserWorkStationsInformation uint16 = 14
	UserControlInformation      uint16 = 16
	UserExpiresInformation      uint16 = 17
	UserInternal1Information    uint16 = 18
	UserParametersInformation   uint16 = 20
	UserAllInformation          uint16 = 21
	UserInternal4Information    uint16 = 23
	UserInternal5Information    uint16 = 24
	UserInternal4InformationNew uint16 = 25
	UserInternal5InformationNew uint16 = 26
	UserInternal7Information    uint16 = 31
	UserInternal8Information    uint16 = 32
)

const (
	UserAllUsername           uint32 = 0x00000001
	UserAllFullname           uint32 = 0x00000002
	UserAllUserid             uint32 = 0x00000004
	UserAllPrimarygroupid     uint32 = 0x00000008
	UserAllAdmincomment       uint32 = 0x00000010
	UserAllUsercomment        uint32 = 0x00000020
	UserAllHomedirectory      uint32 = 0x00000040
	UserAllHomedirectorydrive uint32 = 0x00000080
	UserAllScriptpath         uint32 = 0x00000100
	UserAllProfilepath        uint32 = 0x00000200
	UserAllWorkstations       uint32 = 0x00000400
	UserAllLastlogon          uint32 = 0x00000800
	UserAllLastlogoff         uint32 = 0x00001000
	UserAllLogonhours         uint32 = 0x00002000
	UserAllBadpasswordcount   uint32 = 0x00004000
	UserAllLogoncount         uint32 = 0x00008000
	UserAllPasswordcanchange  uint32 = 0x00010000
	UserAllPasswordmustchange uint32 = 0x00020000
	UserAllPasswordlastset    uint32 = 0x00040000
	UserAllAccountexpires     uint32 = 0x00080000
	UserAllUseraccountcontrol uint32 = 0x00100000
	UserAllParameters         uint32 = 0x00200000
	UserAllCountrycode        uint32 = 0x00400000
	UserAllCodepage           uint32 = 0x00800000
	UserAllNtpasswordpresent  uint32 = 0x01000000
	UserAllLmpasswordpresent  uint32 = 0x02000000
	UserAllPrivatedata        uint32 = 0x04000000
	UserAllPasswordexpired    uint32 = 0x08000000
	UserAllSecuritydescriptor uint32 = 0x10000000
	UserAllUndefined          uint32 = 0xc0000000
)

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

func validateHandle(handle *SamrHandle, t uint8) error {
	if handle == nil {
		return fmt.Errorf("Cannot use a nil SamrHandle")
	}
	desiredType, ok := SamrHandleTypeMap[t]
	if !ok {
		return fmt.Errorf("Cannot validate a SamrHandle against an unknown type: %d", t)
	}

	if handle.Type != t {
		handleType := SamrHandleTypeMap[handle.Type]
		return fmt.Errorf("Invalid handle type. Expected %s not a type: [%s]", desiredType, handleType)
	}
	return nil
}

func newUserPassword(pass string) (res *SamprUserPassword, err error) {
	unc := msdtyp.ToUnicode(pass)
	res = &SamprUserPassword{
		Length: uint32(len(unc)),
		Buffer: make([]byte, 512),
	}
	_, err = rand.Read(res.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	offset := 512 - len(unc)
	copy(res.Buffer[offset:], unc)
	return
}

func (self *SamprUserPassword) EncryptRC4(key []byte) (res []byte, err error) {
	log.Debugln("In EncryptRC4 for SamrUserPassword")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Length)
	if err != nil {
		log.Errorln(err)
		return
	}
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		log.Errorln(err)
		return
	}
	plainText := w.Bytes()
	cipherText := make([]byte, len(plainText))
	cipher.XORKeyStream(cipherText, plainText)

	return cipherText, nil
}

func (sb *RPCCon) SamrConnect5(serverName string) (handle *SamrHandle, err error) {
	log.Debugln("In SamrConnect5")

	innerReq := SamrConnect5Req{
		ServerName:     serverName,
		DesiredAccess:  MaximumAllowed,
		InVersion:      1,
		InRevisionInfo: &SamprRevisionInfoV1{Revision: 3, SupportedFeatures: 0},
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrConnect5, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 40 {
		return nil, fmt.Errorf("Server response to SamrConnect5 was too small. Expected at atleast 40 bytes")
	}

	var resp SamrConnect5Res
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	handle = &SamrHandle{Handle: resp.ServerHandle}
	return
}

func (sb *RPCCon) SamrEnumDomains(handle *SamrHandle) (domains []string, err error) {
	log.Debugln("In SamrEnumDomains")
	if err = validateHandle(handle, SamrHandleTypeServer); err != nil {
		return
	}

	innerReq := SamrEnumDomainsReq{
		ServerHandle:       handle.Handle,
		EnumerationContext: 0,
		PreferredMaxLength: 0xFFFF,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrEnumDomains, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 12 {
		return nil, fmt.Errorf("Server response to SamrEnumDomains was too small. Expected at atleast 12 bytes")
	}

	var resp SamrEnumDomainsRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	for _, item := range resp.Buffer.Buffer {
		log.Infof("Enumerated samr domain name: %s\n", item.Name)
		domains = append(domains, item.Name)
	}

	return
}

func (sb *RPCCon) SamrLookupDomain(handle *SamrHandle, name string) (domainId *msdtyp.SID, err error) {
	log.Debugln("In SamrLookupDomain")
	if err = validateHandle(handle, SamrHandleTypeServer); err != nil {
		return
	}
	if name == "" {
		err = fmt.Errorf("Cannot lookup an empty domain!")
		log.Errorln(err)
		return
	}

	innerReq := SamrLookupDomainReq{
		ServerHandle: handle.Handle,
		Name:         msdtyp.RPCUnicodeStr{S: name},
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrLookupDomain, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 8 {
		return nil, fmt.Errorf("Server response to SamrLookupDomain was too small. Expected at atleast 8 bytes")
	}

	var resp SamrLookupDomainRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	domainId = resp.DomainId

	return
}

func (sb *RPCCon) SamrAddMemberToGroup(groupHandle *SamrHandle, rid, attributes uint32) (err error) {
	log.Debugln("In SamrAddMemberToGroup")
	if err = validateHandle(groupHandle, SamrHandleTypeGroup); err != nil {
		return
	}

	innerReq := SamrAddMemberToGroupReq{
		GroupHandle: groupHandle.Handle,
		MemberId:    rid,
		Attributes:  attributes,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrAddMemberToGroup, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrAddMemberToGroup was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrAddMemberToGroup response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrRemoveMemberFromGroup(groupHandle *SamrHandle, rid uint32) (err error) {
	log.Debugln("In SamrRemoveMemberFromGroup")
	if err = validateHandle(groupHandle, SamrHandleTypeGroup); err != nil {
		return
	}

	innerReq := SamrRemoveMemberFromGroupReq{
		GroupHandle: groupHandle.Handle,
		MemberId:    rid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrRemoveMemberFromGroup, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrRemoveMemberFromGroup was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrRemoveMemberFromGroup response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		} else if status == ResponseCodeMap[StatusMembersPrimaryGroup] {
			err = fmt.Errorf("Cannot remove user from its primary group")
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrGetMembersInGroup(groupHandle *SamrHandle) (members []SamrGroupMember, err error) {
	log.Debugln("In SamrGetMembersInGroup")
	if err = validateHandle(groupHandle, SamrHandleTypeGroup); err != nil {
		return
	}

	innerReq := SamrGetMembersInGroupReq{
		GroupHandle: groupHandle.Handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrGetMembersInGroup, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return nil, fmt.Errorf("Server response to SamrGetMembersInGroup was too small. Expected at atleast 20 bytes")
	}

	var res SamrGetMembersInGroupRes
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := 0; i < int(res.Members.MemberCount); i++ {
		members = append(members, SamrGroupMember{RID: res.Members.Members[i], Attributes: res.Members.Attributes[i]})
	}

	return
}

func (sb *RPCCon) SamrOpenDomain(handle *SamrHandle, desiredAccess uint32, domainId *msdtyp.SID) (domainHandle *SamrHandle, err error) {
	log.Debugln("In SamrOpenDomain")
	if err = validateHandle(handle, SamrHandleTypeServer); err != nil {
		return
	}
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := SamrOpenDomainReq{
		ServerHandle:  handle.Handle,
		DesiredAccess: desiredAccess,
		DomainId:      domainId,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrOpenDomain, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to SamrOpenDomain was too small. Expected at atleast 24 bytes")
	}

	var resp SamrOpenDomainRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		return
	}

	domainHandle = &SamrHandle{Handle: resp.ServerHandle, Type: SamrHandleTypeDomain, Name: domainId.ToString()}

	return
}

func (sb *RPCCon) SamrAddMemberToAlias(aliasHandle *SamrHandle, sid *msdtyp.SID) (err error) {
	log.Debugln("In SamrAddMemberToAlias")
	if err = validateHandle(aliasHandle, SamrHandleTypeAlias); err != nil {
		return
	}

	innerReq := SamrAddMemberToAliasReq{
		AliasHandle: aliasHandle.Handle,
		MemberId:    sid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrAddMemberToAlias, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrAddMemberToAlias was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrAddMemberToAlias response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrRemoveMemberFromAlias(aliasHandle *SamrHandle, sid *msdtyp.SID) (err error) {
	log.Debugln("In SamrRemoveMemberFromAlias")
	if err = validateHandle(aliasHandle, SamrHandleTypeAlias); err != nil {
		return
	}

	innerReq := SamrRemoveMemberFromAliasReq{
		AliasHandle: aliasHandle.Handle,
		MemberId:    sid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrRemoveMemberFromAlias, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrRemoveMemberFromAlias was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrRemoveMemberFromAlias response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrLookupIdsInDomain(domainHandle *SamrHandle, ids []uint32) (names []SamrRidMapping, err error) {
	log.Debugln("In SamrLookupIdsInDomain")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	innerReq := SamrLookupIdsInDomainReq{
		DomainHandle: domainHandle.Handle,
		Count:        uint32(len(ids)),
		RelativeIds:  ids,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrLookupIdsInDomain, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return nil, fmt.Errorf("Server response to SamrLookupIdsInDomain was too small. Expected at atleast 20 bytes")
	}

	var resp SamrLookupIdsInDomainRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	if (resp.ReturnCode > 0) && (resp.ReturnCode != StatusSomeNotMapped) {
		status, found := ResponseCodeMap[resp.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrLookupIdsInDomain response: 0x%x\n", resp.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	// Either it was a complete or a partial success.
	names = make([]SamrRidMapping, resp.Names.Count)
	for i := 0; i < len(names); i++ {
		if resp.Names.Elements[i] != "" {
			names[i].Name = resp.Names.Elements[i]
		} else {
			names[i].Name = "<EMPTY>"
		}
		names[i].Use = resp.Use[i]
		names[i].RID = ids[i]
	}

	return
}

func (sb *RPCCon) SamrOpenGroup(domainHandle *SamrHandle, desiredAccess, rid uint32) (aliasHandle *SamrHandle, err error) {
	log.Debugln("In SamrOpenGroup")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}
	if rid == 0 {
		err = fmt.Errorf("Must specify a RID of group to open. 0 is not a valid RID")
		return
	}

	innerReq := SamrOpenGroupReq{
		DomainHandle:  domainHandle.Handle,
		DesiredAccess: desiredAccess,
		GroupRID:      rid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrOpenGroup, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to SamrOpenGroup was too small. Expected at atleast 24 bytes")
	}

	var resp SamrOpenGroupRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		if err == ResponseCodeMap[StatusNoSuchGroup] {
			err = fmt.Errorf("%s in domain %s", err, domainHandle.Name)
		}
		log.Errorln(err)
		return
	}

	aliasHandle = &SamrHandle{Handle: resp.GroupHandle, Type: SamrHandleTypeGroup, Name: fmt.Sprintf("RID: %d", rid)}

	return
}

func (sb *RPCCon) SamrOpenAlias(domainHandle *SamrHandle, desiredAccess, aliasId uint32) (aliasHandle *SamrHandle, err error) {
	log.Debugln("In SamrOpenAlias")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}
	if aliasId == 0 {
		err = fmt.Errorf("Must specify a RID of alias to open. 0 is not a valid RID")
		return
	}

	innerReq := SamrOpenAliasReq{
		DomainHandle:  domainHandle.Handle,
		DesiredAccess: desiredAccess,
		AliasId:       aliasId,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrOpenAlias, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to SamrOpenAlias was too small. Expected at atleast 24 bytes")
	}

	var resp SamrOpenAliasRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		if err == ResponseCodeMap[StatusNoSuchAlias] {
			err = fmt.Errorf("%s in domain %s", err, domainHandle.Name)
		}
		log.Errorln(err)
		return
	}

	aliasHandle = &SamrHandle{Handle: resp.AliasHandle, Type: SamrHandleTypeAlias, Name: fmt.Sprintf("RID: %d", aliasId)}

	return
}

func (sb *RPCCon) SamrGetMembersInAlias(aliasHandle *SamrHandle) (members []msdtyp.SID, err error) {
	log.Debugln("In SamrGetMembersInAlias")
	if err = validateHandle(aliasHandle, SamrHandleTypeAlias); err != nil {
		return
	}

	innerReq := SamrGetMembersInAliasReq{
		AliasHandle: aliasHandle.Handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrGetMembersInAlias, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return nil, fmt.Errorf("Server response to SamrGetMembersInAlias was too small. Expected at atleast 20 bytes")
	}

	var resp SamrGetMembersInAliasRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	members = make([]msdtyp.SID, 0, resp.Members.Count)
	for i := 0; i < int(resp.Members.Count); i++ {
		members = append(members, *resp.Members.Sids[i].SidPointer)
	}

	return
}

func (sb *RPCCon) SamrCloseHandle(handle *SamrHandle) (err error) {
	log.Debugln("In SamrCloseHandle")
	if handle == nil {
		return fmt.Errorf("Cannot close a nil SamrHandle")
	}

	innerReq := SamrCloseHandleReq{
		ServerHandle: handle.Handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrCloseHandle, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return fmt.Errorf("Server response to SamrCloseHandle was too small. Expected at atleast 24 bytes")
	}

	returnCode := le.Uint32(buffer[20:])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrCloseHandle response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrRidToSid(domainHandle *SamrHandle, rid uint32) (sid *msdtyp.SID, err error) {
	log.Debugln("In SamrRidToSid")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	innerReq := SamrRidToSidReq{
		Handle: domainHandle.Handle,
		Rid:    rid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrRidToSid, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 8 {
		return nil, fmt.Errorf("Server response to SamrRidToSid was too small. Expected at atleast 8 bytes")
	}

	var resp SamrRidToSidRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	sid = resp.Sid

	return
}

func (sb *RPCCon) SamrCreateUserInDomain(domainHandle *SamrHandle, name string, desiredAccess uint32) (userHandle *SamrHandle, rid uint32, err error) {
	log.Debugln("In SamrCreateUserInDomain")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}
	innerReq := SamrCreateUserInDomainReq{
		DomainHandle:  domainHandle.Handle,
		Name:          name,
		DesiredAccess: desiredAccess,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrCreateUserInDomain, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 8 {
		return nil, 0, fmt.Errorf("Server response to SamrCreateUserInDomain was too small. Expected at atleast 8 bytes")
	}

	var resp SamrCreateUserInDomainRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	return &SamrHandle{Handle: resp.UserHandle, Type: SamrHandleTypeUser, Name: fmt.Sprintf("User: %s", name)}, resp.RelativeId, nil
}

func (sb *RPCCon) SamrEnumDomainUsers(domainHandle *SamrHandle, accountFlags uint32, maxLength uint32) (users []SamprRidEnumeration, err error) {
	log.Debugln("In SamrEnumDomainUsers")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}
	// maxLength is mostly used to avoid requesting too much data
	if maxLength == 0 {
		maxLength = 0xFFFFFFFF
	}

	innerReq := SamrEnumDomainUsersReq{
		DomainHandle:       domainHandle.Handle,
		ResumeHandle:       0,
		AccountFlags:       accountFlags,
		PreferredMaxLength: maxLength,
	}

	for {
		var innerBuf []byte
		innerBuf, err = innerReq.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		var buffer []byte
		buffer, err = sb.MakeIoCtlRequest(SamrEnumDomainUsers, innerBuf)
		if err != nil {
			return
		}

		if len(buffer) < 12 {
			return nil, fmt.Errorf("Server response to SamrEnumDomainUsers was too small. Expected at atleast 12 bytes")
		}

		var resp SamrEnumDomainUsersRes
		err = resp.UnmarshalBinary(buffer)
		if err != nil {
			log.Errorln(err)
			return
		}

		if resp.ReturnCode == 0 {
			// We're done
			for _, item := range resp.Buffer.Buffer {
				log.Infof("Enumerated samr domain user (%d): %s\n", item.RelativeId, item.Name)
			}
			users = append(users, resp.Buffer.Buffer...)
			return
		} else if resp.ReturnCode == StatusMoreEntries {
			// Need to send more requests
			users = append(users, resp.Buffer.Buffer...)
			responseLen := uint32(len(buffer))
			if responseLen >= maxLength {
				// We've received as much data as we wanted
				return
			}
			maxLength -= responseLen
			innerReq.ResumeHandle = resp.ResumeHandle
			innerReq.PreferredMaxLength = maxLength
		} else if resp.ReturnCode == StatusInsufficientResources {
			users = append(users, resp.Buffer.Buffer...)
			log.Errorln(ResponseCodeMap[resp.ReturnCode])
			return
		} else {
			status, found := ResponseCodeMap[resp.ReturnCode]
			if !found {
				err = fmt.Errorf("Received unknown Samr return code for SamrEnumDomainUsers response: 0x%x\n", resp.ReturnCode)
				log.Errorln(err)
				return
			}
			err = status
			log.Errorln(err)
			return
		}
	}
}

func (sb *RPCCon) SamrEnumerateGroupsInDomain(domainHandle *SamrHandle, maxLength uint32) (groups []SamprRidEnumeration, err error) {
	log.Debugln("In SamrEnumerateGroupsInDomain")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	// maxLength is mostly used to avoid requesting too much data
	if maxLength == 0 {
		maxLength = 0xFFFFFFFF
	}
	innerReq := SamrEnumerateGroupsInDomainReq{
		DomainHandle:       domainHandle.Handle,
		EnumerationContext: 0,
		PreferredMaxLength: maxLength,
	}

	for {
		var innerBuf []byte
		innerBuf, err = innerReq.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		var buffer []byte
		buffer, err = sb.MakeIoCtlRequest(SamrEnumerateGroupsInDomain, innerBuf)
		if err != nil {
			return
		}

		if len(buffer) < 24 {
			return nil, fmt.Errorf("Server response to SamrEnumerateGroupsInDomain was too small. Expected at atleast 24 bytes")
		}

		var resp SamrEnumerateGroupsInDomainRes
		err = resp.UnmarshalBinary(buffer)
		if err != nil {
			log.Errorln(err)
			return
		}
		if resp.ReturnCode == 0 {
			// We're done
			for _, item := range resp.Buffer.Buffer {
				log.Infof("Enumerated samr domain group (%d): %s\n", item.RelativeId, item.Name)
			}
			groups = append(groups, resp.Buffer.Buffer...)
			return
		} else if resp.ReturnCode == StatusMoreEntries {
			// Need to send more requests
			groups = append(groups, resp.Buffer.Buffer...)
			responseLen := uint32(len(buffer))
			if responseLen >= maxLength {
				// We've received as much data as we wanted
				return
			}
			maxLength -= responseLen
			innerReq.EnumerationContext = resp.EnumerationContext
			innerReq.PreferredMaxLength = maxLength
		} else if resp.ReturnCode == StatusInsufficientResources {
			groups = append(groups, resp.Buffer.Buffer...)
			log.Errorln(ResponseCodeMap[resp.ReturnCode])
			return
		} else {
			status, found := ResponseCodeMap[resp.ReturnCode]
			if !found {
				err = fmt.Errorf("Received unknown Samr return code for SamrEnumDomaingroups response: 0x%x\n", resp.ReturnCode)
				log.Errorln(err)
				return
			}
			err = status
			log.Errorln(err)
			return
		}
	}
}

func (sb *RPCCon) SamrGetUserInfo2(userHandle *SamrHandle, informationClass uint16) (info SamprUserInfoBufferUnion, err error) {
	log.Debugln("In SamrGetUserInfo2")
	if err = validateHandle(userHandle, SamrHandleTypeUser); err != nil {
		return
	}
	if informationClass != UserAllInformation {
		err = fmt.Errorf("Currently, only informationClass UserAllInformation (21) is supported")
		return
	}

	innerReq := SamrQueryInformationUser2Req{
		UserHandle:           userHandle.Handle,
		UserInformationClass: informationClass,
	}
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrQueryInformationUser2, innerBuf)
	if err != nil {
		return
	}

	var res SamrQueryInformationUser2Res
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	info = res.Buffer
	return
}

// Change password of user with knowledge of current PW or NT Hash of current PW
func (sb *RPCCon) SamrChangePassword2(username, currPw, newPw string, currNTHash []byte) (err error) {
	log.Debugln("In SamrChangePassword2")
	if (currPw == "") && (currNTHash != nil) {
		err = fmt.Errorf("Have to supply current password or NT hash to change password")
		return
	}
	if currNTHash == nil {
		currNTHash = ntlmssp.Ntowfv1(currPw)
	}
	newNTHash := ntlmssp.Ntowfv1(newPw)

	// encrypt old NT hash using the new hash
	encNTHash, err := encryptHashWithHash(newNTHash, currNTHash)
	if err != nil {
		log.Errorln(err)
		return
	}
	var pass *SamprUserPassword
	pass, err = newUserPassword(newPw)
	if err != nil {
		log.Errorln(err)
		return
	}
	var encPassword []byte
	encPassword, err = pass.EncryptRC4(currNTHash)
	if err != nil {
		log.Errorln(err)
		return
	}

	innerReq := SamrUnicodeChangePasswordUser2Req{
		ServerName:        "",
		UserName:          username,
		NewPwEncWithOldNt: encPassword,
		LmPresent:         0,
	}
	copy(innerReq.OldNtEncWithNewNt[:], encNTHash[:16])
	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrUnicodeChangePasswordUser2, innerBuf)
	if err != nil {
		return
	}
	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrUnicodeChangePasswordUser2 response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrSetUserInfo2(userHandle *SamrHandle, input *SamrUserInfoInput) (err error) {
	log.Debugln("In SamrSetUserInfo2")
	if err = validateHandle(userHandle, SamrHandleTypeUser); err != nil {
		return
	}

	internal4 := &SamprUserInternal4Information{}

	if input.AccountExpires != nil {
	}
	if input.PasswordCanChange != nil {
	}
	if input.PasswordMustChange != nil {
	}
	if input.Username != "" {
	}
	if input.Fullname != "" {
	}
	if input.HomeDirectory != "" {
	}
	if input.HomeDirectoryPath != "" {
	}
	if input.ScriptPath != "" {
	}
	if input.AdminComment != "" {
	}
	if input.WorkStations != "" {
	}
	if input.UserComment != "" {
	}
	if input.SecurityDescriptor != nil {
	}
	if input.PrimaryGroupId != 0 {
		internal4.I1.WhichFields |= UserAllPrimarygroupid
		internal4.I1.PrimaryGroupId = input.PrimaryGroupId
	}
	if input.UserAccountControl != 0 {
		internal4.I1.WhichFields |= UserAllUseraccountcontrol
		internal4.I1.UserAccountControl = input.UserAccountControl
	}
	if input.LogonHours != nil {
	}
	if input.UnExpirePassword == true {
		internal4.I1.WhichFields |= UserAllPasswordexpired
		internal4.I1.PasswordExpired = false
	}
	if input.NewPassword != "" {
		var pass *SamprUserPassword
		pass, err = newUserPassword(input.NewPassword)
		if err != nil {
			log.Errorln(err)
			return
		}
		var encPassword []byte
		encPassword, err = pass.EncryptRC4(sb.GetSessionKey())
		if err != nil {
			log.Errorln(err)
			return
		}
		internal4.UserPassword = encPassword
		internal4.I1.WhichFields |= UserAllNtpasswordpresent | UserAllLmpasswordpresent
	}

	innerReq := SamrSetInformationUser2Req{
		UserHandle: userHandle.Handle,
	}

	if input.NewPassword != "" {
		innerReq.UserInformationClass = UserInternal4Information
		innerReq.Buffer = internal4
	} else {
		innerReq.UserInformationClass = UserAllInformation
		innerReq.Buffer = &internal4.I1
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrSetInformationUser2, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrSetInformationUser2Req was too small. Expected at atleast 4 bytes")
	}

	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrSetInformationUser response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) SamrEnumAliasesInDomain(domainHandle *SamrHandle, maxLength uint32) (aliases []SamprRidEnumeration, err error) {
	log.Debugln("In SamrEnumAliasesInDomain")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	// maxLength is mostly used to avoid requesting too much data
	if maxLength == 0 {
		maxLength = 0xFFFFFFFF
	}
	innerReq := SamrEnumAliasesInDomainReq{
		DomainHandle:       domainHandle.Handle,
		EnumerationContext: 0,
		PreferredMaxLength: maxLength,
	}

	for {
		var innerBuf []byte
		innerBuf, err = innerReq.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		var buffer []byte
		buffer, err = sb.MakeIoCtlRequest(SamrEnumAliasesInDomain, innerBuf)
		if err != nil {
			return
		}

		if len(buffer) < 24 {
			return nil, fmt.Errorf("Server response to SamrEnumAliasesInDomain was too small. Expected at atleast 24 bytes")
		}

		var resp SamrEnumAliasesInDomainRes
		err = resp.UnmarshalBinary(buffer)
		if err != nil {
			log.Errorln(err)
			return
		}
		if resp.ReturnCode == 0 {
			// We're done
			for _, item := range resp.Buffer.Buffer {
				log.Infof("Enumerated samr domain alias (%d): %s\n", item.RelativeId, item.Name)
			}
			aliases = append(aliases, resp.Buffer.Buffer...)
			return
		} else if resp.ReturnCode == StatusMoreEntries {
			// Need to send more requests
			aliases = append(aliases, resp.Buffer.Buffer...)
			responseLen := uint32(len(buffer))
			if responseLen >= maxLength {
				// We've received as much data as we wanted
				return
			}
			maxLength -= responseLen
			innerReq.EnumerationContext = resp.EnumerationContext
			innerReq.PreferredMaxLength = maxLength
		} else if resp.ReturnCode == StatusInsufficientResources {
			aliases = append(aliases, resp.Buffer.Buffer...)
			log.Errorln(ResponseCodeMap[resp.ReturnCode])
			return
		} else {
			status, found := ResponseCodeMap[resp.ReturnCode]
			if !found {
				err = fmt.Errorf("Received unknown Samr return code for SamrEnumAliasesInDomain response: 0x%x\n", resp.ReturnCode)
				log.Errorln(err)
				return
			}
			err = status
			log.Errorln(err)
			return
		}
	}
}

func (sb *RPCCon) SamrOpenUser(domainHandle *SamrHandle, desiredAccess, rid uint32) (userHandle *SamrHandle, err error) {
	log.Debugln("In SamrOpenUser")
	if err = validateHandle(domainHandle, SamrHandleTypeDomain); err != nil {
		return
	}

	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}
	if rid == 0 {
		err = fmt.Errorf("0 is not a valid User RID")
		return
	}

	innerReq := SamrOpenUserReq{
		DomainHandle:  domainHandle.Handle,
		DesiredAccess: desiredAccess,
		UserId:        rid,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrOpenUser, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 24 {
		return nil, fmt.Errorf("Server response to SamrOpenUser was too small. Expected at atleast 24 bytes")
	}

	var resp SamrOpenUserRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	userHandle = &SamrHandle{Handle: resp.UserHandle, Type: SamrHandleTypeUser, Name: fmt.Sprintf("RID: %d", rid)}

	return
}

func (sb *RPCCon) SamrDeleteUser(userHandle *SamrHandle) (err error) {
	log.Debugln("In SamrDeleteUser")
	if err = validateHandle(userHandle, SamrHandleTypeUser); err != nil {
		return
	}

	innerReq := SamrDeleteUserReq{
		UserHandle: userHandle.Handle,
	}

	innerBuf, err := innerReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SamrDeleteUser, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		return fmt.Errorf("Server response to SamrDeleteUser was too small. Expected at atleast 4 bytes")
	}
	returnCode := le.Uint32(buffer[:4])
	if returnCode > 0 {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrDeleteUser response: 0x%x\n", returnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) CreateLocalUser(username, password, netbiosComputerName string) (userSID string, err error) {
	if username == "" {
		return "", fmt.Errorf("Cannot create a user with an empty username")
	}
	if password == "" {
		return "", fmt.Errorf("Cannot create a user without a password. If that is desired, use SamrCreateUserInDomain instead")
	}
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)
	userHandle, userRid, err := sb.SamrCreateUserInDomain(handleLocalDomain, username, MaximumAllowed)
	if err != nil {
		log.Errorln(err)
		return
	}
	userSID = fmt.Sprintf("%s-%d", localDomainId.ToString(), userRid)
	log.Infof("Created local user named (%s) with SID: %s\n", username, userSID)
	// Activate the account
	input := &SamrUserInfoInput{
		UserAccountControl: UserNormalAccount | UserDontExpirePassword,
		NewPassword:        password,
	}
	err = sb.SamrSetUserInfo2(userHandle, input)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) AddLocalAdmin(userSID string) (err error) {
	if userSID == "" {
		err = fmt.Errorf("Cannot add an empty SID as a local admin")
		return
	}
	sid, err := msdtyp.ConvertStrToSID(userSID)
	if err != nil {
		log.Errorln(err)
		return
	}
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	builtinId, err := sb.SamrLookupDomain(handle, "Builtin")
	if err != nil {
		log.Errorln(err)
		return
	}
	handleBuiltin, err := sb.SamrOpenDomain(handle, MaximumAllowed, builtinId)
	if err != nil {
		log.Errorln(err)
		return
	}
	handleBuiltin.Name = "Builtin"
	defer sb.SamrCloseHandle(handleBuiltin)
	handleLocalGroup, err := sb.SamrOpenAlias(handleBuiltin, MaximumAllowed, 544)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalGroup)
	err = sb.SamrAddMemberToAlias(handleLocalGroup, sid)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (sb *RPCCon) ListLocalUsers(netbiosComputerName string, limit uint32) (users []SamprRidEnumeration, err error) {
	var maxLength uint32
	maxLength = limit * 39 // based on a rough estimate for the mean size of a user entry being 39 bytes
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)

	return sb.SamrEnumDomainUsers(handleLocalDomain, UserNormalAccount, maxLength)
}

func (sb *RPCCon) ListLocalGroups(netbiosComputerName string) (groups []SamprRidEnumeration, err error) {
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)

	return sb.SamrEnumerateGroupsInDomain(handleLocalDomain, 0)
}

func (sb *RPCCon) ListDomainAliases(netbiosComputerName string) (aliases []SamprRidEnumeration, err error) {
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)

	return sb.SamrEnumAliasesInDomain(handleLocalDomain, 0)
}

func (sb *RPCCon) DeleteLocalUser(userRid uint32, netbiosComputerName string) (err error) {
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)
	userHandle, err := sb.SamrOpenUser(handleLocalDomain, MaximumAllowed, userRid)
	if err != nil {
		log.Errorln(err)
		return
	}
	// No need to close the handle when the object is deleted

	return sb.SamrDeleteUser(userHandle)
}

func (sb *RPCCon) QueryLocalUserAllInfo(userRid uint32, netbiosComputerName string) (info *SamprUserAllInformation, err error) {
	handle, err := sb.SamrConnect5("")
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handle)

	if netbiosComputerName == "" {
		var domains []string
		domains, err = sb.SamrEnumDomains(handle)
		if err != nil {
			log.Errorln(err)
			return
		}
		var otherDomains []string
		for _, domain := range domains {
			if domain != "Builtin" {
				otherDomains = append(otherDomains, domain)
			}
		}
		if len(otherDomains) != 1 {
			err = fmt.Errorf("Failed to automatically identity the Netbios domain. Select the correct domain and use it as an argument from the available domains: %v\n", domains)
			return
		}
		netbiosComputerName = otherDomains[0]
	}

	localDomainId, err := sb.SamrLookupDomain(handle, strings.ToUpper(netbiosComputerName))
	if err != nil {
		log.Errorln(err)
		return
	}
	handleLocalDomain, err := sb.SamrOpenDomain(handle, MaximumAllowed, localDomainId)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(handleLocalDomain)
	userHandle, err := sb.SamrOpenUser(handleLocalDomain, MaximumAllowed, userRid)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer sb.SamrCloseHandle(userHandle)

	result, err := sb.SamrGetUserInfo2(userHandle, UserAllInformation)
	info = result.(*SamprUserAllInformation)

	return
}
