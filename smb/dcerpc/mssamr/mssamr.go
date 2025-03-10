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
	SamrCloseHandle           uint16 = 1
	SamrLookupDomain          uint16 = 5
	SamrEnumDomains           uint16 = 6
	SamrOpenDomain            uint16 = 7
	SamrCreateUserInDomain    uint16 = 12
	SamrLookupIdsInDomain     uint16 = 18
	SamrAddMemberToGroup      uint16 = 22
	SamrOpenAlias             uint16 = 27
	SamrAddMemberToAlias      uint16 = 31
	SamrRemoveMemberFromAlias uint16 = 32
	SamrGetMembersInAlias     uint16 = 33
	SamrOpenUser              uint16 = 34
	SamrSetInformationUser2   uint16 = 58
	SamrConnect5              uint16 = 64
	SamrRidToSid              uint16 = 65
)

const (
	ErrorSuccess              uint32 = 0x0   // The operation completed successfully
	ErrorAccessDenied         uint32 = 0x5   // Access is denied
	ErrorInvalidParameter     uint32 = 0x57  // One of the function parameters is not valid.
	ErrorInvalidLevel         uint32 = 0x7c  // The information level is invalid.
	ErrorMoreData             uint32 = 0xea  // More entries are available. The UserInfo buffer was not large enough to contain all the entries.
	ErrorBufTooSmall          uint32 = 0x84b // More entries are available. The TransportInfo buffer was not large enough to contain all the entries.
	StatusInvalidParameter    uint32 = 0xc000000d
	StatusUserExists          uint32 = 0xc0000063
	StatusMemberNotInGroup    uint32 = 0xc0000068
	StatusPasswordRestriction uint32 = 0xc000006c
	StatusNoSuchAlias         uint32 = 0xc0000151
	StatusMemberNotInAlias    uint32 = 0xc0000152
	StatusMemberInAlias       uint32 = 0xc0000153
	StatusNoSuchMember        uint32 = 0xc000017a
)

var ResponseCodeMap = map[uint32]error{
	ErrorSuccess:              fmt.Errorf("The operation completed successfully"),
	ErrorAccessDenied:         fmt.Errorf("Access is denied"),
	ErrorInvalidParameter:     fmt.Errorf("One of the function parameters is not valid."),
	ErrorInvalidLevel:         fmt.Errorf("The information level is invalid."),
	ErrorMoreData:             fmt.Errorf("More entries are available. The UserInfo buffer was not large enough to contain all the entries."),
	ErrorBufTooSmall:          fmt.Errorf("More entries are available. The TransportInfo buffer was not large enough to contain all the entries."),
	StatusInvalidParameter:    fmt.Errorf("Status Invalid Parameter"),
	StatusUserExists:          fmt.Errorf("User already exists"),
	StatusMemberNotInGroup:    fmt.Errorf("User not in group"),
	StatusPasswordRestriction: fmt.Errorf("Password Restrictions"),
	StatusNoSuchAlias:         fmt.Errorf("No such alias"),
	StatusMemberNotInAlias:    fmt.Errorf("Member is NOT in alias"),
	StatusMemberInAlias:       fmt.Errorf("Member is already in alias"),
	StatusNoSuchMember:        fmt.Errorf("No such member"),
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
	UserAllInformation       uint16 = 21
	UserInternal4Information uint16 = 23
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

func (sb *RPCCon) SamrConnect5(serverName string) (handle []byte, err error) {
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

	handle = resp.ServerHandle
	return
}

func (sb *RPCCon) SamrEnumDomains(handle []byte) (domains []string, err error) {
	log.Debugln("In SamrEnumDomains")

	innerReq := SamrEnumDomainsReq{
		ServerHandle:       handle,
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

func (sb *RPCCon) SamrLookupDomain(handle []byte, name string) (domainId *msdtyp.SID, err error) {
	log.Debugln("In SamrLookupDomain")

	innerReq := SamrLookupDomainReq{
		ServerHandle: handle,
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

	if len(buffer) < 16 {
		return nil, fmt.Errorf("Server response to SamrLookupDomain was too small. Expected at atleast 16 bytes")
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

func (sb *RPCCon) SamrAddMemberToGroup(groupHandle []byte, rid, attributes uint32) (err error) {
	log.Debugln("In SamrAddMemberToGroup")

	innerReq := SamrAddMemberToGroupReq{
		GroupHandle: groupHandle,
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

func (sb *RPCCon) SamrOpenDomain(handle []byte, desiredAccess uint32, domainId *msdtyp.SID) (domainHandle []byte, err error) {
	log.Debugln("In SamrOpenDomain")
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := SamrOpenDomainReq{
		ServerHandle:  handle,
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
		log.Errorln(err)
		return
	}

	domainHandle = resp.ServerHandle

	return
}

func (sb *RPCCon) SamrAddMemberToAlias(aliasHandle []byte, sid *msdtyp.SID) (err error) {
	log.Debugln("In SamrAddMemberToAlias")

	innerReq := SamrAddMemberToAliasReq{
		AliasHandle: aliasHandle,
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

func (sb *RPCCon) SamrRemoveMemberFromAlias(aliasHandle []byte, sid *msdtyp.SID) (err error) {
	log.Debugln("In SamrRemoveMemberFromAlias")

	innerReq := SamrRemoveMemberFromAliasReq{
		AliasHandle: aliasHandle,
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

func (sb *RPCCon) SamrLookupIdsInDomain(domainHandle []byte, ids []uint32) (names []SamrRidMapping, err error) {
	log.Debugln("In SamrLookupIdsInDomain")

	innerReq := SamrLookupIdsInDomainReq{
		DomainHandle: domainHandle,
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

	if len(buffer) < 40 {
		return nil, fmt.Errorf("Server response to SamrLookupIdsInDomain was too small. Expected at atleast 40 bytes")
	}

	var resp SamrLookupIdsInDomainRes
	err = resp.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	names = make([]SamrRidMapping, resp.Names.Count)
	for i := 0; i < len(names); i++ {
		names[i].Name = resp.Names.Elements[i]
		names[i].Use = resp.Use[i]
		names[i].RID = ids[i]
	}

	return
}

func (sb *RPCCon) SamrOpenAlias(domainHandle []byte, desiredAccess, aliasId uint32) (aliasHandle []byte, err error) {
	log.Debugln("In SamrOpenAlias")
	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := SamrOpenAliasReq{
		DomainHandle:  domainHandle,
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
		log.Errorln(err)
		return
	}

	aliasHandle = resp.AliasHandle

	return
}

func (sb *RPCCon) SamrGetMembersInAlias(aliasHandle []byte) (members []msdtyp.SID, err error) {
	log.Debugln("In SamrGetMembersInAlias")

	innerReq := SamrGetMembersInAliasReq{
		AliasHandle: aliasHandle,
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

func (sb *RPCCon) SamrCloseHandle(handle []byte) (err error) {
	log.Debugln("In SamrCloseHandle")

	innerReq := SamrCloseHandleReq{
		ServerHandle: handle,
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

func (sb *RPCCon) SamrRidToSid(domainHandle []byte, rid uint32) (sid *msdtyp.SID, err error) {
	log.Debugln("In SamrRidToSid")

	innerReq := SamrRidToSidReq{
		Handle: domainHandle,
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

func (sb *RPCCon) SamrCreateUserInDomain(domainHandle []byte, name string, desiredAccess uint32) (userHandle []byte, rid uint32, err error) {
	log.Debugln("In SamrCreateUserInDomain")

	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}
	innerReq := SamrCreateUserInDomainReq{
		DomainHandle:  domainHandle,
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

	return resp.UserHandle, resp.RelativeId, nil
}

func (sb *RPCCon) SamrSetUserInfo(userHandle []byte, input *SamrUserInfoInput) (err error) {
	log.Debugln("In SamrSetUserInfo")
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
		UserHandle:           userHandle,
		UserInformationClass: UserInternal4Information,
		Buffer:               internal4,
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

func (sb *RPCCon) SamrOpenUser(domainHandle []byte, desiredAccess, rid uint32) (userHandle []byte, err error) {
	log.Debugln("In SamrOpenUser")

	if desiredAccess == 0 {
		desiredAccess = MaximumAllowed
	}

	innerReq := SamrOpenUserReq{
		DomainHandle:  domainHandle,
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
	userHandle = resp.UserHandle

	return
}

func (sb *RPCCon) CreateLocalUser(username, password, netbiosComputerName string) (userSID string, err error) {
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
	input := &SamrUserInfoInput{
		NewPassword:        password,
		UserAccountControl: 0x00000010 | 0x00000200,
	}
	err = sb.SamrSetUserInfo(userHandle, input)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (sb *RPCCon) AddLocalAdmin(userSID string) (err error) {
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
