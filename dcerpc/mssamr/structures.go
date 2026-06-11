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
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

type SamrHandle struct {
	Handle [20]byte
	Type   byte
	Name   string
}

// Opnum 1
type SamrCloseHandleReq struct {
	ServerHandle [20]byte
}

// Opnum 5
type SamrLookupDomainReq struct {
	ServerHandle [20]byte
	Name         mstypes.RPCUnicodeString `ndr:"toplevel"`
}

// Opnum 5
type SamrLookupDomainRes struct {
	DomainId   *msdtyp.SID `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

// Opnum 6
type SamrEnumDomainsReq struct {
	ServerHandle       [20]byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 6
type SamrEnumDomainsRes struct {
	EnumerationContext uint32
	Buffer             *SamprEnumerationBuffer `ndr:"toplevel,fullpointer"`
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 7
type SamrOpenDomainReq struct {
	ServerHandle  [20]byte
	DesiredAccess uint32
	DomainId      msdtyp.SID `ndr:"toplevel"`
}

// Opnum 7
type SamrOpenDomainRes struct {
	DomainHandle [20]byte
	ReturnCode   uint32
}

// Opnum 11
type SamrEnumerateGroupsInDomainReq struct {
	DomainHandle       [20]byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 11
type SamrEnumerateGroupsInDomainRes struct {
	EnumerationContext uint32
	Buffer             *SamprEnumerationBuffer `ndr:"toplevel,fullpointer"`
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 12
type SamrCreateUserInDomainReq struct {
	DomainHandle  [20]byte
	Name          mstypes.RPCUnicodeString `ndr:"toplevel"`
	DesiredAccess uint32
}

// Opnum 12
type SamrCreateUserInDomainRes struct {
	UserHandle [20]byte
	RelativeId uint32
	ReturnCode uint32
}

// Opnum 13
type SamrEnumDomainUsersReq struct {
	DomainHandle       [20]byte
	ResumeHandle       uint32
	AccountFlags       uint32
	PreferredMaxLength uint32
}

// Opnum 13
type SamrEnumDomainUsersRes struct {
	ResumeHandle  uint32
	Buffer        *SamprEnumerationBuffer `ndr:"toplevel,fullpointer"`
	CountReturned uint32
	ReturnCode    uint32
}

// Opnum 15
type SamrEnumAliasesInDomainReq struct {
	DomainHandle       [20]byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 15
type SamrEnumAliasesInDomainRes struct {
	EnumerationContext uint32
	Buffer             *SamprEnumerationBuffer `ndr:"toplevel,fullpointer"`
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 17
type SamrLookupNamesInDomainReq struct {
	DomainHandle [20]byte
	Count        uint32
	Names        []mstypes.RPCUnicodeString `ndr:"toplevel,conformant,varying,maxcount:1000"`
}

// Opnum 17
type SamrLookupNamesInDomainRes struct {
	RelativeIds SamprULongArray `ndr:"toplevel"`
	Use         SamprULongArray `ndr:"toplevel"`
	ReturnCode  uint32
}

// Opnum 18
type SamrLookupIdsInDomainReq struct {
	DomainHandle [20]byte
	Count        uint32
	RelativeIds  []uint32 `ndr:"toplevel,conformant,varying,maxcount:1000"`
}

// Opnum 18
type SamrLookupIdsInDomainRes struct {
	Names      SamprReturnedUstringArray `ndr:"toplevel"`
	Use        SamprULongArray           `ndr:"toplevel"`
	ReturnCode uint32
}

// Opnum 19
type SamrOpenGroupReq struct {
	DomainHandle  [20]byte
	DesiredAccess uint32
	GroupRID      uint32
}

// Opnum 19
type SamrOpenGroupRes struct {
	GroupHandle [20]byte
	ReturnCode  uint32
}

// Opnum 22
type SamrAddMemberToGroupReq struct {
	GroupHandle [20]byte
	MemberId    uint32
	Attributes  uint32
}

// Opnum 24
type SamrRemoveMemberFromGroupReq struct {
	GroupHandle [20]byte
	MemberId    uint32
}

// Opnum 25
type SamrGetMembersInGroupReq struct {
	GroupHandle [20]byte
}

// Opnum 25
type SamrGetMembersInGroupRes struct {
	Members    *SamprGetMembersBuffer `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

// Opnum 27
type SamrOpenAliasReq struct {
	DomainHandle  [20]byte
	DesiredAccess uint32
	AliasId       uint32
}

// Opnum 27
type SamrOpenAliasRes struct {
	AliasHandle [20]byte
	ReturnCode  uint32
}

// Opnum 31
type SamrAddMemberToAliasReq struct {
	AliasHandle [20]byte
	MemberId    msdtyp.SID `ndr:"toplevel"`
}

// Opnum 32
type SamrRemoveMemberFromAliasReq struct {
	AliasHandle [20]byte
	MemberId    msdtyp.SID `ndr:"toplevel"`
}

// Opnum 33
type SamrGetMembersInAliasReq struct {
	AliasHandle [20]byte
}

// Opnum 33
type SamrGetMembersInAliasRes struct {
	Members    SamprPsidArrayOut `ndr:"toplevel"`
	ReturnCode uint32
}

// Opnum 34
type SamrOpenUserReq struct {
	DomainHandle  [20]byte
	DesiredAccess uint32
	UserId        uint32
}

// Opnum 34
type SamrOpenUserRes struct {
	UserHandle [20]byte
	ReturnCode uint32
}

// Opnum 35
type SamrDeleteUserReq struct {
	UserHandle [20]byte
}

// Opnum 47
type SamrQueryInformationUser2Req struct {
	UserHandle           [20]byte
	UserInformationClass uint16
}

// Opnum 47
type SamrQueryInformationUser2Res struct {
	Buffer     *SamprUserInfoBuffer `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

// Opnum 50
type SamrCreateUser2InDomainReq struct {
	DomainHandle  [20]byte
	Name          mstypes.RPCUnicodeString `ndr:"toplevel"`
	AccountType   uint32
	DesiredAccess uint32
}

// Opnum 50
type SamrCreateUser2InDomainRes struct {
	UserHandle    [20]byte
	GrantedAccess uint32
	RelativeId    uint32
	ReturnCode    uint32
}

// Opnum 55
// MS-SAMR 3.1.5.10.3 SamrUnicodeChangePasswordUser2
type SamrUnicodeChangePasswordUser2Req struct {
	ServerName        *mstypes.RPCUnicodeString `ndr:"toplevel,fullpointer"`
	UserName          mstypes.RPCUnicodeString  `ndr:"toplevel"`
	NewPwEncWithOldNt [516]byte                 `ndr:"toplevel,fullpointer"`
	OldNtEncWithNewNt [16]byte                  `ndr:"toplevel,fullpointer"`
	LmPresent         uint8
	NewPwEncWithOldLm [516]byte `ndr:"toplevel,fullpointer"`
	OldLmEncWithNewLm [16]byte  `ndr:"toplevel,fullpointer"`
}

// Opnum 58
// Non-encapsulated discriminant: UserInformationClass is written twice on the
// wire (once as the switch_is parameter, once as the union discriminant) which
// matches the MS-SAMR captured wire format without any struct alignment padding.
type SamrSetInformationUser2Req struct {
	UserHandle           [20]byte                      `ndr:"toplevel"`
	UserInformationClass uint16                        `ndr:"unionTag"`
	AllInformation       SamprUserAllInformation       `ndr:"unionField"`
	Internal4Information SamprUserInternal4Information `ndr:"unionField"`
}

func (u SamrSetInformationUser2Req) SwitchFunc(t interface{}) string {
	switch t.(uint16) {
	case UserAllInformation:
		return "AllInformation"
	case UserInternal4Information:
		return "Internal4Information"
	}
	return ""
}

// Opnum 64
type SamrConnect5Req struct {
	ServerName     string `ndr:"toplevel,fullpointer,conformant,varying"`
	DesiredAccess  uint32
	InVersion      uint32
	InRevisionInfo SamprRevisionInfo `ndr:"toplevel"`
}

// Opnum 64
type SamrConnect5Res struct {
	OutVersion      uint32
	OutRevisionInfo SamprRevisionInfo `ndr:"toplevel"`
	ServerHandle    [20]byte
	ReturnCode      uint32
}

// Opnum 65
type SamrRidToSidReq struct {
	Handle [20]byte
	Rid    uint32
}

// Opnum 65
type SamrRidToSidRes struct {
	Sid        *msdtyp.SID `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

type SamprEnumerationBuffer struct {
	EntriesRead uint32
	Buffer      []SamprRidEnumeration `ndr:"fullpointer,conformant"`
}

type SamprRidEnumeration struct {
	RelativeId uint32
	Name       mstypes.RPCUnicodeString
}

// MS-SAMR Section 2.2.7.15 — Discriminated union
type SamprRevisionInfo struct {
	Tag uint32              `ndr:"unionTag,encapsulated"`
	V1  SamprRevisionInfoV1 `ndr:"unionField"`
}

func (u SamprRevisionInfo) SwitchFunc(t interface{}) string {
	switch t.(uint32) {
	case 1:
		return "V1"
	default:
		return ""
	}
}

// MS-SAMR Section 2.2.7.3
type EncryptedNtOWFPassword struct {
	data [16]byte
}

// MS-SAMR Section 2.2.7.4
type SamprULongArray struct {
	Count    uint32
	Elements []uint32 `ndr:"fullpointer,conformant"`
}

// MS-SAMR Section 2.2.7.6
type SamprSidInformation struct {
	SidPointer *msdtyp.SID `ndr:"fullpointer"`
}

// MS-SAMR Section 2.2.7.7
type SamprPsidArrayOut struct {
	Count uint32
	Sids  []SamprSidInformation `ndr:"fullpointer,conformant"`
}

// MS-SAMR Section 2.2.7.8
type SamprReturnedUstringArray struct {
	Count    uint32
	Elements []mstypes.RPCUnicodeString `ndr:"fullpointer,conformant"`
}

// MS-SAMR Section 2.2.7.14
type SamprGetMembersBuffer struct {
	MemberCount uint32
	Members     []uint32 `ndr:"fullpointer,conformant"`
	Attributes  []uint32 `ndr:"fullpointer,conformant"`
}

// MS-SAMR Section 2.2.7.15
type SamprRevisionInfoV1 struct {
	Revision          uint32 // The value MUST be set to 3
	SupportedFeatures uint32
}

type SamrRidMapping struct {
	Name string
	RID  uint32
	Use  uint32
}

// MS-SAMR Section 2.2.2.4
type RpcShortBlob struct {
	Length    uint16
	MaxLength uint16
	Buffer    []byte `ndr:"fullpointer,conformant,varying"`
}

// MS-SAMR Section 2.2.6.5
type SamprLogonHours struct {
	UnitsPerWeek uint16
	LogonHours   []byte `ndr:"fullpointer,conformant,varying,maxcount:1260"`
}

// MS-SAMR Section 2.2.6.3
type SamprSrSecurityDescriptor struct {
	Length             uint32
	SecurityDescriptor []byte `ndr:"fullpointer,conformant"`
}

// MS-SAMR Section 2.2.6.6
type SamprUserAllInformation struct {
	LastLogon            msdtyp.Filetime
	LastLogoff           msdtyp.Filetime
	PasswordLastSet      msdtyp.Filetime
	AccountExpires       msdtyp.Filetime
	PasswordCanChange    msdtyp.Filetime
	PasswordMustChange   msdtyp.Filetime
	Username             mstypes.RPCUnicodeString
	Fullname             mstypes.RPCUnicodeString
	HomeDirectory        mstypes.RPCUnicodeString
	HomeDirectoryPath    mstypes.RPCUnicodeString
	ScriptPath           mstypes.RPCUnicodeString
	ProfilePath          mstypes.RPCUnicodeString
	AdminComment         mstypes.RPCUnicodeString
	WorkStations         mstypes.RPCUnicodeString
	UserComment          mstypes.RPCUnicodeString
	Parameters           mstypes.RPCUnicodeString
	LmOwfPassword        RpcShortBlob
	NtOwfPassword        RpcShortBlob
	PrivateData          mstypes.RPCUnicodeString
	SecurityDescriptor   SamprSrSecurityDescriptor
	UserId               uint32
	PrimaryGroupId       uint32
	UserAccountControl   uint32
	WhichFields          uint32
	LogonHours           SamprLogonHours
	BadPasswordCount     uint16
	LogonCount           uint16
	CountryCode          uint16
	CodePage             uint16
	LmPasswordPresent    bool
	NtPasswordPresent    bool
	PasswordExpired      bool
	PrivateDataSensitive bool
}

// MS-SAMR Section 2.2.6.21
type SamprUserPassword struct {
	Buffer []byte
	Length uint32
}

// MS-SAMR Section 2.2.6.24
type SamprUserInternal4Information struct {
	I1           SamprUserAllInformation
	UserPassword [516]byte
}

// MS-SAMR Section 2.2.6.29
type SamprUserInfoBuffer struct {
	Tag                  uint16                        `ndr:"unionTag,encapsulated"`
	AllInformation       SamprUserAllInformation       `ndr:"unionField"`
	Internal4Information SamprUserInternal4Information `ndr:"unionField"`
}

func (u SamprUserInfoBuffer) SwitchFunc(t interface{}) string {
	switch t.(uint16) {
	case UserAllInformation:
		return "AllInformation"
	case UserInternal4Information:
		return "Internal4Information"
	default:
		return ""
	}
}

// Input arguments for SamrSetUserInfo method
type SamrUserInfoInput struct {
	AccountExpires     *msdtyp.Filetime
	PasswordCanChange  *msdtyp.Filetime
	PasswordMustChange *msdtyp.Filetime
	Username           string
	Fullname           string
	HomeDirectory      string
	HomeDirectoryPath  string
	ScriptPath         string
	ProfilePath        string
	AdminComment       string
	WorkStations       string
	UserComment        string
	SecurityDescriptor *msdtyp.SID
	PrimaryGroupId     uint32
	UserAccountControl uint32
	LogonHours         *SamprLogonHours
	UnExpirePassword   bool // Only to set password NOT Expired
	NewPassword        string
}

type SamrGroupMember struct {
	RID        uint32
	Attributes uint32
}

func (s *SamrCloseHandleReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrCloseHandleReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrCloseHandleReq: %w", err)
	}
	return
}

func (s *SamrConnect5Req) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrConnect5Req")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrConnect5Req: %w", err)
	}
	return
}

func (s *SamrConnect5Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrConnect5Req")
}

func (s *SamrConnect5Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrConnect5Res")
}

func (s *SamrConnect5Res) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrConnect5Res")
	if len(buf) < 40 {
		return fmt.Errorf("Buffer too small for SamrConnect5Res")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrConnect5Res: %w", err)
	}
	return
}

func (s *SamrQueryInformationUser2Req) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrQueryInformationUser2Req")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrQueryInformationUser2Req: %w", err)
	}
	return
}

func (s *SamrQueryInformationUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrQueryInformationUser2Req")
}

func (s *SamrQueryInformationUser2Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrQueryInformationUser2Res")
}

func (s *SamrQueryInformationUser2Res) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrQueryInformationUser2Res")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SamrQueryInformationUser2Res")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrQueryInformationUser2Res: %w", err)
	}
	return
}

func (s *SamrCreateUser2InDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrCreateUser2InDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrCreateUser2InDomainReq: %w", err)
	}
	return
}

func (s *SamrCreateUser2InDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrCreateUser2InDomainReq")
}

func (s *SamrCreateUser2InDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrCreateUser2InDomainRes")
}

func (s *SamrCreateUser2InDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrCreateUser2InDomainRes")
	if len(buf) < 28 {
		return fmt.Errorf("Buffer too small for SamrCreateUser2InDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrCreateUser2InDomainRes: %w", err)
	}
	return
}

func (s *SamrUnicodeChangePasswordUser2Req) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrUnicodeChangePasswordUser2Req")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrUnicodeChangePasswordUser2Req: %w", err)
	}
	return
}

func (s *SamrUnicodeChangePasswordUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrUnicodeChangePasswordUser2Req")
}

func (s *SamrSetInformationUser2Req) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrSetInformationUser2Req")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrSetInformationUser2Req: %w", err)
	}
	return
}

func (s *SamrSetInformationUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrSetInformationUser2Req")
}

func (s *SamrLookupDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrLookupDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrLookupDomainReq: %w", err)
	}
	return
}

func (s *SamrLookupDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupDomainReq")
}

func (s *SamrLookupDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupDomainRes")
}

func (s *SamrLookupDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrLookupDomainRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SamrLookupDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrLookupDomainRes: %w", err)
	}
	return
}

func (s *SamrAddMemberToGroupReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrAddMemberToGroupReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrAddMemberToGroupReq: %w", err)
	}
	return
}

func (s *SamrAddMemberToGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrAddMemberToGroupReq")
}

func (s *SamrRemoveMemberFromGroupReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrRemoveMemberFromGroupReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrRemoveMemberFromGroupReq: %w", err)
	}
	return
}

func (s *SamrRemoveMemberFromGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRemoveMemberFromGroupReq")
}

func (s *SamrOpenDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrOpenDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrOpenDomainReq: %w", err)
	}
	return
}

func (s *SamrOpenDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenDomainReq")
}

func (s *SamrOpenDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenDomainRes")
}

func (s *SamrOpenDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrOpenDomainRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer too small for SamrOpenDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrOpenDomainRes: %w", err)
	}
	return
}

func (s *SamrEnumerateGroupsInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrEnumerateGroupsInDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrEnumerateGroupsInDomainReq: %w", err)
	}
	return
}

func (s *SamrEnumerateGroupsInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumerateGroupsInDomainReq")
}

func (s *SamrEnumerateGroupsInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumerateGroupsInDomainRes")
}

func (s *SamrEnumerateGroupsInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrEnumerateGroupsInDomainRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer too small for SamrEnumerateGroupsInDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrEnumerateGroupsInDomainRes: %w", err)
	}
	return
}

func (s *SamrCreateUserInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrCreateUserInDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrCreateUserInDomainReq: %w", err)
	}
	return
}

func (s *SamrCreateUserInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrCreateUserInDomainReq")
}

func (s *SamrCreateUserInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrCreateUserInDomainRes")
}

func (s *SamrCreateUserInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrCreateUserInDomainRes")
	if len(buf) < 28 {
		return fmt.Errorf("Buffer too small for SamrCreateUserInDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrCreateUserInDomainRes: %w", err)
	}
	return
}

func (s *SamrEnumDomainUsersReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrEnumDomainUsersReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrEnumDomainUsersReq: %w", err)
	}
	return
}

func (s *SamrEnumDomainUsersReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumDomainUsersReq")
}

func (s *SamrEnumDomainUsersRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumDomainUsersRes")
}

func (s *SamrEnumDomainUsersRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrEnumDomainUsersRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer too small for SamrEnumDomainUsersRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrEnumDomainUsersRes: %w", err)
	}
	return
}

func (s *SamrEnumAliasesInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrEnumAliasesInDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrEnumAliasesInDomainReq: %w", err)
	}
	return
}

func (s *SamrEnumAliasesInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumAliasesInDomainReq")
}

func (s *SamrEnumAliasesInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumAliasesInDomainRes")
}

func (s *SamrEnumAliasesInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrEnumAliasesInDomainRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer too small for SamrEnumAliasesInDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrEnumAliasesInDomainRes: %w", err)
	}
	return
}

func (s *SamrAddMemberToAliasReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrAddMemberToAliasReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrAddMemberToAliasReq: %w", err)
	}
	return
}

func (s *SamrAddMemberToAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrAddMemberToAliasReq")
}

func (s *SamrRemoveMemberFromAliasReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrRemoveMemberFromAliasReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrRemoveMemberFromAliasReq: %w", err)
	}
	return
}

func (s *SamrRemoveMemberFromAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRemoveMemberFromAliasReq")
}

func (s *SamrLookupNamesInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrLookupNamesInDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrLookupNamesInDomainReq: %w", err)
	}
	return

}

func (s *SamrLookupNamesInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupNamesInDomainReq")
}

func (s *SamrLookupNamesInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupNamesInDomainRes")
}

func (s *SamrLookupNamesInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrLookupNamesInDomainRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer too small for SamrLookupNamesInDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrLookupNamesInDomainRes: %w", err)
	}
	return
}

func (s *SamrLookupIdsInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrLookupIdsInDomainReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrLookupIdsInDomainReq: %w", err)
		return
	}
	return
}

func (s *SamrLookupIdsInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupIdsInDomainReq")
}

func (s *SamrLookupIdsInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupIdsInDomainRes")
}

func (s *SamrLookupIdsInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrLookupIdsInDomainRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer too small for SamrLookupIdsInDomainRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrLookupIdsInDomainRes: %w", err)
	}
	return
}

func (s *SamrOpenGroupReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrOpenGroupReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrOpenGroupReq: %w", err)
	}
	return
}

func (s *SamrOpenGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenGroupReq")
}

func (s *SamrOpenGroupRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenGroupRes")
}

func (s *SamrOpenGroupRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrOpenGroupRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer too small for SamrOpenGroupRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrOpenGroupRes: %w", err)
	}
	return
}

func (s *SamrOpenAliasReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrOpenAliasReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrOpenAliasReq: %w", err)
	}
	return
}

func (s *SamrOpenAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenAliasReq")
}

func (s *SamrOpenAliasRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenAliasRes")
}

func (s *SamrOpenAliasRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrOpenAliasRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer too small for SamrOpenAliasRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrOpenAliasRes: %w", err)
	}
	return
}

func (s *SamrGetMembersInAliasReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrGetMembersInAliasReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrGetMembersInAliasReq: %w", err)
	}
	return
}

func (s *SamrGetMembersInAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrGetMembersInAliasReq")
}

func (s *SamrGetMembersInAliasRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrGetMembersInAliasRes")
}

func (s *SamrGetMembersInAliasRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrGetMembersInAliasRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SamrGetMembersInAliasRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrGetMembersInAliasRes: %w", err)
	}
	return
}

func (s *SamrOpenUserReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrOpenUserReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrOpenUserReq: %w", err)
	}
	return
}

func (s *SamrOpenUserReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenUserReq")
}

func (s *SamrOpenUserRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenUserRes")
}

func (s *SamrOpenUserRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrOpenUserRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer too small for SamrOpenUserRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrOpenUserRes: %w", err)
	}
	return
}

func (s *SamrDeleteUserReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrDeleteUserReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrDeleteUserReq: %w", err)
	}
	return
}

func (s *SamrDeleteUserReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrDeleteUserReq")
}

func (s *SamrEnumDomainsReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrEnumDomainsReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrEnumDomainsReq: %w", err)
	}
	return
}

func (s *SamrEnumDomainsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumDomainsReq")
}

func (s *SamrEnumDomainsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumDomainsRes")
}

func (s *SamrEnumDomainsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrEnumDomainsRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer too small for SamrEnumDomainsRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrEnumDomainsRes: %w", err)
	}
	return
}

func (s *SamrRidToSidReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrRidToSidReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrRidToSidReq: %w", err)
	}
	return
}

func (s *SamrRidToSidReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRidToSidReq")
}

func (s *SamrRidToSidRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrRidToSidRes")
}

func (s *SamrRidToSidRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrRidToSidRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SamrRidToSidRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrRidToSidRes: %w", err)
	}
	return
}

func (s *SamrGetMembersInGroupReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for SamrGetMembersInGroupReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling SamrGetMembersInGroupReq: %w", err)
	}
	return
}

func (s *SamrGetMembersInGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrGetMembersInGroupReq")
}

func (s *SamrGetMembersInGroupRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrGetMembersInGroupRes")
}

func (s *SamrGetMembersInGroupRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for SamrGetMembersInGroupRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer too small for SamrGetMembersInGroupRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling SamrGetMembersInGroupRes: %w", err)
	}
	return
}
