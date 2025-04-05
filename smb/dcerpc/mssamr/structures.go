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
//
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package mssamr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"io"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

type SamrHandle struct {
	Handle []byte
	Type   byte
	Name   string
}

// Opnum 1
type SamrCloseHandleReq struct {
	ServerHandle []byte
}

// Opnum 5
type SamrLookupDomainReq struct {
	ServerHandle []byte
	Name         msdtyp.RPCUnicodeStr
}

// Opnum 5
type SamrLookupDomainRes struct {
	DomainId   *msdtyp.SID
	ReturnCode uint32
}

// Opnum 6
type SamrEnumDomainsReq struct {
	ServerHandle       []byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 6
type SamrEnumDomainsRes struct {
	EnumerationContext uint32
	Buffer             SamprEnumerationBuffer
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 7
type SamrOpenDomainReq struct {
	ServerHandle  []byte
	DesiredAccess uint32
	DomainId      *msdtyp.SID
}

// Opnum 7
type SamrOpenDomainRes struct {
	ServerHandle []byte
	ReturnCode   uint32
}

// Opnum 11
type SamrEnumerateGroupsInDomainReq struct {
	DomainHandle       []byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 11
type SamrEnumerateGroupsInDomainRes struct {
	EnumerationContext uint32
	Buffer             SamprEnumerationBuffer
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 12
type SamrCreateUserInDomainReq struct {
	DomainHandle  []byte
	Name          string // RPC_UNICODE_STRING
	DesiredAccess uint32
}

// Opnum 12
type SamrCreateUserInDomainRes struct {
	UserHandle []byte
	RelativeId uint32
	ReturnCode uint32
}

// Opnum 13
type SamrEnumDomainUsersReq struct {
	DomainHandle       []byte
	ResumeHandle       uint32
	AccountFlags       uint32
	PreferredMaxLength uint32
}

// Opnum 13
type SamrEnumDomainUsersRes struct {
	ResumeHandle  uint32
	Buffer        SamprEnumerationBuffer
	CountReturned uint32
	ReturnCode    uint32
}

// Opnum 15
type SamrEnumAliasesInDomainReq struct {
	DomainHandle       []byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// Opnum 15
type SamrEnumAliasesInDomainRes struct {
	EnumerationContext uint32
	Buffer             SamprEnumerationBuffer
	CountReturned      uint32
	ReturnCode         uint32
}

// Opnum 17
type SamrLookupNamesInDomainReq struct {
	DomainHandle []byte
	Count        uint32
	Names        []msdtyp.RPCUnicodeStr
}

// Opnum 17
type SamrLookupNamesInDomainRes struct {
	RelativeIds SamprULongArray
	Use         SamprULongArray
	ReturnCode  uint32
}

// Opnum 18
type SamrLookupIdsInDomainReq struct {
	DomainHandle []byte
	Count        uint32
	RelativeIds  []uint32 // DCERPC (NDR) 14.3.3.4 Uni-dimensional Conformant-varying (Arrays inside a struct)
}

// Opnum 18
type SamrLookupIdsInDomainRes struct {
	Names      SamprReturnedUstringArray
	Use        []uint32 // DCERPC (NDR) 14.3.3.2 Uni-dimensional Conformant Arrays I think
	ReturnCode uint32
}

// Opnum 19
type SamrOpenGroupReq struct {
	DomainHandle  []byte
	DesiredAccess uint32
	GroupRID      uint32
}

// Opnum 19
type SamrOpenGroupRes struct {
	GroupHandle []byte
	ReturnCode  uint32
}

// Opnum 22
type SamrAddMemberToGroupReq struct {
	GroupHandle []byte
	MemberId    uint32
	Attributes  uint32
}

// Opnum 24
type SamrRemoveMemberFromGroupReq struct {
	GroupHandle []byte
	MemberId    uint32
}

// Opnum 25
type SamrGetMembersInGroupReq struct {
	GroupHandle []byte
}

// Opnum 25
type SamrGetMembersInGroupRes struct {
	Members    SamprGetMembersBuffer
	ReturnCode uint32
}

// Opnum 27
type SamrOpenAliasReq struct {
	DomainHandle  []byte
	DesiredAccess uint32
	AliasId       uint32
}

// Opnum 27
type SamrOpenAliasRes struct {
	AliasHandle []byte
	ReturnCode  uint32
}

// Opnum 31
type SamrAddMemberToAliasReq struct {
	AliasHandle []byte
	MemberId    *msdtyp.SID
}

// Opnum 32
type SamrRemoveMemberFromAliasReq struct {
	AliasHandle []byte
	MemberId    *msdtyp.SID
}

// Opnum 33
type SamrGetMembersInAliasReq struct {
	AliasHandle []byte
}

// Opnum 33
type SamrGetMembersInAliasRes struct {
	Members    SamprPsidArrayOut
	ReturnCode uint32
}

// Opnum 34
type SamrOpenUserReq struct {
	DomainHandle  []byte
	DesiredAccess uint32
	UserId        uint32
}

// Opnum 34
type SamrOpenUserRes struct {
	UserHandle []byte
	ReturnCode uint32
}

// Opnum 35
type SamrDeleteUserReq struct {
	UserHandle []byte
}

// Opnum 47
type SamrQueryInformationUser2Req struct {
	UserHandle           []byte
	UserInformationClass uint16
}

// Opnum 47
type SamrQueryInformationUser2Res struct {
	Buffer     SamprUserInfoBufferUnion
	ReturnCode uint32
}

// Opnum 55
type SamrUnicodeChangePasswordUser2Req struct {
	//BindingHandle           []byte
	ServerName        string
	UserName          string
	NewPwEncWithOldNt []byte
	OldNtEncWithNewNt [16]byte
	LmPresent         uint32 // Actually uint8, but easier for alignment
	NewPwEncWithOldLm []byte
	OldLmEncWithNewLm [16]byte
}

// Opnum 58
type SamrSetInformationUser2Req struct {
	UserHandle           []byte
	UserInformationClass uint16
	Buffer               SamprUserInfoBufferUnion
}

// Opnum 64
type SamrConnect5Req struct {
	ServerName     string
	DesiredAccess  uint32
	InVersion      uint32
	InRevisionInfo SamprRevisionInfoUnion
}

// Opnum 64
type SamrConnect5Res struct {
	OutVersion      uint32
	OutRevisionInfo SamprRevisionInfoUnion
	ServerHandle    []byte
	ReturnCode      uint32
}

// Opnum 65
type SamrRidToSidReq struct {
	Handle []byte
	Rid    uint32
}

// Opnum 65
type SamrRidToSidRes struct {
	Sid        *msdtyp.SID
	ReturnCode uint32
}

type SamprEnumerationBuffer struct {
	EntriesRead uint32
	Buffer      []SamprRidEnumeration
}

type SamprRidEnumeration struct {
	RelativeId uint32
	Name       string
}

type SamprRevisionInfoUnion interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
}

// MS-SAMR Section 2.2.7.3
type EncryptedNtOWFPassword struct {
	data [16]byte
}

// MS-SAMR Section 2.2.7.4
type SamprULongArray struct {
	Count    uint32
	Elements []uint32 // Actually a pointer to the array
}

// MS-SAMR Section 2.2.7.6
type SamprSidInformation struct {
	SidPointer *msdtyp.SID
}

// MS-SAMR Section 2.2.7.7
type SamprPsidArrayOut struct {
	Count uint32
	Sids  []SamprSidInformation
}

// MS-SAMR Section 2.2.7.8
type SamprReturnedUstringArray struct {
	Count    uint32
	Elements []string // []msdtyp.RPCUnicodeStr (Actually pointers to the structs)
}

// MS-SAMR Section 2.2.7.14
type SamprGetMembersBuffer struct {
	MemberCount uint32
	Members     []uint32
	Attributes  []uint32
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

// MS-SAMR Section 2.2.6.29
type SamprUserInfoBufferUnion interface {
	MarshalBinary() ([]byte, error)
	//UnmarshalBinary([]byte) (error)
}

// MS-SAMR Section 2.2.6.5
// unsigned short UnitsPerWeek;
// [size_is(1260), length_is((UnitsPerWeek+7)/8)]
// unsigned char* LogonHours;
type SamrLogonHours struct {
	UnitsPerWeek uint16
	LogonHours   []byte
}

// MS-SAMR Section 2.2.6.21
type SamprUserPassword struct {
	Buffer []byte
	Length uint32
}

// MS-SAMR Section 2.2.6.24
type SamprUserInternal4Information struct {
	I1           SamprUserAllInformation
	UserPassword []byte
}

// MS-SAMR Section 2.2.6.6
type SamprUserAllInformation struct {
	LastLogon            msdtyp.Filetime
	LastLogoff           msdtyp.Filetime
	PasswordLastSet      msdtyp.Filetime
	AccountExpires       msdtyp.Filetime
	PasswordCanChange    msdtyp.Filetime
	PasswordMustChange   msdtyp.Filetime
	Username             string
	Fullname             string
	HomeDirectory        string
	HomeDirectoryPath    string
	ScriptPath           string
	ProfilePath          string
	AdminComment         string
	WorkStations         string
	UserComment          string
	Parameters           string
	LmOwfPassword        any
	NtOwfPassword        any
	PrivateData          string
	SecurityDescriptor   *msdtyp.SID
	UserId               uint32
	PrimaryGroupId       uint32
	UserAccountControl   uint32
	WhichFields          uint32
	LogonHours           SamrLogonHours
	BadPasswordCount     uint16
	LogonCount           uint16
	CountryCode          uint16
	CodePage             uint16
	LmPasswordPresent    bool
	NtPasswordPresent    bool
	PasswordExpired      bool
	PrivateDataSensitive bool
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
	LogonHours         *SamrLogonHours
	UnExpirePassword   bool // Only to set password NOT Expired
	NewPassword        string
}

type SamrGroupMember struct {
	RID        uint32
	Attributes uint32
}

func (self *SamrCloseHandleReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrCloseHandleReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.ServerHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrConnect5Req) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrConnect5Req")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.ServerName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.ServerName != "" {
		refId++
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.InVersion)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.InRevisionInfo.MarshalBinary()
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

func (self *SamrConnect5Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrConnect5Req")
}

func (self *SamrConnect5Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrConnect5Res")
}

func (self *SamrConnect5Res) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrConnect5Res")
	if len(buf) < 40 {
		return fmt.Errorf("Buffer to small for SamrConnect5Res")
	}
	r := bytes.NewReader(buf)

	// Start with fixed size fields
	_, err = r.Seek(-24, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ServerHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.ServerHandle)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrConnect5 response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.OutVersion)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.OutVersion != 1 {
		err = fmt.Errorf("Unknown OutVersion in SamrConnect5 response: %d", self.OutVersion)
		log.Errorln(err)
		return
	}

	switch self.OutVersion {
	case 1:
		var data SamprRevisionInfoV1
		err = data.UnmarshalBinary(buf[4:])
		if err != nil {
			log.Errorln(err)
			return
		}
		self.OutRevisionInfo = &data
	default:
		err = fmt.Errorf("Unknown Version %d in SamrConnect5 response structure", self.OutVersion)
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrQueryInformationUser2Req) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrQueryInformationUser2Req")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.UserHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.UserInformationClass)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrQueryInformationUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrQueryInformationUser2Req")
}

func (self *SamrQueryInformationUser2Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrQueryInformationUser2Res")
}

func (self *SamrQueryInformationUser2Res) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrQueryInformationUser2Res")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for SamrQueryInformationUser2Res")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrQueryInformationUser2 response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	if len(buf) <= 8 {
		// Empty result
		return
	}

	// Return to start and skip Ref id ptr
	_, err = r.Seek(4, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	var infoClass uint16
	err = binary.Read(r, le, &infoClass)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip padding
	_, err = r.Seek(2, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch infoClass {
	case UserAllInformation:
		var allInfo SamprUserAllInformation
		err = allInfo.ReadSamprUserAllInformation(r)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Buffer = &allInfo

	default:
		err = fmt.Errorf("Unsupported InformationClass: %d", infoClass)
		return
	}

	return
}

func (self *SamrUnicodeChangePasswordUser2Req) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrUnicodeChangePasswordUser2Req")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	if self.ServerName == "" {
		err = binary.Write(w, le, uint32(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.ServerName, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.UserName, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.UserName != "" {
		refId++
	}

	// Write refId ptr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	if self.NewPwEncWithOldNt == nil {
		// Empty password
		self.NewPwEncWithOldNt = make([]byte, 516)
	}
	err = binary.Write(w, le, self.NewPwEncWithOldNt)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Write refId ptr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.OldNtEncWithNewNt)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if self.NewPwEncWithOldLm != nil {
		self.LmPresent = 1
	}
	err = binary.Write(w, le, self.LmPresent)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Write refId ptr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	if self.NewPwEncWithOldLm == nil {
		// Empty password
		self.NewPwEncWithOldLm = make([]byte, 516)
	}
	err = binary.Write(w, le, self.NewPwEncWithOldLm)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	// Write refId ptr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.OldLmEncWithNewLm)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

func (self *SamrUnicodeChangePasswordUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrUnicodeChangePasswordUser2Req")
}

func (self *SamrSetInformationUser2Req) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrSetInformationUser2Req")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.UserHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.UserInformationClass)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.Buffer.MarshalBinary()
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

func (self *SamrSetInformationUser2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrSetInformationUser2Req")
}

func (self *SamrLookupDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrLookupDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	err = binary.Write(w, le, self.ServerHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	var n int
	n, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.Name.S, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = w.Bytes()

	encodedStringSize := 20 + len(self.Name.S)*2
	padd := n - encodedStringSize
	if padd < 0 {
		err = fmt.Errorf("Failed to marshal all %d bytes to byte buffer. Only wrote %d bytes", encodedStringSize, n)
		log.Errorln(err)
		return
	} else if padd > 0 {
		// Since this is the last member of the request structure we do not need to add padding
		// But because WriteRPCUnicodeString adds padding to all strings we remove it here
		res = res[:len(res)-padd]
	}

	return
}

func (self *SamrLookupDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupDomainReq")
}

func (self *SamrLookupDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupDomainRes")
}

func (self *SamrLookupDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrLookupDomainRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for SamrLookupDomainRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrLookupDomain response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}
	if len(buf) <= 8 {
		// Empty result
		return
	}

	// Return to start and skip 8 bytes for Ref id ptr and Count
	// Not sure where this structure with a 4 byte Count field is defined
	_, err = r.Seek(8, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.DomainId, err = msdtyp.ReadSID(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrAddMemberToGroupReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrAddMemberToGroupReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.GroupHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.MemberId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Attributes)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = w.Bytes()

	return
}

func (self *SamrAddMemberToGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrAddMemberToGroupReq")
}

func (self *SamrRemoveMemberFromGroupReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrRemoveMemberFromGroupReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.GroupHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.MemberId)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = w.Bytes()

	return
}

func (self *SamrRemoveMemberFromGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRemoveMemberFromGroupReq")
}

func (self *SamrOpenDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrOpenDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.ServerHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.DomainId.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	// First write the number of sub authorities before the actual SID
	// Probably since it is handled as an array by NDR?
	err = binary.Write(w, le, uint32(self.DomainId.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrOpenDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenDomainReq")
}

func (self *SamrOpenDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenDomainRes")
}

func (self *SamrOpenDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrOpenDomainRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrOpenDomainRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrOpenDomain response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ServerHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.ServerHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrEnumerateGroupsInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrEnumerateGroupsInDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PreferredMaxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrEnumerateGroupsInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumerateGroupsInDomainReq")
}

func (self *SamrEnumerateGroupsInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumerateGroupsInDomainRes")
}

func (self *SamrEnumerateGroupsInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrEnumerateGroupsInDomainRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrEnumerateGroupsInDomainRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Continue with other fixed size fields
	_, err = r.Seek(-8, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.CountReturned)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.CountReturned == 0 {
		return
	}

	err = self.Buffer.UnmarshalBinary(buf[4 : len(buf)-8])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrCreateUserInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrCreateUserInDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.Name, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrCreateUserInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrCreateUserInDomainReq")
}

func (self *SamrCreateUserInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrCreateUserInDomainRes")
}

func (self *SamrCreateUserInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrCreateUserInDomainRes")
	if len(buf) < 28 {
		return fmt.Errorf("Buffer to small for SamrCreateUserInDomainRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrCreateUserInDomain response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.UserHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.UserHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.RelativeId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrEnumDomainUsersReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrEnumDomainUsersReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.AccountFlags)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PreferredMaxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrEnumDomainUsersReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumDomainUsersReq")
}

func (self *SamrEnumDomainUsersRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumDomainUsersRes")
}

func (self *SamrEnumDomainUsersRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrEnumDomainUsersRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer to small for SamrEnumDomainUsersRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Continue with fixed size fields
	_, err = r.Seek(-8, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.CountReturned)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.CountReturned == 0 {
		return
	}

	// Since we do not return directly for some errors, we need to keep track of the previous error
	err = self.Buffer.UnmarshalBinary(buf[4 : len(buf)-8])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrEnumAliasesInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrEnumAliasesInDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PreferredMaxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrEnumAliasesInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumAliasesInDomainReq")
}

func (self *SamrEnumAliasesInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumAliasesInDomainRes")
}

func (self *SamrEnumAliasesInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrEnumAliasesInDomainRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrEnumAliasesInDomainRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Continue with other fixed size fields
	_, err = r.Seek(-8, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.CountReturned)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.CountReturned == 0 {
		return
	}

	err = self.Buffer.UnmarshalBinary(buf[4 : len(buf)-8])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrAddMemberToAliasReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrAddMemberToAliasReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AliasHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.MemberId.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	// First write the number of sub authorities before the actual SID
	// Probably since it is handled as an array by NDR?
	err = binary.Write(w, le, uint32(self.MemberId.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = w.Bytes()

	return
}

func (self *SamrAddMemberToAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrAddMemberToAliasReq")
}

func (self *SamrRemoveMemberFromAliasReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrRemoveMemberFromAliasReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AliasHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.MemberId.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	// First write the number of sub authorities before the actual SID
	// Probably since it is handled as an array by NDR?
	err = binary.Write(w, le, uint32(self.MemberId.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = w.Bytes()

	return
}

func (self *SamrRemoveMemberFromAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRemoveMemberFromAliasReq")
}

func (self *SamrLookupNamesInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrLookupNamesInDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Count)
	if err != nil {
		log.Errorln(err)
		return
	}

	// DCERPC (NDR) 14.3.3.4 Uni-dimensional Conformant-varying Arrays
	_, err = msdtyp.WriteUniDimensionalConformanVaryingArray(w, self.Names, 1000, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrLookupNamesInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupNamesInDomainReq")
}

func (self *SamrLookupNamesInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupNamesInDomainRes")
}

func (self *SamrLookupNamesInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrLookupNamesInDomainRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for SamrLookupNamesInDomainRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if (self.ReturnCode > 0) && (self.ReturnCode != StatusSomeNotMapped) {
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.RelativeIds.fromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.Use.fromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrLookupIdsInDomainReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrLookupIdsInDomainReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Count)
	if err != nil {
		log.Errorln(err)
		return
	}

	// DCERPC (NDR) 14.3.3.4 Uni-dimensional Conformant-varying (Arrays inside a struct)
	// Write Max Count
	err = binary.Write(w, le, uint32(1000)) // Max value allowed by protocol
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, uint32(0)) // Offset
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint32(len(self.RelativeIds))) // ActualCount
	if err != nil {
		log.Errorln(err)
		return
	}
	for _, val := range self.RelativeIds {
		err = binary.Write(w, le, val) // RID
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (self *SamrLookupIdsInDomainReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrLookupIdsInDomainReq")
}

func (self *SamrLookupIdsInDomainRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrLookupIdsInDomainRes")
}

func (self *SamrLookupIdsInDomainRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrLookupIdsInDomainRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for SamrLookupIdsInDomainRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	if (self.ReturnCode > 0) && (self.ReturnCode != StatusSomeNotMapped) {
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.Names.Count)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.Names.Count == 0 {
		return
	}
	self.Names.Elements, err = msdtyp.ReadRPCUnicodeStrArray(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	useCount := uint32(0)
	err = binary.Read(r, le, &useCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip refid ptr and max count
	_, err = r.Seek(8, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := 0; i < int(useCount); i++ {
		var use uint32
		err = binary.Read(r, le, &use)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Use = append(self.Use, use)
	}

	return
}

func (self *SamrOpenGroupReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrOpenGroupReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.GroupRID)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrOpenGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenGroupReq")
}

func (self *SamrOpenGroupRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenGroupRes")
}

func (self *SamrOpenGroupRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrOpenGroupRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrOpenGroupRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrOpenGroup response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.GroupHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.GroupHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrOpenAliasReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrOpenAliasReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.AliasId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrOpenAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenAliasReq")
}

func (self *SamrOpenAliasRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenAliasRes")
}

func (self *SamrOpenAliasRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrOpenAliasRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrOpenAliasRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrOpenAlias response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.AliasHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.AliasHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrGetMembersInAliasReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrGetMembersInAliasReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AliasHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrGetMembersInAliasReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrGetMembersInAliasReq")
}

func (self *SamrGetMembersInAliasRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrGetMembersInAliasRes")
}

func (self *SamrGetMembersInAliasRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrGetMembersInAliasRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for SamrGetMembersInAliasRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrGetMembersInAlias response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.Members.Count)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.Members.Count == 0 {
		return
	}

	// Skip max count and ref id ptrs
	_, err = r.Seek(int64(8+4*self.Members.Count), io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(self.Members.Count); i++ {
		var sidInfo SamprSidInformation
		// Skip count before each SID struct
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		sidInfo.SidPointer, err = msdtyp.ReadSID(r)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Members.Sids = append(self.Members.Sids, sidInfo)
	}

	return
}

func (self *SamrOpenUserReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrOpenUserReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.DomainHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.UserId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrOpenUserReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrOpenUserReq")
}

func (self *SamrOpenUserRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrOpenUserRes")
}

func (self *SamrOpenUserRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrOpenUserRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for SamrOpenUserRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrOpenUser response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.UserHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.UserHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrDeleteUserReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrDeleteUserReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.UserHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrDeleteUserReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrDeleteUserReq")
}

func (self *SamrEnumDomainsReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrEnumDomainsReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.ServerHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PreferredMaxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrEnumDomainsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrEnumDomainsReq")
}

func (self *SamrEnumDomainsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrEnumDomainsRes")
}

func (self *SamrEnumDomainsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrEnumDomainsRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer to small for SamrEnumDomainsRes")
	}
	r := bytes.NewReader(buf)

	// Start with fixed size fields
	_, err = r.Seek(-8, io.SeekEnd)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.CountReturned)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrEnumDomains response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	if self.CountReturned == 0 {
		err = fmt.Errorf("Received SamrEnumDomains response with 0 domains returned")
		log.Errorln(err)
		return
	}

	err = self.Buffer.UnmarshalBinary(buf[4 : len(buf)-8])
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamprRevisionInfoV1) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamprRevisionInfoV1")

	var ret []byte
	w := bytes.NewBuffer(ret)

	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, uint32(1))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, self.Revision)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = binary.Write(w, le, self.SupportedFeatures)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

func (self *SamprRevisionInfoV1) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamprRevisionInfoV1")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer to small for SamprRevisionInfoV1")
	}
	r := bytes.NewReader(buf)

	// Skip union switch (level)
	_, err = r.Seek(4, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.Revision)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.SupportedFeatures)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

func (self *SamprEnumerationBuffer) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamprEnumerationBuffer")
	if len(buf) < 4 {
		return fmt.Errorf("Buffer to small for SamprEnumerationBuffer")
	}
	r := bytes.NewReader(buf)
	// Skip ref id ptr
	_, err = r.Seek(4, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.EntriesRead)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.EntriesRead > 0 {
		if len(buf) < int(16+(24*self.EntriesRead)) {
			err = fmt.Errorf("SamprEnumerationBuffer is too small to contain %d entries", self.EntriesRead)
			log.Errorln(err)
			return
		}
		// Skip ref id ptr and max count
		_, err = r.Seek(8, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	for i := 0; i < int(self.EntriesRead); i++ {
		var item SamprRidEnumeration
		err = binary.Read(r, le, &item.RelativeId)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Skip entry len, size and ref id ptr
		_, err = r.Seek(8, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Buffer = append(self.Buffer, item)
	}

	for i := 0; i < int(self.EntriesRead); i++ {
		self.Buffer[i].Name, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return nil
}

func (self *SamrRidToSidReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrRidToSidReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Handle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Rid)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrRidToSidReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrRidToSidReq")
}

func (self *SamrRidToSidRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrRidToSidRes")
}

func (self *SamrRidToSidRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrRidToSidRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for SamrRidToSidRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrRidToSid response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	// Skip referent Id ptr and sub authority count
	_, err = r.Seek(8, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.Sid, err = msdtyp.ReadSID(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamrGetMembersInGroupReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamrGetMembersInGroupReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.GroupHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SamrGetMembersInGroupReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of SamrGetMembersInGroupReq")
}

func (self *SamrGetMembersInGroupRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of SamrGetMembersInGroupRes")
}

func (self *SamrGetMembersInGroupRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for SamrGetMembersInGroupRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for SamrGetMembersInGroupRes")
	}
	r := bytes.NewReader(buf)

	// Start with ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
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
		status, found := ResponseCodeMap[self.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown Samr return code for SamrGetMembersInGroup response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.Members.fromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamprUserInternal4Information) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamprUserInternal4Information")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)
	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, UserInternal4Information)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = self.I1.WriteSamprUserAllInformation(w, &refId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if self.UserPassword == nil {
		// Empty password
		self.UserPassword = make([]byte, 516)
	}
	err = binary.Write(w, le, self.UserPassword)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

func (self *SamprUserAllInformation) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamprUserAllInformation")
	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// When encoding a union type that is switched by a uint32 variable
	// first encode the union switch (level)
	err = binary.Write(w, le, UserAllInformation)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	err = self.WriteSamprUserAllInformation(w, &refId)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

func (self *SamprUserAllInformation) WriteSamprUserAllInformation(w io.Writer, refId *uint32) (err error) {
	log.Debugln("In WriteSamprUserAllInformation")

	_, err = self.LastLogon.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = self.LastLogoff.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = self.PasswordLastSet.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = self.AccountExpires.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = self.PasswordCanChange.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = self.PasswordMustChange.ToWriter(w)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.Username, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.Fullname, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.HomeDirectory, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.HomeDirectoryPath, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.ScriptPath, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.ProfilePath, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.AdminComment, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.WorkStations, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.UserComment, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.Parameters, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint64(0)) // Empty LmOwfPassword
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint64(0)) // Empty NtOwfPassword
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrPtr(w, self.PrivateData, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.SecurityDescriptor == nil {
		err = binary.Write(w, le, uint64(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		var buf []byte
		buf, err = self.SecurityDescriptor.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, le, buf)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	err = binary.Write(w, le, self.UserId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PrimaryGroupId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.UserAccountControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.WhichFields)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.LogonHours.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.BadPasswordCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.LogonCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.CountryCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.CodePage)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.LmPasswordPresent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.NtPasswordPresent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PasswordExpired)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.PrivateDataSensitive)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *SamprUserAllInformation) ReadSamprUserAllInformation(r *bytes.Reader) (err error) {
	log.Debugln("In ReadSamprUserAllInformation")

	err = self.LastLogon.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.LastLogoff.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = self.PasswordLastSet.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.AccountExpires.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.PasswordCanChange.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.PasswordMustChange.FromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip array item len, max size and ref id ptr for the 10 strings
	_, err = r.Seek(int64(8*10), io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	// MS-SAMR Section 3.1.5.5.5
	// Skip LM/NT Ows Password, PrivateData and SecurityDescriptor which are never present
	_, err = r.Seek(32, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.UserId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.PrimaryGroupId)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.UserAccountControl)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.WhichFields)
	if err != nil {
		log.Errorln(err)
		return
	}

	// LogonHours structure is 2 bytes UnitsPerWeek followed by a ptr to a byte array
	// But because it is NDR encoding with nested structures, there is first a ptr to
	// array (refId) and then the actual byte buffew with Max Count, Offset,
	// Actual Count comes at the end of this structure, after the Conformant Varying
	// Strings and all the fixed size fields.
	err = binary.Read(r, le, &self.LogonHours.UnitsPerWeek)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip 2 byte alignment and 4 bytes ref id ptr for LogonHours
	_, err = r.Seek(6, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.BadPasswordCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.LogonCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.CountryCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.CodePage)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.LmPasswordPresent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.NtPasswordPresent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.PasswordExpired)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.PrivateDataSensitive)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.Username, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.Fullname, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.HomeDirectory, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.HomeDirectoryPath, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ScriptPath, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ProfilePath, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.AdminComment, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.WorkStations, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.UserComment, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.Parameters, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.LogonHours.LogonHours, _, err = msdtyp.ReadConformantVaryingArray(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (self *SamrLogonHours) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for SamprLogonHours")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, uint32(self.UnitsPerWeek)) // Using 32bit value for alignment
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	if self.UnitsPerWeek == 0 {
		// Write null ptr
		err = binary.Write(w, le, uint32(0))
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	} else {
		err = binary.Write(w, le, self.LogonHours)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	}

	return w.Bytes(), nil
}

func (self *SamprGetMembersBuffer) fromReader(r *bytes.Reader) (err error) {
	log.Debugln("In fromReader for SamprGetMembersBuffer")
	// Skip ref id ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MemberCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ref id ptrs for both lists and maxCount for Members
	_, err = r.Seek(12, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	var rid uint32
	for i := 0; i < int(self.MemberCount); i++ {
		err = binary.Read(r, le, &rid)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Members = append(self.Members, rid)
	}
	// Skip maxCount for Attributes
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	var attribute uint32
	for i := 0; i < int(self.MemberCount); i++ {
		err = binary.Read(r, le, &attribute)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Attributes = append(self.Attributes, attribute)
	}

	return
}

func (self *SamprULongArray) fromReader(r *bytes.Reader) (err error) {
	err = binary.Read(r, le, &self.Count)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip refId and maxCount
	_, err = r.Seek(8, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.Elements = make([]uint32, self.Count)
	for i := 0; i < int(self.Count); i++ {
		err = binary.Read(r, le, &self.Elements[i])
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return
}
