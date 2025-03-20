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

package mslsad

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

// MS-LSAD Section Opnum 0
type LsarCloseReq struct {
	ObjectHandle []byte
}

// MS-LSAD Opnum 7
type LsarQueryInformationPolicyReq struct {
	PolicyHandle     []byte
	InformationClass uint16
}

// MS-LSAD Opnum 7
type LsarQueryInformationPolicyRes struct {
	PolicyInformation LsaprPolicyInformation
	ReturnCode        uint32
}

// MS-LSAD Opnum 10
type LsarCreateAccountReq struct {
	PolicyHandle  []byte
	AccountSid    *msdtyp.SID
	DesiredAccess uint32
}

// MS-LSAD Opnum 10
type LsarCreateAccountRes struct {
	AccountHandle []byte
	ReturnCode    uint32
}

// MS-LSAD Opnum 11
type LsarEnumerateAccountsReq struct {
	PolicyHandle       []byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// MS-LSAD Opnum 11
type LsarEnumerateAccountsRes struct {
	EnumerationContext uint32
	EnumerationBuffer  *LsaprAccountEnumBuffer
	ReturnCode         uint32
}

// MS-LSAD Opnum 17
type LsarOpenAccountReq struct {
	PolicyHandle  []byte
	AccountSid    msdtyp.SID
	DesiredAccess uint32
}

// MS-LSAD Opnum 17
type LsarOpenAccountRes struct {
	AccountHandle []byte
	ReturnCode    uint32
}

// MS-LSAD Opnum 23
type LsarGetSystemAccessAccountReq struct {
	AccountHandle []byte
}

// MS-LSAD Opnum 23
type LsarGetSystemAccessAccountRes struct {
	SystemAccess uint32
	ReturnCode   uint32
}

// MS-LSAD Opnum 24
type LsarSetSystemAccessAccountReq struct {
	AccountHandle []byte
	SystemAccess  uint32
}

// MS-LSAD Opnum 36
type LsarEnumerateAccountRightsReq struct {
	PolicyHandle []byte
	AccountSid   msdtyp.SID
}

// MS-LSAD Opnum 36
type LsarEnumerateAccountRightsRes struct {
	UserRights LsaprUserRightSet
	ReturnCode uint32
}

// MS-LSAD Opnum 37
type LsarAddAccountRightsReq struct {
	PolicyHandle []byte
	AccountSid   msdtyp.SID
	UserRights   LsaprUserRightSet
}

// MS-LSAD Opnum 38
type LsarRemoveAccountRightsReq struct {
	PolicyHandle []byte
	AccountSid   msdtyp.SID
	AllRights    bool
	UserRights   LsaprUserRightSet
}

// MS-LSAD Opnum 44
type LsarOpenPolicy2Req struct {
	SystemName       string
	ObjectAttributes LsaprObjectAttributes
	DesiredAccess    uint32
}

// MS-LSAD Opnum 44
type LsarOpenPolicy2Res struct {
	PolicyHandle []byte
	ReturnCode   uint32
}

// MS-LSAD Section 2.2.2.4
type LsaprObjectAttributes struct {
	Length                   uint32                   // Must be ignored
	RootDirectory            string                   // Must be NULL
	ObjectName               string                   // Must be ignored
	Attributes               uint32                   // Must be ignored
	SecurityDescriptor       *msdtyp.SID              // Must be ignored
	SecurityQualityOfService SecurityQualityOfService // Must be ignored
}

// MS-LSAD Section 2.2.3.7
type SecurityQualityOfService struct {
	Length              uint32
	ImpersonationLevel  uint16
	ContextTrackingMode uint8
	EffectiveOnly       uint8
}

// MS-LSAD Section 2.2.4.2
type LsaprPolicyInformation interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary([]byte) error
	//fromReader(r *bytes.Reader) (err error)
	//toWriter(w io.Writer, refId *uint32) (err error)
}

// MS-LSAD Section 2.2.4.5
type LsaprPolicyPrimaryDomInfo struct {
	Name string
	Sid  *msdtyp.SID
}

// MS-LSAD Section 2.2.5.1
type LsaprAccountInformation struct {
	Sid *msdtyp.SID
}

// MS-LSAD Section 2.2.5.2
type LsaprAccountEnumBuffer struct {
	Entries     uint32
	Information []LsaprAccountInformation
}

// MS-LSAD Section 2.2.5.3
type LsaprUserRightSet struct {
	Entries    uint32
	UserRights []string // Use ReadRPCUnicodeStrArray/WriteRPCUnicodeStrArray
}

func (self *SecurityQualityOfService) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarSecurityQualityOfService")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Length)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ImpersonationLevel)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ContextTrackingMode)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.EffectiveOnly)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsaprObjectAttributes) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarObjectAttributes")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Length)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint32(0)) // RootDirectory
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint32(0)) // ObjectName
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Attributes)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint32(0)) // SecurityDescriptor
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	err = binary.Write(w, le, refId) // refId ptr for the SecurityQualityOfService
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.SecurityQualityOfService.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(buf) // SecurityQualityOfService
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (self *LsaprAccountEnumBuffer) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsaprAccountEnumBufferRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for LsaprAccountEnumBufferRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.Entries)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.Entries == 0 {
		return
	}

	// skip ref id, max count nested ref id ptr for each SID structure
	_, err = r.Seek(8+int64(self.Entries*4), io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(self.Entries); i++ {
		var sid *msdtyp.SID
		// Skip count
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		sid, err = msdtyp.ReadSID(r)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Information = append(self.Information, LsaprAccountInformation{Sid: sid})
	}

	return
}

func (self *LsaprUserRightSet) fromReader(r *bytes.Reader) (err error) {
	log.Debugln("In fromReader for LsaprUserRightSet")

	err = binary.Read(r, le, &self.Entries)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.Entries == 0 {
		// Maybe read more from the reader if empty list?
		return
	}

	self.UserRights, err = msdtyp.ReadRPCUnicodeStrArray(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *LsaprUserRightSet) toWriter(w io.Writer, refId *uint32) (err error) {
	log.Debugln("In toWriter for LsaprUserRightSet")

	self.Entries = uint32(len(self.UserRights))

	err = binary.Write(w, le, &self.Entries)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = msdtyp.WriteRPCUnicodeStrArray(w, self.UserRights, refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *LsaprPolicyPrimaryDomInfo) fromReader(r *bytes.Reader) (err error) {
	log.Debugln("In fromReader for LsaprPolicyPrimaryDomInfo")

	var count, maxCount uint16
	err = binary.Read(r, le, &count)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip refId ptr in both structs
	_, err = r.Seek(8, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.Name, err = msdtyp.ReadConformantVaryingString(r, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip SID sub authority count
	_, err = r.Seek(4, io.SeekCurrent)
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

func (self *LsaprPolicyPrimaryDomInfo) toWriter(w io.Writer, refId *uint32) (err error) {
	log.Debugln("In toWriter for LsaprPolicyPrimaryInformation")

	offset, count, paddlen, unc := msdtyp.NewUnicodeStr(self.Name, false)
	maxCount := count + 1

	// First write len and size of unicode string for name field
	err = binary.Write(w, le, count*2)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, maxCount*2)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Write RefId ptr for name struct
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	*refId++
	// Write RefId ptr for SID struct
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	*refId++

	// Write Unicode string
	err = binary.Write(w, le, count)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, offset)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, unc)
	if err != nil {
		log.Errorln(err)
		return
	}
	if paddlen > 0 {
		buf := make([]byte, paddlen)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	sidBuf, err := self.Sid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	// Write SID sub authority count
	err = binary.Write(w, le, uint32(self.Sid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	// Write SID
	err = binary.Write(w, le, sidBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *LsaprPolicyPrimaryDomInfo) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsaprPolicyPrimaryDomInfo")
	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)
	err = self.toWriter(w, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsaprPolicyPrimaryDomInfo) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsaprPolicyPrimaryDomInfo")
	r := bytes.NewReader(buf)
	return self.fromReader(r)
}

func (self *LsarCloseReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarCloseReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.ObjectHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarCloseReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarCloseReq")
}

func (self *LsarQueryInformationPolicyReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarQueryInformationPolicyReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.InformationClass)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarQueryInformationPolicyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarQueryInformationPolicyReq")
}

func (self *LsarQueryInformationPolicyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarQueryInformationPolicyRes")
}

func (self *LsarQueryInformationPolicyRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarQueryInformationPolicyRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for LsarQueryInformationPolicyRes")
	}
	r := bytes.NewReader(buf)
	// Begin by reading the return code
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
			err = fmt.Errorf("Received unknown LSAD return code for LsarQueryInformationPolicy response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	// Skip ref id ptr
	_, err = r.Seek(4, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	var val uint32
	err = binary.Read(r, le, &val)
	if err != nil {
		log.Errorln(err)
		return
	}
	var informationPolicy uint16
	informationPolicy = uint16(val)
	switch informationPolicy {
	case PolicyPrimaryDomainInformation:
		var info LsaprPolicyPrimaryDomInfo
		err = info.fromReader(r)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.PolicyInformation = &info
	}

	return
}

func (self *LsarCreateAccountReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarCreateAccountReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := self.AccountSid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	// First write the number of sub authorities before the actual SID
	err = binary.Write(w, le, uint32(self.AccountSid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
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

func (self *LsarCreateAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarCreateAccountReq")
}

func (self *LsarCreateAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarCreateAccountRes")
}

func (self *LsarCreateAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarCreateAccountRes")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for LsarCreateAccountRes")
	}
	r := bytes.NewReader(buf)
	// Begin by reading the return code
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
			err = fmt.Errorf("Received unknown LSAD return code for LsarCreateAccount response: 0x%x\n", self.ReturnCode)
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

	self.AccountHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.AccountHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *LsarEnumerateAccountsReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarEnumerateAccountsReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.PolicyHandle)
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

func (self *LsarEnumerateAccountsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarEnumerateAccountsReq")
}

func (self *LsarEnumerateAccountsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarEnumerateAccountsRes")
}

func (self *LsarEnumerateAccountsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarEnumerateAccountsRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for LsarEnumerateAccountsRes")
	}
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &self.EnumerationContext)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read the return code
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
			err = fmt.Errorf("Received unknown LSAD return code for LsarEnumerateAccounts response: 0x%x\n", self.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		log.Errorln(err)
		return
	}

	buflen := len(buf)
	var res LsaprAccountEnumBuffer
	err = res.UnmarshalBinary(buf[4 : buflen-4])
	if err != nil {
		log.Errorln(err)
		return
	}
	self.EnumerationBuffer = &res
	return
}

func (self *LsarOpenAccountReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarOpenAccountReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	// First write number of subauthorities
	err = binary.Write(w, le, uint32(self.AccountSid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := self.AccountSid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
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

func (self *LsarOpenAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarOpenAccountReq")
}

func (self *LsarOpenAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarOpenAccountRes")
}

func (self *LsarOpenAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarOpenAccountRes")
	if len(buf) < 20 {
		return fmt.Errorf("Buffer to small for LsarOpenAccountRes")
	}
	r := bytes.NewReader(buf)
	// Begin by reading the return code
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
			err = fmt.Errorf("Received unknown LSAD return code for LsarOpenAccount response: 0x%x\n", self.ReturnCode)
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

	self.AccountHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.AccountHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (self *LsarGetSystemAccessAccountReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarGetSystemAccessAccountReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AccountHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarGetSystemAccessAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarGetSystemAccessAccountReq")
}

func (self *LsarGetSystemAccessAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarGetSystemAccessAccountRes")
}

func (self *LsarGetSystemAccessAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarGetSystemAccessAccountRes")
	if len(buf) < 8 {
		return fmt.Errorf("Buffer to small for LsarGetSystemAccessAccountRes")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.SystemAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *LsarSetSystemAccessAccountReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarSetSystemAccessAccountReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AccountHandle)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.SystemAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarSetSystemAccessAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarSetSystemAccessAccountReq")
}

func (self *LsarEnumerateAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarEnumerateAccountRightsReq")

	var ret []byte
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	// First write number of subauthorities
	err = binary.Write(w, le, uint32(self.AccountSid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := self.AccountSid.MarshalBinary()
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

func (self *LsarEnumerateAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarEnumerateAccountRightsReq")
}

func (self *LsarEnumerateAccountRightsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarEnumerateAccountRightsRes")
}

func (self *LsarEnumerateAccountRightsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarEnumerateAccountRightsRes")
	if len(buf) < 12 {
		return fmt.Errorf("Buffer to small for LsarEnumerateAccountRightsRes")
	}
	r := bytes.NewReader(buf)
	// Begin by reading the return code
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
		return
	}

	_, err = r.Seek(0, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.UserRights.fromReader(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func (self *LsarAddAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarAddAccountRightsReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	var refId uint32 = 1

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	// First write number of subauthorities
	err = binary.Write(w, le, uint32(self.AccountSid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := self.AccountSid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.UserRights.toWriter(w, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarAddAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarAddAccountRightsReq")
}

func (self *LsarRemoveAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarRemoveAccountRightsReq")

	var ret []byte
	w := bytes.NewBuffer(ret)
	var refId uint32 = 1

	err = binary.Write(w, le, self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	// First write number of subauthorities
	err = binary.Write(w, le, uint32(self.AccountSid.NumAuth))
	if err != nil {
		log.Errorln(err)
		return
	}
	buf, err := self.AccountSid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	allRights := uint32(0)
	if self.AllRights {
		allRights = 1
	}
	err = binary.Write(w, le, allRights)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = self.UserRights.toWriter(w, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *LsarRemoveAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarRemoveAccountRightsReq")
}

func (self *LsarOpenPolicy2Req) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for LsarOpenPolicy2Req")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refId := uint32(1)

	// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
	_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.SystemName, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}
	if self.SystemName != "" {
		refId++
	}

	buf, err := self.ObjectAttributes.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(buf) // ObjectAttributes
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

func (self *LsarOpenPolicy2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of LsarOpenPolicy2Req")
}

func (self *LsarOpenPolicy2Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary of LsarOpenPolicy2Res")
}

func (self *LsarOpenPolicy2Res) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for LsarOpenPolicy2Res")
	if len(buf) < 24 {
		return fmt.Errorf("Buffer to small for LsarOpenPolicy2Res")
	}
	r := bytes.NewReader(buf)

	// Begin by reading the return code
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
			err = fmt.Errorf("Received unknown LSAD return code for LsarOpenPolicy response: 0x%x\n", self.ReturnCode)
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

	self.PolicyHandle = make([]byte, 20)
	err = binary.Read(r, le, &self.PolicyHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}
