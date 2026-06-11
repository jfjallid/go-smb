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

// MS-LSAD Section Opnum 0
type LsarCloseReq struct {
	ObjectHandle [20]byte
}

// MS-LSAD Opnum 7
type LsarQueryInformationPolicyReq struct {
	PolicyHandle     [20]byte
	InformationClass uint16
}

// MS-LSAD Opnum 7
type LsarQueryInformationPolicyRes struct {
	PolicyInformation *LsaprPolicyInformation `ndr:"toplevel,fullpointer"`
	ReturnCode        uint32
}

// MS-LSAD Opnum 10
type LsarCreateAccountReq struct {
	PolicyHandle  [20]byte
	AccountSid    msdtyp.SID `ndr:"toplevel"`
	DesiredAccess uint32
}

// MS-LSAD Opnum 10
type LsarCreateAccountRes struct {
	AccountHandle [20]byte
	ReturnCode    uint32
}

// MS-LSAD Opnum 11
type LsarEnumerateAccountsReq struct {
	PolicyHandle       [20]byte
	EnumerationContext uint32
	PreferredMaxLength uint32
}

// MS-LSAD Opnum 11
type LsarEnumerateAccountsRes struct {
	EnumerationContext uint32
	EnumerationBuffer  *LsaprAccountEnumBuffer `ndr:"toplevel"`
	ReturnCode         uint32
}

// MS-LSAD Opnum 17
type LsarOpenAccountReq struct {
	PolicyHandle  [20]byte
	AccountSid    msdtyp.SID `ndr:"toplevel"` // workaround to make sure conformant max is not hoisted before PolicyHandle
	DesiredAccess uint32
}

// MS-LSAD Opnum 17
type LsarOpenAccountRes struct {
	AccountHandle [20]byte
	ReturnCode    uint32
}

// MS-LSAD Opnum 23
type LsarGetSystemAccessAccountReq struct {
	AccountHandle [20]byte
}

// MS-LSAD Opnum 23
type LsarGetSystemAccessAccountRes struct {
	SystemAccess uint32
	ReturnCode   uint32
}

// MS-LSAD Opnum 24
type LsarSetSystemAccessAccountReq struct {
	AccountHandle [20]byte
	SystemAccess  uint32
}

// MS-LSAD Opnum 36
type LsarEnumerateAccountRightsReq struct {
	PolicyHandle [20]byte
	AccountSid   msdtyp.SID `ndr:"toplevel"`
}

// MS-LSAD Opnum 36
type LsarEnumerateAccountRightsRes struct {
	UserRights LsaprUserRightSet `ndr:"toplevel"`
	ReturnCode uint32
}

// MS-LSAD Opnum 37
type LsarAddAccountRightsReq struct {
	PolicyHandle [20]byte
	AccountSid   msdtyp.SID        `ndr:"toplevel"`
	UserRights   LsaprUserRightSet `ndr:"toplevel"`
}

// MS-LSAD Opnum 38
type LsarRemoveAccountRightsReq struct {
	PolicyHandle [20]byte
	AccountSid   msdtyp.SID `ndr:"toplevel"`
	AllRights    bool
	UserRights   LsaprUserRightSet `ndr:"toplevel"`
}

// MS-LSAD Opnum 44
type LsarOpenPolicy2Req struct {
	SystemName       string                `ndr:"toplevel,fullpointer,conformant,varying"`
	ObjectAttributes LsaprObjectAttributes `ndr:"toplevel"`
	DesiredAccess    uint32
}

// MS-LSAD Opnum 44
type LsarOpenPolicy2Res struct {
	PolicyHandle [20]byte
	ReturnCode   uint32
}

// MS-LSAD Section 2.2.2.4
type LsaprObjectAttributes struct {
	Length                   uint32                   // Must be ignored
	RootDirectory            string                   `ndr:"fullpointer,conformant,varying"` // Must be NULL
	ObjectName               string                   `ndr:"fullpointer,conformant,varying"` // Must be ignored
	Attributes               uint32                   // Must be ignored
	SecurityDescriptor       *msdtyp.SID              `ndr:"fullpointer"` // Must be ignored
	SecurityQualityOfService SecurityQualityOfService `ndr:"fullpointer"` // Must be ignored
}

// MS-LSAD Section 2.2.3.7
type SecurityQualityOfService struct {
	Length              uint32
	ImpersonationLevel  uint16
	ContextTrackingMode uint8
	EffectiveOnly       uint8
}

// // MS-LSAD Section 2.2.4.2
type LsaprPolicyInformation struct {
	Tag                     uint16                    `ndr:"unionTag,encapsulated"`
	PolicyPrimaryDomainInfo LsaprPolicyPrimaryDomInfo `ndr:"unionField"`
}

func (u LsaprPolicyInformation) SwitchFunc(tag interface{}) string {
	t := tag.(uint16)
	switch t {
	case 3: // PolicyPrimaryDomainInformation
		return "PolicyPrimaryDomainInfo"
	}
	return ""
}

// MS-LSAD Section 2.2.4.5
type LsaprPolicyPrimaryDomInfo struct {
	Name mstypes.RPCUnicodeString
	Sid  *msdtyp.SID `ndr:"pointer"`
}

// MS-LSAD Section 2.2.5.1
type LsaprAccountInformation struct {
	Sid *msdtyp.SID `ndr:"pointer"`
}

// MS-LSAD Section 2.2.5.2
type LsaprAccountEnumBuffer struct {
	Entries     uint32
	Information []LsaprAccountInformation `ndr:"pointer,conformant"`
}

// MS-LSAD Section 2.2.5.3
type LsaprUserRightSet struct {
	Entries    uint32
	UserRights []mstypes.RPCUnicodeString `ndr:"fullpointer,conformant"` // [size_is(Entries)] PRPC_UNICODE_STRING
}

func (s *LsarCloseReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarCloseReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarCloseReq: %w", err)
	}
	return
}

func (s *LsarCloseReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarCloseReq")
}

func (s *LsarQueryInformationPolicyReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarQueryInformationPolicyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarQueryInformationPolicyReq: %w", err)
	}
	return
}

func (s *LsarQueryInformationPolicyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarQueryInformationPolicyReq")
}

func (s *LsarQueryInformationPolicyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarQueryInformationPolicyRes")
}

func (s *LsarQueryInformationPolicyRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarQueryInformationPolicyRes")
	if len(buf) < 24 {
		return fmt.Errorf("buffer too small for LsarQueryInformationPolicyRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarQueryInformationPolicyRes: %w", err)
	}

	return
}

func (s *LsarCreateAccountReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarCreateAccountReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarCreateAccountReq: %w", err)
	}
	return
}

func (s *LsarCreateAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarCreateAccountReq")
}

func (s *LsarCreateAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarCreateAccountRes")
}

func (s *LsarCreateAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarCreateAccountRes")
	if len(buf) < 24 {
		return fmt.Errorf("buffer too small for LsarCreateAccountRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarCreateAccountRes: %w", err)
	}

	return
}

func (s *LsarEnumerateAccountsReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarEnumerateAccountsReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarEnumerateAccountsReq: %w", err)
	}
	return
}

func (s *LsarEnumerateAccountsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarEnumerateAccountsReq")
}

func (s *LsarEnumerateAccountsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarEnumerateAccountsRes")
}

func (s *LsarEnumerateAccountsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarEnumerateAccountsRes")
	if len(buf) < 16 {
		return fmt.Errorf("buffer too small for LsarEnumerateAccountsRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarEnumerateAccountsRes: %w", err)
	}

	return
}

func (s *LsarOpenAccountReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarOpenAccountReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarOpenAccountReq: %w", err)
	}
	return
}

func (s *LsarOpenAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarOpenAccountReq")
}

func (s *LsarOpenAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarOpenAccountRes")
}

func (s *LsarOpenAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarOpenAccountRes")
	if len(buf) < 20 {
		return fmt.Errorf("buffer too small for LsarOpenAccountRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarOpenAccountRes: %w", err)
	}

	return
}

func (s *LsarGetSystemAccessAccountReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarGetSystemAccessAccountReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarGetSystemAccessAccountReq: %w", err)
	}
	return
}

func (s *LsarGetSystemAccessAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarGetSystemAccessAccountReq")
}

func (s *LsarGetSystemAccessAccountRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarGetSystemAccessAccountRes")
}

func (s *LsarGetSystemAccessAccountRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarGetSystemAccessAccountRes")
	if len(buf) < 8 {
		return fmt.Errorf("buffer too small for LsarGetSystemAccessAccountRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarGetSystemAccessAccountRes: %w", err)
	}

	return
}

func (s *LsarSetSystemAccessAccountReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarSetSystemAccessAccountReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarSetSystemAccessAccountReq: %w", err)
	}
	return
}

func (s *LsarSetSystemAccessAccountReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarSetSystemAccessAccountReq")
}

func (s *LsarEnumerateAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarEnumerateAccountRightsReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarEnumerateAccountRightsReq: %w", err)
	}
	return
}

func (s *LsarEnumerateAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarEnumerateAccountRightsReq")
}

func (s *LsarEnumerateAccountRightsRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarEnumerateAccountRightsRes")
}

func (s *LsarEnumerateAccountRightsRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarEnumerateAccountRightsRes")
	if len(buf) < 12 {
		return fmt.Errorf("buffer too small for LsarEnumerateAccountRightsRes")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarEnumerateAccountRightsRes: %w", err)
	}
	return
}

func (s *LsarAddAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarAddAccountRightsReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarAddAccountRightsReq: %w", err)
	}
	return
}

func (s *LsarAddAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarAddAccountRightsReq")
}

func (s *LsarRemoveAccountRightsReq) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarRemoveAccountRightsReq")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarRemoveAccountRightsReq: %w", err)
	}
	return
}

func (s *LsarRemoveAccountRightsReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarRemoveAccountRightsReq")
}

func (s *LsarOpenPolicy2Req) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for LsarOpenPolicy2Req")
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	res, err = enc.Encode(s)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarOpenPolicy2Req: %w", err)
	}
	return
}

func (s *LsarOpenPolicy2Req) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("not implemented: UnmarshalBinary of LsarOpenPolicy2Req")
}

func (s *LsarOpenPolicy2Res) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary of LsarOpenPolicy2Res")
}

func (s *LsarOpenPolicy2Res) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for LsarOpenPolicy2Res")
	if len(buf) < 24 {
		return fmt.Errorf("buffer too small for LsarOpenPolicy2Res")
	}
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	err = dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling LsarOpenPolicy2Res: %w", err)
	}

	return
}
