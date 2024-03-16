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
package msrrp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

type ReturnCode struct {
	uint32
}

// MS-DTYP FILETIME
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type PFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

type PACL struct {
	AclRevision uint16
	AclSize     uint16
	AceCount    uint32
	ACLS        []ACE
}

// MS-DTYP Section 2.4.4.1 ACE_HEADER
type ACEHeader struct {
	Type  byte
	Flags byte
	Size  uint16 //Includes header size?
}

type ACE struct {
	Header ACEHeader
	Mask   uint32
	Sid    SID //Must be multiple of 4
}

type SID struct {
	Revision       byte
	NumAuth        byte
	Authority      []byte
	SubAuthorities []uint32
}

// Shared struct, not all fields are used for every response type
type KeyInfo struct {
	KeyName         string
	ClassName       string
	SubKeys         uint32
	MaxSubKeyLen    uint32
	MaxClassLen     uint32
	Values          uint32
	MaxValueNameLen uint32
	MaxValueLen     uint32
}

type ValueInfo struct {
	Name     string
	Type     uint32
	ValueLen uint32
	Value    []byte
}

// Opnums 0-4
type OpenRootKeyReq struct {
	ServerName    uint32 // Should actually be pointer to array of WCHAR elements. But defined as always null.
	DesiredAccess uint32
}

type OpenKeyRes struct {
	HKey       []byte
	ReturnCode uint32
}

// Opnum 5
type BaseRegCloseKeyReq struct {
	HKey []byte
}

// MS-DTYP 2.3.10
/*
typedef struct _RPC_UNICODE_STRING {
  unsigned short Length;
  unsigned short MaximumLength;
  [size_is(MaximumLength/2), length_is(Length/2)]
    WCHAR* Buffer;
} RPC_UNICODE_STRING,
 *PRPC_UNICODE_STRING;
*/
type RPCUnicodeStr struct {
	MaxLength uint16
	S         string // Must NOT be null terminated
}

type RRPUnicodeStr struct {
	MaxLength uint16
	S         string // Must be null terminated
}

type RpcSecurityAttributes struct {
	Length             uint32
	SecurityDescriptor RpcSecurityDescriptor
	InheritHandle      byte
}

type RpcSecurityDescriptor struct {
	SecurityDescriptor    *SecurityDescriptor
	InSecurityDescriptor  uint32 // The "Max Size" to tell the server how much space we've allocated
	OutSecurityDescriptor uint32 // The length of the transmitted security descriptor
}

// Opnum 9
type BaseRegEnumKeyReq struct {
	HKey          []byte
	Index         uint32
	NameIn        RRPUnicodeStr
	ClassIn       RRPUnicodeStr
	LastWriteTime *PFiletime
}

type BaseRegEnumKeyRes struct {
	NameOut       RRPUnicodeStr
	ClassOut      RRPUnicodeStr
	LastWriteTime PFiletime
	ReturnCode    uint32
}

// Opnum 10
/*
error_status_t BaseRegEnumValue(
    [in] RPC_HKEY hKey,
    [in] DWORD dwIndex,
    [in] PRRP_UNICODE_STRING lpValueNameIn,
    [out] PRPC_UNICODE_STRING lpValueNameOut,
    [in, out, unique] LPDWORD lpType,
    [in, out, unique, size_is(lpcbData?*lpcbData:0), length_is(lpcbLen?*lpcbLen:0), range(0, 0x4000000)]
        LPBYTE lpData,
    [in, out, unique] LPDWORD lpcbData,
    [in, out, unique] LPDWORD lpcbLen
);
*/
type BaseRegEnumValueReq struct {
	HKey    []byte
	Index   uint32
	NameIn  RRPUnicodeStr
	Type    uint32
	Data    []byte // Need ReferentId ptr, maxCount, offset and actualCount
	MaxLen  uint32 // How many bytes are allocated .e.g., ActualSize or ActualCount
	DataLen uint32 // How many bytes are transmitted in Data. E.g., ActualSize
}

type BaseRegEnumValueRes struct {
	/*NOTE that NameOut according to MS-RRP is an RPC_UNICODE_STRING which is
	 * defined in MS-DTYP Section 2.3.10 RPC_UNICODE_STRING and as such MUST NOT
	 * be null-terminated. However, of course Microsoft's implementation of SMB
	 * null terminates the names...
	 */
	NameOut    RPCUnicodeStr // Cannot be null terminated?
	Type       uint32
	Data       []byte
	DataLen    uint32
	MaxLen     uint32
	ReturnCode uint32
}

type SecurityDescriptor struct {
	Revision    uint16
	Control     uint16
	OffsetOwner uint32
	OffsetGroup uint32
	OffsetSacl  uint32 // From beginning of struct?
	OffsetDacl  uint32 // From beginning of struct?
	OwnerSid    *SID
	GroupSid    *SID
	Sacl        *PACL
	Dacl        *PACL
}

// Opnum 12
/*
error_status_t
BaseRegGetKeySecurity(
  [ in ] RPC_HKEY hKey,
  [ in ] SECURITY_INFORMATION SecurityInformation,
  [ in ] PRPC_SECURITY_DESCRIPTOR pRpcSecurityDescriptorIn,
  [ out ] PRPC_SECURITY_DESCRIPTOR pRpcSecurityDescriptorOut
);
*/
type BaseRegGetKeySecurityReq struct {
	HKey                 []byte
	SecurityInformation  uint32
	SecurityDescriptorIn RpcSecurityDescriptor // Size of a security descriptor. Data is irrelevant
}

type BaseRegGetKeySecurityRes struct {
	SecurityDescriptorOut RpcSecurityDescriptor
	ReturnCode            uint32
}

// Opnum 15
type BaseRegOpenKeyReq struct {
	HKey          []byte
	SubKey        RRPUnicodeStr
	Options       uint32
	DesiredAccess uint32 // REGSAM
}

// Opnum 16
type BaseRegQueryInfoKeyReq struct {
	HKey    []byte
	ClassIn RRPUnicodeStr // Optional, can be null
}

type BaseRegQueryInfoKeyRes struct {
	ClassOut           RPCUnicodeStr
	SubKeys            uint32
	MaxSubKeyLen       uint32
	MaxClassLen        uint32
	Values             uint32
	MaxValueNameLen    uint32
	MaxValueLen        uint32
	SecurityDescriptor uint32
	LastWriteTime      Filetime
	ReturnCode         uint32
}

// Opnum 17
type BaseRegQueryValueReq struct {
	HKey      []byte
	ValueName RRPUnicodeStr
	Type      uint32
	Data      []byte
	MaxLen    uint32 // How many bytes are allocated .e.g., ActualSize or ActualCount
	DataLen   uint32 // How many bytes are transmitted in Data. E.g., ActualSize
}

type BaseRegQueryValueRes struct {
	Type       uint32
	Data       []byte
	DataLen    uint32
	MaxLen     uint32
	ReturnCode uint32
}

// Opnum 20
type BaseRegSaveKeyReq struct {
	HKey               []byte
	FileName           RRPUnicodeStr
	SecurityAttributes RpcSecurityAttributes
}

// Opnum 21
type BaseRegSetKeySecurityReq struct {
	HKey                 []byte
	SecurityInformation  uint32
	SecurityDescriptorIn RpcSecurityDescriptor
}

func (self *ReturnCode) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for ReturnCode")
}

func (self *ReturnCode) UnmarshalBinary(buf []byte) error {
	self.uint32 = le.Uint32(buf)
	return nil
}

// Useful for decoding BaseRegEnumValueRes
func readRPCUnicodeStr(r *bytes.Reader) (s string, maxLength uint16, err error) {
	l := uint16(0)
	err = binary.Read(r, le, &l)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &maxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Is there any problems with skipping to read more if length is 0
	if l == 0 {
		// Skip null ptr
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
		}
		return
	}

	s, err = readConformantVaryingStringPtr(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func readRPCUnicodeStrPtr(r *bytes.Reader) (s string, maxLength uint16, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return readRPCUnicodeStr(r)
}

func writeRRPUnicodeStr(w io.Writer, bo binary.ByteOrder, us *RRPUnicodeStr, refId *uint32, optional bool) (err error) {
	// Encode the length
	if us.S == "" {
		err = binary.Write(w, bo, uint16(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		us.S = nullTerminate(us.S)
		// Encoded length of the Unicode string
		encodedLen := uint16(len(us.S)) * 2
		err = binary.Write(w, bo, encodedLen)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// Sanity check that MaxLength is not less than actualLength
	l := uint16(len(us.S))
	if us.MaxLength < l {
		us.MaxLength = l
	}

	// Encode maxLength as the size of a unicode string
	err = binary.Write(w, bo, us.MaxLength*2)
	if err != nil {
		log.Errorln(err)
		return
	}

	if us.S == "" && optional {
		// Write null ptr
		err = binary.Write(w, bo, uint32(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		_, err = writeConformantVaryingStringPtr(w, bo, us, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return
}

func (self *RRPUnicodeStr) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	refId := uint32(1)
	err = writeRRPUnicodeStr(w, le, self, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func readRRPUnicodeStr(r *bytes.Reader) (s string, maxLength uint16, err error) {
	s, maxLength, err = readRPCUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	s = stripNullByte(s) // Skip terminating null character
	return
}

func (self *RRPUnicodeStr) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		return fmt.Errorf("Buffer too small for RRPUnicodeStr!")
	}
	r := bytes.NewReader(buf)
	self.S, self.MaxLength, err = readRRPUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

// Opnums 0-4
func (self *OpenRootKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.ServerName)
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

func (self *OpenRootKeyReq) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &self.ServerName)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

func (self *OpenKeyRes) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in OpenKeyRes")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (self *OpenKeyRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		err = fmt.Errorf("Buffer too short to unmarshal OpenKeyRes")
		log.Errorln(err)
		return
	}
	r := bytes.NewReader(buf)
	self.HKey = make([]byte, 20)
	err = binary.Read(r, le, &self.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

// Opnum 5
func (self *BaseRegCloseKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegCloseKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (self *BaseRegCloseKeyReq) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		err = fmt.Errorf("Buffer too short to unmarshal BaseRegCloseKeyReq")
		log.Errorln(err)
		return
	}
	r := bytes.NewReader(buf)
	self.HKey = make([]byte, 20)
	err = binary.Read(r, le, &self.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

// Opnum 9
func (self *BaseRegEnumKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegEnumKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Index)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)

	// Encode the RRPUnicodeStr NameIn
	err = writeRRPUnicodeStr(w, le, &self.NameIn, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode extra ReferentId ptr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	// Encode the RRPUnicodeStr ClassIn
	err = writeRRPUnicodeStr(w, le, &self.ClassIn, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode LastWriteTime
	binary.Write(w, le, refId) // Referent ID
	binary.Write(w, le, self.LastWriteTime.LowDateTime)
	binary.Write(w, le, self.LastWriteTime.HighDateTime)

	return w.Bytes(), nil
}

func (self *BaseRegEnumKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegEnumKeyReq")
}

func (self *BaseRegEnumKeyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegEnumKeyRes")
}

func (self *BaseRegEnumKeyRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 36 {
		return fmt.Errorf("Buffer too short for BaseRegEnumKeyRes")
	}

	r := bytes.NewReader(buf)

	self.NameOut.S, self.NameOut.MaxLength, err = readRRPUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip Referent Id
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	self.ClassOut.S, self.ClassOut.MaxLength, err = readRRPUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip Referent Id
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.LastWriteTime.LowDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.LastWriteTime.HighDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 10
func (self *BaseRegEnumValueReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegEnumValueReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Index)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode ValueNameIn
	err = writeRRPUnicodeStr(w, le, &self.NameIn, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Type
	// Referent ID
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Data
	_, err = writeConformantVaryingArrayPtr(w, self.Data, self.MaxLen, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the MaxLen value
	err = binary.Write(w, le, refId) // Referent ID
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the Actual length of transmitted data value
	err = binary.Write(w, le, refId) // Referent ID
	if err != nil {
		log.Errorln(err)
		return
	}

	refId++
	err = binary.Write(w, le, uint32(len(self.Data)))
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegEnumValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegEnumValueReq")
}

func (self *BaseRegEnumValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegEnumValueRes")
}

func (self *BaseRegEnumValueRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 36 {
		return fmt.Errorf("Buffer to short for BaseRegEnumValueRes")
	}
	r := bytes.NewReader(buf)

	// Read RPCUnicodeStr
	self.NameOut.S, self.NameOut.MaxLength, err = readRPCUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read Type
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read Data
	self.Data, _, err = readConformantVaryingArrayPtr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read DataLen
	// Skip referentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.DataLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read MaxLen
	// Skip referentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

// Opnum 10
func (self *BaseRegGetKeySecurityReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegGetKeySecurityReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.SecurityInformation)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	err = writeRPCSecurityDescriptor(w, le, self.SecurityDescriptorIn, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegGetKeySecurityReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegGetKeySecurityReq")
}

func (self *BaseRegGetKeySecurityRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegGetKeySecurityRes")
}

func (self *BaseRegGetKeySecurityRes) UnmarshalBinary(buf []byte) (err error) {
	// Read SecurityDescriptorOut
	if len(buf) < 16 {
		return fmt.Errorf("Buffer to short for BaseRegGetKeySecurityRes")
	}
	r := bytes.NewReader(buf)

	// Skip ReferentId ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read max size of SecurityDescriptor
	err = binary.Read(r, le, &self.SecurityDescriptorOut.InSecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read actual size of SecurityDescriptor
	err = binary.Read(r, le, &self.SecurityDescriptorOut.OutSecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	data, _, err := readConformantVaryingArray(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	sd := SecurityDescriptor{}
	err = sd.UnmarshalBinary(data)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.SecurityDescriptorOut.SecurityDescriptor = &sd

	// Read ReturnCode
	err = binary.Read(r, le, &self.ReturnCode)

	return nil
}

// Opnum 15
func (self *BaseRegOpenKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegOpenKeyReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode SubKey
	err = writeRRPUnicodeStr(w, le, &self.SubKey, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Options)
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

func (self *BaseRegOpenKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegOpenKeyReq")
}

// Opnum 16
func (self *BaseRegQueryInfoKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegQueryInfoKey")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	err = writeRRPUnicodeStr(w, le, &self.ClassIn, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegQueryInfoKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryInfoKeyReq")
}

func (self *BaseRegQueryInfoKeyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryInfoKeyRes")
}

func (self *BaseRegQueryInfoKeyRes) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	// Read ClassOut
	self.ClassOut.S, self.ClassOut.MaxLength, err = readRPCUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.SubKeys)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MaxSubKeyLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MaxClassLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.Values)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MaxValueNameLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.MaxValueLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.SecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read LastWriteTime
	err = binary.Read(r, le, &self.LastWriteTime.LowDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.LastWriteTime.HighDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 17
func (self *BaseRegQueryValueReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegQueryValueReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode the RRPUnicodeStr ValueName
	err = writeRRPUnicodeStr(w, le, &self.ValueName, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Type
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Data
	_, err = writeConformantVaryingArrayPtr(w, self.Data, self.MaxLen, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the MaxLen value
	err = binary.Write(w, le, refId) // Referent ID
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++
	err = binary.Write(w, le, self.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the Actual length of transmitted data value
	err = binary.Write(w, le, refId) // Referent ID
	if err != nil {
		log.Errorln(err)
		return
	}

	refId++
	err = binary.Write(w, le, uint32(len(self.Data)))
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegQueryValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryValueReq")
}

func (self *BaseRegQueryValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryValueRes")
}

func (self *BaseRegQueryValueRes) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	// Read Type
	// Skip ReferentId
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read Data
	self.Data, _, err = readConformantVaryingArrayPtr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read DataLen
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.DataLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read MaxLen
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &self.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 20
func (self *BaseRegSaveKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegSaveKeyReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode the RRPUnicodeStr FileName
	err = writeRRPUnicodeStr(w, le, &self.FileName, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode SecurityAttributes
	err = writeRPCSecurityAttributes(w, le, self.SecurityAttributes, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegSaveKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSaveKeyReq")
}

// Opnum 21
func (self *BaseRegSetKeySecurityReq) MarshalBinary() (ret []byte, err error) {
	if len(self.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegSetKeySecurityReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.SecurityInformation)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode SecurityInformation
	err = writeRPCSecurityDescriptor(w, le, self.SecurityDescriptorIn, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BaseRegSetKeySecurityReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSetKeySecurityReq")
}

func writeRPCSecurityAttributes(w io.Writer, bo binary.ByteOrder, sa RpcSecurityAttributes, refId *uint32) (err error) {
	// Begins with a ReferentIdPtr
	err = binary.Write(w, bo, *refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	*refId++

	// Encode the actual SecurityDescriptor as self-relative as required for RPC
	// MS-DTYP section 2.4.6 states that this is always encoded as LittleEndian byte order.
	buf, err := sa.SecurityDescriptor.SecurityDescriptor.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	buflen := uint32(len(buf))

	// Encode Length
	if sa.Length < buflen {
		sa.Length = buflen
	}
	err = binary.Write(w, bo, sa.Length)
	if err != nil {
		log.Errorln(err)
		return
	}
	*refId++

	// Write RefIdPtr that is lifted out of the RpcSecurityDescriptor
	err = binary.Write(w, bo, *refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	*refId++

	// Encode InSecurityDescriptor
	err = binary.Write(w, bo, buflen)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode OutSecurityDescriptor
	err = binary.Write(w, bo, buflen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode InheritHandle
	// Note the intentional LittleEndian encoding to place the single byte value correctly
	err = binary.Write(w, le, uint32(sa.InheritHandle))
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the SecurityDescriptor
	_, err = writeConformantVaryingArray(w, buf, 0)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

// Do I need a readRPCSecurityDescriptor function?
func writeRPCSecurityDescriptor(w io.Writer, bo binary.ByteOrder, sd RpcSecurityDescriptor, refId *uint32) (err error) {
	if sd.SecurityDescriptor == nil {
		err = binary.Write(w, bo, uint32(0)) // Null ptr
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, bo, sd.InSecurityDescriptor)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Write(w, bo, sd.OutSecurityDescriptor)
		if err != nil {
			log.Errorln(err)
			return
		}
		return
	}

	// Allow skipping RefidPtr if it has been placed earlier in the octet stream
	if *refId != 0 {
		// Write ptr to SecurityDescriptor (RefId)
		err = binary.Write(w, bo, *refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		*refId++
	}

	// Encode the actual SecurityDescriptor as self-relative as required for RPC
	// MS-DTYP section 2.4.6 states that this is always encoded as LittleEndian byte order.
	buf, err := sd.SecurityDescriptor.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	// Sanity check
	buflen := uint32(len(buf))
	if sd.InSecurityDescriptor < buflen {
		sd.InSecurityDescriptor = buflen
	}
	err = binary.Write(w, bo, sd.InSecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode OutSecurityDescriptor
	err = binary.Write(w, bo, buflen)
	if err != nil {
		log.Errorln(err)
		return
	}

	//NOTE Might need to add support to skip padding if it becomes a problem
	_, err = writeConformantVaryingArray(w, buf, 0)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *RpcSecurityAttributes) MarshalBinary() (ret []byte, err error) {

	refId := uint32(1)
	w := bytes.NewBuffer(ret)
	err = writeRPCSecurityAttributes(w, le, *self, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (self *RpcSecurityAttributes) UnmarshalBinary(buf []byte) error {

	err := fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for RpcSecurityAttributes")
	return err
}

func (self *SecurityDescriptor) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	ptrBuf := make([]byte, 0)
	// Order: 1. SACL, 2. DACL, 3. Owner, 4. Group
	bufOffset := uint32(20)

	if self.Sacl != nil {
		sBuf, err := self.Sacl.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		ptrBuf = append(ptrBuf, sBuf...)
		self.Control |= SecurityDescriptorFlagSP
		self.OffsetSacl = bufOffset
		bufOffset += uint32(len(sBuf))
	}
	if self.Dacl != nil {
		dBuf, err := self.Dacl.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, dBuf...)
		self.Control |= SecurityDescriptorFlagDP
		self.OffsetDacl = bufOffset
		bufOffset += uint32(len(dBuf))
	}

	if self.OwnerSid != nil {
		oBuf, err := self.OwnerSid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, oBuf...)
		self.OffsetOwner = bufOffset
		bufOffset += uint32(len(oBuf))
	}

	if self.OffsetGroup != 0 {
		gBuf, err := self.GroupSid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, gBuf...)
		self.OffsetGroup = bufOffset
	}

	// Encode revision
	err = binary.Write(w, le, self.Revision)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode control
	err = binary.Write(w, le, self.Control)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode  OffsetOwner
	err = binary.Write(w, le, self.OffsetOwner)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode  OffsetGroup
	err = binary.Write(w, le, self.OffsetGroup)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode  OffsetSacl
	err = binary.Write(w, le, self.OffsetSacl)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode  OffsetDacl
	err = binary.Write(w, le, self.OffsetDacl)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode serialized Owner, Group, Sacl and Dacl
	_, err = w.Write(ptrBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *SecurityDescriptor) UnmarshalBinary(buf []byte) (err error) {

	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.Revision)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Control)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.OffsetOwner)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.OffsetGroup)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.OffsetSacl)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.OffsetDacl)
	if err != nil {
		log.Errorln(err)
		return
	}

	if self.OffsetOwner != 0 {
		_, err = r.Seek(int64(self.OffsetOwner), io.SeekStart)
		self.OwnerSid, err = readSID(r)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	if self.OffsetGroup != 0 {
		_, err = r.Seek(int64(self.OffsetGroup), io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.GroupSid, err = readSID(r)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if (self.Control & SecurityDescriptorFlagSP) == SecurityDescriptorFlagSP {
		_, err = r.Seek(int64(self.OffsetSacl), io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Sacl, err = readPACL(r)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if (self.Control & SecurityDescriptorFlagDP) == SecurityDescriptorFlagDP {
		_, err = r.Seek(int64(self.OffsetDacl), io.SeekStart)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Dacl, err = readPACL(r)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return nil
}

func (self *SID) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	// Encode ACE SID
	err = binary.Write(w, le, self.Revision)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, byte(len(self.SubAuthorities)))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Authority)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.SubAuthorities)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func readSID(r *bytes.Reader) (s *SID, err error) {
	s = &SID{}
	// Decode ACE SID
	err = binary.Read(r, le, &s.Revision)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.NumAuth)
	if err != nil {
		log.Errorln(err)
		return
	}

	s.Authority = make([]byte, 6)
	err = binary.Read(r, le, &s.Authority)
	if err != nil {
		log.Errorln(err)
		return
	}

	s.SubAuthorities = make([]uint32, s.NumAuth)
	for i := range s.SubAuthorities {
		err = binary.Read(r, le, &s.SubAuthorities[i])
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return
}

func (self *SID) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	sid, err := readSID(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	*self = *sid
	return nil
}

func (self *ACE) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.Header.Type)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Header.Flags)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Header.Size)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.Mask)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode ACE SID
	sidBuf, err := self.Sid.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	err = binary.Write(w, le, sidBuf)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func readACE(r *bytes.Reader) (a *ACE, err error) {
	a = &ACE{}
	err = binary.Read(r, le, &a.Header.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &a.Header.Flags)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &a.Header.Size)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &a.Mask)
	if err != nil {
		log.Errorln(err)
		return
	}

	sid, err := readSID(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	a.Sid = *sid

	return
}

func (self *ACE) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	ace, err := readACE(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	*self = *ace
	return nil
}

func (self *PACL) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, self.AclRevision)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.AclSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode AceCount at 4 byte boundary
	err = binary.Write(w, le, uint32(len(self.ACLS)))
	if err != nil {
		log.Errorln(err)
		return
	}

	for _, item := range self.ACLS {
		var aceBuf []byte
		aceBuf, err = item.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}
		_, err = w.Write(aceBuf)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func readPACL(r *bytes.Reader) (p *PACL, err error) {
	p = &PACL{}
	err = binary.Read(r, le, &p.AclRevision)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &p.AclSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &p.AceCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	p.ACLS = make([]ACE, p.AceCount)
	for i := range p.ACLS {
		var ace *ACE
		ace, err = readACE(r)
		if err != nil {
			log.Errorln(err)
			return
		}
		p.ACLS[i] = *ace
	}

	return
}

func (self *PACL) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	pacl, err := readPACL(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	*self = *pacl

	return nil
}
