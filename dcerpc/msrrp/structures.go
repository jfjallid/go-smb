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

	"github.com/jfjallid/go-smb/msdtyp"
)

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

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
	TypeName string
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
	SecurityDescriptor    *msdtyp.SecurityDescriptor
	InSecurityDescriptor  uint32 // The "Max Size" to tell the server how much space we've allocated
	OutSecurityDescriptor uint32 // The length of the transmitted security descriptor
}

// Opnum 6
type BaseRegCreateKeyReq struct {
	HKey          []byte
	SubKey        RRPUnicodeStr
	Class         RRPUnicodeStr
	Options       uint32
	DesiredAccess uint32
	SecurityAttr  *RpcSecurityAttributes
	Disposition   uint32
}

// Opnum 6
type BaseRegCreateKeyRes struct {
	HKey        []byte
	Disposition uint32
	ReturnCode  uint32
}

// Opnum 7
type BaseRegDeleteKeyReq struct {
	HKey   []byte
	SubKey RRPUnicodeStr
}

// Opnum 8
type BaseRegDeleteValueReq struct {
	HKey      []byte
	ValueName RRPUnicodeStr
}

// Opnum 9
type BaseRegEnumKeyReq struct {
	HKey          []byte
	Index         uint32
	NameIn        RRPUnicodeStr
	ClassIn       RRPUnicodeStr
	LastWriteTime *msdtyp.PFiletime
}

type BaseRegEnumKeyRes struct {
	NameOut       RRPUnicodeStr
	ClassOut      RRPUnicodeStr
	LastWriteTime msdtyp.PFiletime
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
	NameOut    msdtyp.RPCUnicodeStr // Cannot be null terminated?
	Type       uint32
	Data       []byte
	DataLen    uint32
	MaxLen     uint32
	ReturnCode uint32
}

// Opnum 12
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
	ClassOut           msdtyp.RPCUnicodeStr
	SubKeys            uint32
	MaxSubKeyLen       uint32
	MaxClassLen        uint32
	Values             uint32
	MaxValueNameLen    uint32
	MaxValueLen        uint32
	SecurityDescriptor uint32
	LastWriteTime      msdtyp.Filetime
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

// Opnum 22
type BaseRegSetValueReq struct {
	HKey      []byte
	ValueName RRPUnicodeStr
	Type      uint32
	Data      []byte
	DataLen   uint32 // How many bytes are transmitted in Data. E.g., ActualSize
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
		us.S = msdtyp.NullTerminate(us.S)
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

func (s *RRPUnicodeStr) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	refId := uint32(1)
	err = writeRRPUnicodeStr(w, le, s, &refId, false)
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

	s = msdtyp.StripNullByte(s) // Skip terminating null character
	return
}

func (s *RRPUnicodeStr) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		return fmt.Errorf("Buffer too small for RRPUnicodeStr!")
	}
	r := bytes.NewReader(buf)
	s.S, s.MaxLength, err = readRRPUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

// Opnums 0-4
func (s *OpenRootKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.ServerName)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *OpenRootKeyReq) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &s.ServerName)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

func (s *OpenKeyRes) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in OpenKeyRes")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (s *OpenKeyRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		err = fmt.Errorf("Buffer too short to unmarshal OpenKeyRes")
		log.Errorln(err)
		return
	}
	r := bytes.NewReader(buf)
	s.HKey = make([]byte, 20)
	err = binary.Read(r, le, &s.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

// Opnum 5
func (s *BaseRegCloseKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegCloseKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (s *BaseRegCloseKeyReq) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 20 {
		err = fmt.Errorf("Buffer too short to unmarshal BaseRegCloseKeyReq")
		log.Errorln(err)
		return
	}
	r := bytes.NewReader(buf)
	s.HKey = make([]byte, 20)
	err = binary.Read(r, le, &s.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

func (s *BaseRegCreateKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegCreateKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)

	// Encode the RRPUnicodeStr SubKey
	err = writeRRPUnicodeStr(w, le, &s.SubKey, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode the RRPUnicodeStr Class
	err = writeRRPUnicodeStr(w, le, &s.Class, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.Options)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.SecurityAttr == nil {
		err = binary.Write(w, le, uint32(0))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		err = writeRPCSecurityAttributes(w, le, *s.SecurityAttr, &refId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if s.Disposition != 0 {
		err = binary.Write(w, le, refId)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	err = binary.Write(w, le, s.Disposition)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (s *BaseRegCreateKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegCreateKeyReq")
}

func (s *BaseRegCreateKeyRes) MarshalBinary() (ret []byte, err error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegCreateKeyReq")
}

func (s *BaseRegCreateKeyRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 28 {
		err = fmt.Errorf("Buffer too short to unmarshal BaseRegCreateKeyRes")
		log.Errorln(err)
		return
	}
	r := bytes.NewReader(buf)
	s.HKey = make([]byte, 20)
	err = binary.Read(r, le, &s.HKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Disposition)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

func (s *BaseRegDeleteKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegDeleteKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)

	// Encode the RRPUnicodeStr SubKey
	err = writeRRPUnicodeStr(w, le, &s.SubKey, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegDeleteKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegDeleteKeyReq")
}

func (s *BaseRegDeleteValueReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegDeleteValueReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)

	// Encode the RRPUnicodeStr ValueName
	err = writeRRPUnicodeStr(w, le, &s.ValueName, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegDeleteValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegDeleteValueReq")
}

// Opnum 9
func (s *BaseRegEnumKeyReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegEnumKeyReq")
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.Index)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)

	// Encode the RRPUnicodeStr NameIn
	err = writeRRPUnicodeStr(w, le, &s.NameIn, &refId, false)
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
	err = writeRRPUnicodeStr(w, le, &s.ClassIn, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode LastWriteTime
	binary.Write(w, le, refId) // Referent ID
	binary.Write(w, le, s.LastWriteTime.LowDateTime)
	binary.Write(w, le, s.LastWriteTime.HighDateTime)

	return w.Bytes(), nil
}

func (s *BaseRegEnumKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegEnumKeyReq")
}

func (s *BaseRegEnumKeyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegEnumKeyRes")
}

func (s *BaseRegEnumKeyRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 36 {
		return fmt.Errorf("Buffer too short for BaseRegEnumKeyRes")
	}

	r := bytes.NewReader(buf)

	s.NameOut.S, s.NameOut.MaxLength, err = readRRPUnicodeStr(r)
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

	s.ClassOut.S, s.ClassOut.MaxLength, err = readRRPUnicodeStr(r)
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

	err = binary.Read(r, le, &s.LastWriteTime.LowDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.LastWriteTime.HighDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 10
func (s *BaseRegEnumValueReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegEnumValueReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.Index)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode ValueNameIn
	err = writeRRPUnicodeStr(w, le, &s.NameIn, &refId, false)
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
	err = binary.Write(w, le, s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Data
	_, err = msdtyp.WriteConformantVaryingArrayPtr(w, s.Data, s.MaxLen, &refId)
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
	err = binary.Write(w, le, s.MaxLen)
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
	err = binary.Write(w, le, uint32(len(s.Data)))
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegEnumValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegEnumValueReq")
}

func (s *BaseRegEnumValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegEnumValueRes")
}

func (s *BaseRegEnumValueRes) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 36 {
		return fmt.Errorf("Buffer to short for BaseRegEnumValueRes")
	}
	r := bytes.NewReader(buf)

	// Read RPCUnicodeStr
	s.NameOut.S, s.NameOut.MaxLength, err = readRPCUnicodeStr(r)
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
	err = binary.Read(r, le, &s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read Data
	s.Data, _, err = msdtyp.ReadConformantVaryingArrayPtr(r)
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

	err = binary.Read(r, le, &s.DataLen)
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

	err = binary.Read(r, le, &s.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

// Opnum 10
func (s *BaseRegGetKeySecurityReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegGetKeySecurityReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.SecurityInformation)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	err = writeRPCSecurityDescriptor(w, le, s.SecurityDescriptorIn, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegGetKeySecurityReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegGetKeySecurityReq")
}

func (s *BaseRegGetKeySecurityRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegGetKeySecurityRes")
}

func (s *BaseRegGetKeySecurityRes) UnmarshalBinary(buf []byte) (err error) {
	// Read SecurityDescriptorOut
	if len(buf) < 16 {
		return fmt.Errorf("Buffer to short for BaseRegGetKeySecurityRes")
	}
	r := bytes.NewReader(buf)

	// First read ReturnCode
	_, err = r.Seek(-4, io.SeekEnd)
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}
	if s.ReturnCode != 0 {
		return
	}

	// Skip ReferentId ptr
	_, err = r.Seek(4, io.SeekStart)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read max size of SecurityDescriptor
	err = binary.Read(r, le, &s.SecurityDescriptorOut.InSecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read actual size of SecurityDescriptor
	err = binary.Read(r, le, &s.SecurityDescriptorOut.OutSecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	data, _, err := msdtyp.ReadConformantVaryingArray(r)
	if err != nil {
		log.Errorln(err)
		return
	}
	sd := msdtyp.SecurityDescriptor{}
	err = sd.UnmarshalBinary(data)
	if err != nil {
		log.Errorln(err)
		return
	}
	s.SecurityDescriptorOut.SecurityDescriptor = &sd

	return nil
}

// Opnum 15
func (s *BaseRegOpenKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegOpenKeyReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode SubKey
	err = writeRRPUnicodeStr(w, le, &s.SubKey, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.Options)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.DesiredAccess)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegOpenKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegOpenKeyReq")
}

// Opnum 16
func (s *BaseRegQueryInfoKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegQueryInfoKey")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	err = writeRRPUnicodeStr(w, le, &s.ClassIn, &refId, true)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegQueryInfoKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryInfoKeyReq")
}

func (s *BaseRegQueryInfoKeyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryInfoKeyRes")
}

func (s *BaseRegQueryInfoKeyRes) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	// Read ClassOut
	s.ClassOut.S, s.ClassOut.MaxLength, err = readRPCUnicodeStr(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.SubKeys)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.MaxSubKeyLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.MaxClassLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.Values)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.MaxValueNameLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.MaxValueLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &s.SecurityDescriptor)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read LastWriteTime
	err = binary.Read(r, le, &s.LastWriteTime.LowDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.LastWriteTime.HighDateTime)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 17
func (s *BaseRegQueryValueReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegQueryValueReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode the RRPUnicodeStr ValueName
	err = writeRRPUnicodeStr(w, le, &s.ValueName, &refId, false)
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
	err = binary.Write(w, le, s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Data
	_, err = msdtyp.WriteConformantVaryingArrayPtr(w, s.Data, s.MaxLen, &refId)
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
	err = binary.Write(w, le, s.MaxLen)
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
	err = binary.Write(w, le, uint32(len(s.Data)))
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegQueryValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryValueReq")
}

func (s *BaseRegQueryValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryValueRes")
}

func (s *BaseRegQueryValueRes) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	// Read Type
	// Skip ReferentId
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read Data
	s.Data, _, err = msdtyp.ReadConformantVaryingArrayPtr(r)
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
	err = binary.Read(r, le, &s.DataLen)
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
	err = binary.Read(r, le, &s.MaxLen)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Read ReturnCode
	err = binary.Read(r, le, &s.ReturnCode)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}

// Opnum 20
func (s *BaseRegSaveKeyReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegSaveKeyReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode the RRPUnicodeStr FileName
	err = writeRRPUnicodeStr(w, le, &s.FileName, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode SecurityAttributes
	err = writeRPCSecurityAttributes(w, le, s.SecurityAttributes, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegSaveKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSaveKeyReq")
}

// Opnum 21
func (s *BaseRegSetKeySecurityReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegSetKeySecurityReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.SecurityInformation)
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode SecurityInformation
	err = writeRPCSecurityDescriptor(w, le, s.SecurityDescriptorIn, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegSetKeySecurityReq) UnmarshalBinary(buf []byte) error {
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
	_, err = msdtyp.WriteConformantVaryingArray(w, buf, 0)
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
	_, err = msdtyp.WriteConformantVaryingArray(w, buf, 0)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (s *RpcSecurityAttributes) MarshalBinary() (ret []byte, err error) {

	refId := uint32(1)
	w := bytes.NewBuffer(ret)
	err = writeRPCSecurityAttributes(w, le, *s, &refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (s *RpcSecurityAttributes) UnmarshalBinary(buf []byte) error {

	err := fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for RpcSecurityAttributes")
	return err
}

func (s *BaseRegSetValueReq) MarshalBinary() (ret []byte, err error) {
	if len(s.HKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in BaseRegSetValueReq")
		log.Errorln(err)
		return
	}
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.HKey[:20])
	if err != nil {
		log.Errorln(err)
		return
	}

	refId := uint32(1)
	// Encode the RRPUnicodeStr ValueName
	err = writeRRPUnicodeStr(w, le, &s.ValueName, &refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Type
	err = binary.Write(w, le, s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode Data
	_, err = msdtyp.WriteConformantArray(w, s.Data)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the Actual length of transmitted data value
	err = binary.Write(w, le, uint32(len(s.Data)))
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *BaseRegSetValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSetValueReq")
}
