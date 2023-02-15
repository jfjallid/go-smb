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

// Not sure if this is correct
//type PSID struct {
//    Revision            byte
//    SubAuthorityCount   byte `smb:"count:SubAuthority"`
//    IdentifierAuthority []byte `smb:"fixed:6"`
//    SubAuthority        []uint32
//}

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

// Share struct, not all fields are used for every response type
type KeyInfo struct {
	KeyName         []uint16
	ClassName       []uint16
	SubKeys         uint32
	MaxSubKeyLen    uint32
	MaxClassLen     uint32
	Values          uint32
	MaxValueNameLen uint32
	MaxValueLen     uint32
}

type ValueInfo struct {
	Name     []uint16
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

// Temp until all are migrated to this new structure. Then rename it back to PRRPUnicodeStr
type PRRPUnicodeStr2 struct {
	Length    uint16
	MaxLength uint16
	Buffer    []uint16
}

// Temp until all are migrated to this new structure. Then rename it back to RRPUnicodeStr
// The difference to PRRPUnicodeStr is that this one replaced empty keyNames with 4 null bytes, and PRRPUnicodeStr replaced a nil ptr with nothing.
type RRPUnicodeStr3 struct {
	Length    uint16
	MaxLength uint16
	Buffer    []uint16
}

type RpcSecurityAttributes struct {
	Length             uint32
	SecurityDescriptor RpcSecurityDescriptor
	InheritHandle      byte
}

type RpcSecurityDescriptor struct {
	SecurityDescriptor    SecurityDescriptor
	InSecurityDescriptor  uint32
	OutSecurityDescriptor uint32
}

// Opnum 9
type BaseRegEnumKeyReq struct {
	HKey          []byte
	Index         uint32
	NameIn        PRRPUnicodeStr2
	ClassIn       PRRPUnicodeStr2
	LastWriteTime *PFiletime
}

type BaseRegEnumKeyRes struct {
	NameOut       PRRPUnicodeStr2
	ClassOut      PRRPUnicodeStr2
	LastWriteTime PFiletime
	ReturnCode    uint32
}

// Opnum 10
type BaseRegEnumValueReq struct {
	HKey    []byte
	Index   uint32
	NameIn  PRRPUnicodeStr2
	Type    uint32
	Data    []byte
	MaxLen  uint32 // How many bytes are allocated .e.g., ActualSize or ActualCount
	DataLen uint32 // How many bytes are transmitted in Data. E.g., ActualSize
}

type BaseRegEnumValueRes struct {
	NameOut    PRRPUnicodeStr2
	Type       uint32
	Data       []byte
	DataLen    uint32
	MaxLen     uint32
	ReturnCode uint32
}

type SecurityData struct {
	Size            uint32
	Len             uint32
	KeySecurityData *SecurityDescriptor
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
type BaseRegGetKeySecurityReq struct {
	HKey                 []byte
	SecurityInformation  uint32
	SecurityDescriptorIn SecurityData // Size of a security descriptor. Data is irrelevant
}

type BaseRegGetKeySecurityRes struct {
	SecurityDescriptorOut SecurityData // Size of a security descriptor. Data is irrelevant
	ReturnCode
}

// Opnum 15
type BaseRegOpenKeyReq struct {
	HKey          []byte
	SubKey        PRRPUnicodeStr2
	Options       uint32
	DesiredAccess uint32 // REGSAM
}

// Opnum 16
type BaseRegQueryInfoKeyReq struct {
	HKey    []byte
	ClassIn RRPUnicodeStr3 // Optional, can be null
}

type BaseRegQueryInfoKeyRes struct {
	ClassOut           RRPUnicodeStr3
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
	ValueName PRRPUnicodeStr2
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
	FileName           PRRPUnicodeStr2
	SecurityAttributes RpcSecurityAttributes
}

// Opnum 21
type BaseRegSetKeySecurityReq struct {
	HKey                 []byte
	SecurityInformation  uint32
	SecurityDescriptorIn SecurityData
}

func (self *ReturnCode) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for ReturnCode")
}

func (self *ReturnCode) UnmarshalBinary(buf []byte) error {
	// Read ReturnCode
	self.uint32 = le.Uint32(buf)
	return nil
}

// Opnums 0-4
func (self *OpenRootKeyReq) MarshalBinary() ([]byte, error) {
	ret := make([]byte, 8)
	le.PutUint32(ret, self.ServerName)
	le.PutUint32(ret[4:], self.DesiredAccess)
	return ret, nil
}

func (self *OpenRootKeyReq) UnmarshalBinary(buf []byte) error {
	self.ServerName = le.Uint32(buf[0:])
	self.DesiredAccess = le.Uint32(buf[4:])
	return nil
}

func (self *OpenKeyRes) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey)
	binary.Write(w, le, self.ReturnCode)
	return w.Bytes(), nil
}

func (self *OpenKeyRes) UnmarshalBinary(buf []byte) error {
	self.HKey = make([]byte, 20)
	copy(self.HKey, buf[0:20])
	self.ReturnCode = le.Uint32(buf[20:])
	return nil
}

// Opnum 5
func (self *BaseRegCloseKeyReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey)
	return w.Bytes(), nil
}

func (self *BaseRegCloseKeyReq) UnmarshalBinary(buf []byte) error {
	self.HKey = make([]byte, 20)
	copy(self.HKey, buf[0:20])
	return nil
}

// Opnum 9
func (self *BaseRegEnumKeyReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	binary.Write(w, le, self.Index)

	// Encode the PRRPUnicodeStr2 NameIn
	binary.Write(w, le, self.NameIn.Length*2)
	binary.Write(w, le, self.NameIn.MaxLength*2)
	binary.Write(w, le, [4]byte{1}) // Referent ID
	binary.Write(w, le, uint32(self.NameIn.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.NameIn.Length))
	binary.Write(w, le, self.NameIn.Buffer)
	// Encode the PRRPUnicodeStr2 ClassIn
	binary.Write(w, le, [4]byte{2}) // Extra Referent ID
	binary.Write(w, le, self.ClassIn.Length*2)
	binary.Write(w, le, self.ClassIn.MaxLength*2)
	binary.Write(w, le, [4]byte{3}) // Referent ID
	binary.Write(w, le, uint32(self.ClassIn.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.ClassIn.Length))
	binary.Write(w, le, self.ClassIn.Buffer)
	// Encode LastWriteTime
	binary.Write(w, le, [4]byte{4}) // Referent ID
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

func (self *BaseRegEnumKeyRes) UnmarshalBinary(buf []byte) error {
	self.NameOut.Length = le.Uint16(buf)
	self.NameOut.MaxLength = le.Uint16(buf[2:])

	nameLen := int(self.NameOut.Length / 2)
	// Skipping past 16 bytes of metadata for representing a string
	offset := 20
	for i := 0; i < nameLen; i++ {
		self.NameOut.Buffer = append(self.NameOut.Buffer, le.Uint16(buf[offset+i*2:offset+(i+1)*2]))
	}
	offset += nameLen * 2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	offset += 4 // Skip nested Referent Id

	self.ClassOut.Length = le.Uint16(buf[offset:])
	self.ClassOut.MaxLength = le.Uint16(buf[offset+2:])
	classLen := int(self.ClassOut.Length / 2)
	// Skipping past 16 bytes of metadata for representing a string
	offset += 20
	for i := 0; i < classLen; i++ {
		self.ClassOut.Buffer = append(self.ClassOut.Buffer, le.Uint16(buf[offset+i*2:offset+(i+1)*2]))
	}
	offset += classLen * 2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align = offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	offset += 4 // Skip Referent Id
	self.LastWriteTime.LowDateTime = le.Uint32(buf[offset:])
	self.LastWriteTime.HighDateTime = le.Uint32(buf[offset+4:])
	self.ReturnCode = le.Uint32(buf[offset+8:])

	return nil
}

// Opnum 10
func (self *BaseRegEnumValueReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	binary.Write(w, le, self.Index)

	offset := 24 // Use to keep track of alignment

	// Encode the PRRPUnicodeStr2 NameIn
	binary.Write(w, le, self.NameIn.Length*2)
	binary.Write(w, le, self.NameIn.MaxLength*2)
	binary.Write(w, le, [4]byte{1}) // Referent ID
	binary.Write(w, le, uint32(self.NameIn.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.NameIn.Length))
	binary.Write(w, le, self.NameIn.Buffer)
	offset += 20 + len(self.NameIn.Buffer)

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
		binary.Write(w, le, make([]byte, align))
	}
	offset += align

	// Encode Type
	binary.Write(w, le, [4]byte{2}) // Referent ID
	binary.Write(w, le, self.Type)

	// Encode the value []uint16
	binary.Write(w, le, [4]byte{1})             // Extra Referent ID
	binary.Write(w, le, self.MaxLen)            // Not sure this is correct, but have to encode max size of this value
	binary.Write(w, le, uint32(0))              // Offset
	binary.Write(w, le, uint32(len(self.Data))) // Not sure this is correct, but have to encode actual size of this value
	offset += 20 + len(self.Data)

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align = offset % 4
	if align != 0 {
		align = 4 - align
		binary.Write(w, le, make([]byte, align))
	}
	offset += align

	// Encode the MaxLen value
	binary.Write(w, le, [4]byte{4}) // Referent ID
	binary.Write(w, le, self.MaxLen)

	// Encode the Actual length of transmitted data value
	binary.Write(w, le, [4]byte{3})               // Referent ID
	binary.Write(w, le, uint32(len(self.Data)/2)) // []uint16 not []byte

	return w.Bytes(), nil
}

func (self *BaseRegEnumValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegEnumValueReq")
}

func (self *BaseRegEnumValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegEnumKeyRes")
}

func (self *BaseRegEnumValueRes) UnmarshalBinary(buf []byte) error {
	self.NameOut.Length = le.Uint16(buf)
	self.NameOut.MaxLength = le.Uint16(buf[2:])

	nameLen := int(self.NameOut.Length / 2)
	// Skipping past 16 bytes of metadata for representing a string
	offset := 20
	for i := 0; i < nameLen; i++ {
		self.NameOut.Buffer = append(self.NameOut.Buffer, le.Uint16(buf[offset+i*2:offset+(i+1)*2]))
	}
	offset += nameLen * 2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	// Read Type
	self.Type = le.Uint32(buf[offset+4:]) // Skip nested Referent Id
	offset += 8

	// Read Data
	//self.Data
	offset += 12 // Skip metadata
	actualCount := int(le.Uint32(buf[offset:]))
	self.Data = make([]byte, actualCount)
	copy(self.Data, buf[offset+4:offset+4+actualCount])
	offset += 4 + actualCount

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align = offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	// Read DataLen
	self.DataLen = le.Uint32(buf[offset+4:]) // Skip Referent Id
	offset += 8

	// Read MaxLen
	self.MaxLen = le.Uint32(buf[offset+4:]) // Skip Referent Id
	offset += 8

	// Read ReturnCode
	self.ReturnCode = le.Uint32(buf[offset:])

	return nil
}

// Opnum 10
func (self *BaseRegGetKeySecurityReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	binary.Write(w, le, self.SecurityInformation)

	//offset := 24 // Use to keep track of alignment

	// Encode SecurityInformation
	if self.SecurityDescriptorIn.KeySecurityData == nil {
		binary.Write(w, le, uint32(0))
	} else {
		return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary with non-nil SecurityDescriptor")
	}

	binary.Write(w, le, self.SecurityDescriptorIn.Size)
	binary.Write(w, le, self.SecurityDescriptorIn.Len)

	return w.Bytes(), nil
}

func (self *BaseRegGetKeySecurityReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegGetKeySecurityReq")
}

func (self *BaseRegGetKeySecurityRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegGetKeySecurityRes")
}

func (self *BaseRegGetKeySecurityRes) UnmarshalBinary(buf []byte) error {
	// Read SecurityDescriptorOut
	offset := 4                                                // Skip Referent Id
	self.SecurityDescriptorOut.Size = le.Uint32(buf[offset:])  // Max Size
	self.SecurityDescriptorOut.Len = le.Uint32(buf[offset+4:]) // Actual Len
	offset += 8

	offset += 12 // Skip metadata
	// Read 100 bytes or actual size, then call unmarshal again? for the Security Descriptor which perhaps deserves its own marshal/unmarshal functions
	sd := SecurityDescriptor{}
	err := sd.UnmarshalBinary(buf[offset : offset+int(self.SecurityDescriptorOut.Len)])
	if err != nil {
		return err
	}

	self.SecurityDescriptorOut.KeySecurityData = &sd
	offset += int(self.SecurityDescriptorOut.Len)

	// Read ReturnCode
	self.ReturnCode.uint32 = le.Uint32(buf[offset:])

	return nil
}

// Opnum 15
func (self *BaseRegOpenKeyReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	offset := 20

	// Encode the PRRPUnicodeStr2 SubKey
	binary.Write(w, le, self.SubKey.Length*2)
	binary.Write(w, le, self.SubKey.MaxLength*2)
	binary.Write(w, le, [4]byte{1}) // Referent ID
	binary.Write(w, le, uint32(self.SubKey.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.SubKey.Length))
	binary.Write(w, le, self.SubKey.Buffer)

	offset += 20 + len(self.SubKey.Buffer)*2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align
	binary.Write(w, le, make([]byte, align)) // Add padding bytes for alignment

	binary.Write(w, le, self.Options)
	binary.Write(w, le, self.DesiredAccess)

	return w.Bytes(), nil
}

func (self *BaseRegOpenKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegOpenKeyReq")
}

// Opnum 16
func (self *BaseRegQueryInfoKeyReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])

	// Encode the PRRPUnicodeStr3 SubKey
	binary.Write(w, le, self.ClassIn.Length)
	binary.Write(w, le, self.ClassIn.MaxLength)
	if len(self.ClassIn.Buffer) > 0 {
		binary.Write(w, le, self.ClassIn.Buffer)
	} else {
		binary.Write(w, le, [4]byte{0})
	}

	return w.Bytes(), nil
}

func (self *BaseRegQueryInfoKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryInfoKeyReq")
}

func (self *BaseRegQueryInfoKeyRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryInfoKeyRes")
}

func (self *BaseRegQueryInfoKeyRes) UnmarshalBinary(buf []byte) error {
	offset := 0
	// Read ClassOut
	self.ClassOut.Length = le.Uint16(buf[offset:])      // Actual Len
	self.ClassOut.MaxLength = le.Uint16(buf[offset+2:]) // Max Size
	offset += 4
	offset += 16 // Skip metadata
	buffLen := int(self.ClassOut.Length / 2)
	self.ClassOut.Buffer = make([]uint16, buffLen)
	for i := 0; i < buffLen; i++ {
		self.ClassOut.Buffer[i] = le.Uint16(buf[offset+i*2 : offset+(i+1)*2])
	}
	offset += buffLen * 2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	self.SubKeys = le.Uint32(buf[offset:])
	offset += 4

	self.MaxSubKeyLen = le.Uint32(buf[offset:])
	offset += 4

	self.MaxClassLen = le.Uint32(buf[offset:])
	offset += 4

	self.Values = le.Uint32(buf[offset:])
	offset += 4

	self.MaxValueNameLen = le.Uint32(buf[offset:])
	offset += 4

	self.MaxValueLen = le.Uint32(buf[offset:])
	offset += 4

	self.SecurityDescriptor = le.Uint32(buf[offset:])
	offset += 4

	// Read LastWriteTime
	self.LastWriteTime.LowDateTime = le.Uint32(buf[offset:])
	self.LastWriteTime.HighDateTime = le.Uint32(buf[offset+4:])

	// Read ReturnCode
	self.ReturnCode = le.Uint32(buf[offset+8:])

	return nil
}

// Opnum 17
func (self *BaseRegQueryValueReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	offset := 20

	// Encode the PRRPUnicodeStr2 ValueName
	binary.Write(w, le, self.ValueName.Length*2)
	binary.Write(w, le, self.ValueName.MaxLength*2)
	binary.Write(w, le, [4]byte{1}) // Referent Id
	binary.Write(w, le, uint32(self.ValueName.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.ValueName.Length))
	binary.Write(w, le, self.ValueName.Buffer)

	offset += 20 + len(self.ValueName.Buffer)*2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align
	binary.Write(w, le, make([]byte, align)) // Add padding bytes for alignment

	// Encoder Type
	binary.Write(w, le, [4]byte{2}) // Referent Id
	binary.Write(w, le, self.Type)
	offset += 8

	// Encode Data
	binary.Write(w, le, [4]byte{1})             // Referent Id
	binary.Write(w, le, self.MaxLen)            // Max count
	binary.Write(w, le, uint32(0))              // Offset
	binary.Write(w, le, uint32(len(self.Data))) // Actual count
	binary.Write(w, le, self.Data)
	offset += 16 + len(self.Data)

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align = offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align
	binary.Write(w, le, make([]byte, align)) // Add padding bytes for alignment

	binary.Write(w, le, [4]byte{3})  // Referent Id
	binary.Write(w, le, self.MaxLen) // Max count

	binary.Write(w, le, [4]byte{4})             // Referent Id
	binary.Write(w, le, uint32(len(self.Data))) // Actual count

	return w.Bytes(), nil
}

func (self *BaseRegQueryValueReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegQueryValueReq")
}

func (self *BaseRegQueryValueRes) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BaseRegQueryValueRes")
}

func (self *BaseRegQueryValueRes) UnmarshalBinary(buf []byte) error {
	offset := 0
	// Read Type
	self.Type = le.Uint32(buf[offset+4:]) // Skip Referent Id
	offset += 8

	// Read Data
	offset += 16 // Skip metadata
	datalen := int(le.Uint32(buf[offset-4:]))
	self.Data = make([]byte, datalen)
	copy(self.Data, buf[offset:offset+datalen])
	offset += datalen

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align

	// Read DataLen
	self.DataLen = le.Uint32(buf[offset+4:]) // Skip nested Referent Id
	offset += 8

	// Read MaxLen
	self.MaxLen = le.Uint32(buf[offset+4:]) // Skip nested Referent Id
	offset += 8

	// Read ReturnCode
	self.ReturnCode = le.Uint32(buf[offset:])

	return nil
}

// Opnum 20
func (self *BaseRegSaveKeyReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	offset := 20

	// Encode the PRRPUnicodeStr2 FileName
	binary.Write(w, le, self.FileName.Length*2)
	binary.Write(w, le, self.FileName.MaxLength*2)
	binary.Write(w, le, [4]byte{1}) // Referent ID
	binary.Write(w, le, uint32(self.FileName.MaxLength))
	binary.Write(w, le, uint32(0)) // Offset
	binary.Write(w, le, uint32(self.FileName.Length))
	binary.Write(w, le, self.FileName.Buffer)

	offset += 20 + len(self.FileName.Buffer)*2

	// Next element has to begin at proper alignment for its size
	// In this case, 4 byte boundary
	align := offset % 4
	if align != 0 {
		align = 4 - align
	}
	offset += align
	binary.Write(w, le, make([]byte, align)) // Add padding bytes for alignment

	// Encode SecurityAttributes
	sa, err := self.SecurityAttributes.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.Write(w, le, sa)

	return w.Bytes(), nil
}

func (self *BaseRegSaveKeyReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSaveKeyReq")
}

// Opnum 21
func (self *BaseRegSetKeySecurityReq) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	binary.Write(w, le, self.HKey[:20])
	binary.Write(w, le, self.SecurityInformation)

	// Encode SecurityInformation
	if self.SecurityDescriptorIn.KeySecurityData == nil {
		return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary with nil SecurityDescriptor")
	}

	binary.Write(w, le, [4]byte{0x01})                  // Referent Id
	binary.Write(w, le, self.SecurityDescriptorIn.Size) // Max Size
	binary.Write(w, le, self.SecurityDescriptorIn.Len)  // Actual Len

	binary.Write(w, le, self.SecurityDescriptorIn.Size) // Max Size
	binary.Write(w, le, uint32(0))                      // Offset
	binary.Write(w, le, self.SecurityDescriptorIn.Len)  // Actual len

	sdbuf, err := self.SecurityDescriptorIn.KeySecurityData.MarshalBinary()
	if err != nil {
		return nil, err
	}
	binary.Write(w, le, sdbuf)

	return w.Bytes(), nil
}

func (self *BaseRegSetKeySecurityReq) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for BaseRegSetKeySecurityReq")
}

func (self *RpcSecurityAttributes) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 24)
	referentId := uint32(0x1)
	referentId2 := uint32(0x2)
	// Begins with a ReferentIdPtr
	buf = binary.LittleEndian.AppendUint32(buf, referentId)
	buf = binary.LittleEndian.AppendUint32(buf, self.Length)
	// Lift out inner ReferentIdPtr
	buf = binary.LittleEndian.AppendUint32(buf, referentId2)
	buf = binary.LittleEndian.AppendUint32(buf, self.SecurityDescriptor.InSecurityDescriptor)
	buf = binary.LittleEndian.AppendUint32(buf, self.SecurityDescriptor.OutSecurityDescriptor)
	buf = append(buf, self.InheritHandle)
	buf = append(buf, []byte{0, 0, 0}...) // fixed size alignment

	sdBuf, err := self.SecurityDescriptor.SecurityDescriptor.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(sdBuf)))
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(sdBuf)))
	buf = append(buf, sdBuf...)

	return buf, nil
}

func (self *RpcSecurityAttributes) UnmarshalBinary(buf []byte) error {

	err := fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for RpcSecurityAttributes")
	return err
}

func (self *SecurityDescriptor) MarshalBinary() ([]byte, error) {
	ptrBuf := make([]byte, 0)
	// Order: 1. SACL, 2. DACL, 3. Owner, 4. Group
	bufOffset := uint32(20)
	if self.Sacl != nil {
		sBuf, err := self.Sacl.MarshalBinary()
		if err != nil {
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

	buf := make([]byte, 0, 20+len(ptrBuf))
	buf = binary.LittleEndian.AppendUint16(buf, self.Revision)
	buf = binary.LittleEndian.AppendUint16(buf, self.Control)
	buf = binary.LittleEndian.AppendUint32(buf, self.OffsetOwner)
	buf = binary.LittleEndian.AppendUint32(buf, self.OffsetGroup)
	buf = binary.LittleEndian.AppendUint32(buf, self.OffsetSacl)
	buf = binary.LittleEndian.AppendUint32(buf, self.OffsetDacl)
	buf = append(buf, ptrBuf...)

	return buf, nil
}

func (self *SecurityDescriptor) UnmarshalBinary(buf []byte) error {

	self.Revision = binary.LittleEndian.Uint16(buf)
	self.Control = binary.LittleEndian.Uint16(buf[2:])
	self.OffsetOwner = binary.LittleEndian.Uint32(buf[4:])
	self.OffsetGroup = binary.LittleEndian.Uint32(buf[8:])
	self.OffsetSacl = binary.LittleEndian.Uint32(buf[12:])
	self.OffsetDacl = binary.LittleEndian.Uint32(buf[16:])

	if self.OffsetOwner != 0 {
		oSid := SID{}
		err := oSid.UnmarshalBinary(buf[self.OffsetOwner:])
		if err != nil {
			return err
		}
		self.OwnerSid = &oSid
	}
	if self.OffsetGroup != 0 {
		gSid := SID{}
		err := gSid.UnmarshalBinary(buf[self.OffsetGroup:])
		if err != nil {
			return err
		}
		self.GroupSid = &gSid
	}
	if (self.Control & SecurityDescriptorFlagSP) == SecurityDescriptorFlagSP {
		sacl := PACL{}
		err := sacl.UnmarshalBinary(buf[self.OffsetSacl:])
		if err != nil {
			return err
		}
		self.Sacl = &sacl
	}
	if (self.Control & SecurityDescriptorFlagDP) == SecurityDescriptorFlagDP {
		dacl := PACL{
			ACLS: []ACE{},
		}
		err := dacl.UnmarshalBinary(buf[self.OffsetDacl:])
		if err != nil {
			return err
		}
		self.Dacl = &dacl
	}

	return nil
}

func (self *PACL) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)

	binary.Write(w, le, self.AclRevision)
	binary.Write(w, le, self.AclSize)

	// Encode AceCount at 4 byte boundary
	binary.Write(w, le, uint32(len(self.ACLS)))

	for _, item := range self.ACLS {
		// Encoder ACE Header
		binary.Write(w, le, item.Header.Type)
		binary.Write(w, le, item.Header.Flags)
		binary.Write(w, le, item.Header.Size)

		// Encoder ACE Mask
		binary.Write(w, le, item.Mask) // Write at 4 byte boundary

		// Encoder ACE SID
		sidBuf, err := item.Sid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		binary.Write(w, le, sidBuf)
	}

	return w.Bytes(), nil
}

func (self *PACL) UnmarshalBinary(buf []byte) error {
	offset := 0
	self.AclRevision = le.Uint16(buf[offset:])
	self.AclSize = le.Uint16(buf[offset+2:])
	self.AceCount = le.Uint32(buf[offset+4:])
	offset += 8

	slice := []ACE{}
	for i := 0; i < int(self.AceCount); i++ {
		var item ACE
		// Decode ACE Header
		item.Header.Type = buf[offset]
		item.Header.Flags = buf[offset+1]
		item.Header.Size = le.Uint16(buf[offset+2:])
		offset += 4

		// Decode ACE Mask
		item.Mask = le.Uint32(buf[offset:])
		offset += 4

		// Decode ACE SID
		err := item.Sid.UnmarshalBinary(buf[offset:])
		if err != nil {
			return err
		}
		offset += 8
		offset += int(item.Sid.NumAuth) * 4

		slice = append(slice, item)
	}

	self.ACLS = slice

	return nil
}

func (self *SID) MarshalBinary() ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)

	// Encode ACE SID
	binary.Write(w, le, self.Revision)
	binary.Write(w, le, byte(len(self.SubAuthorities)))
	binary.Write(w, le, self.Authority)
	binary.Write(w, le, self.SubAuthorities)

	return w.Bytes(), nil
}

func (self *SID) UnmarshalBinary(buf []byte) error {
	offset := 0

	// Decode ACE SID
	self.Revision = buf[offset]
	self.NumAuth = buf[offset+1]
	offset += 2

	self.Authority = make([]byte, 6)
	copy(self.Authority, buf[offset:offset+6])
	offset += 6
	self.SubAuthorities = make([]uint32, 0)

	for j := 0; j < int(self.NumAuth); j++ {
		self.SubAuthorities = append(self.SubAuthorities, le.Uint32(buf[offset:]))
		offset += 4
	}

	return nil
}
