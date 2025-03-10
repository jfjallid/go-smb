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
package msdtyp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/jfjallid/golog"
	"io"
)

var (
	le  = binary.LittleEndian
	be  = binary.BigEndian
	log = golog.Get("github.com/jfjallid/go-smb/msdtyp")
)

// MS-DTYP Section 2.4.6 Security_Descriptor Control Flag
const (
	SecurityDescriptorFlagOD uint16 = 0x0001 // Owner Default
	SecurityDescriptorFlagGD uint16 = 0x0002 // Group Default
	SecurityDescriptorFlagDP uint16 = 0x0004 // DACL Present
	SecurityDescriptorFlagDD uint16 = 0x0008 // DACL Defaulted
	SecurityDescriptorFlagSP uint16 = 0x0010 // SACL Present
	SecurityDescriptorFlagSD uint16 = 0x0020 // SACL Defaulted
	SecurityDescriptorFlagDT uint16 = 0x0040 // DACL Trusted
	SecurityDescriptorFlagSS uint16 = 0x0080 // Server Security
	SecurityDescriptorFlagDC uint16 = 0x0100 // DACL Computed Inheritance Required
	SecurityDescriptorFlagSC uint16 = 0x0200 // SACL Computed Inheritance Required
	SecurityDescriptorFlagDI uint16 = 0x0400 // DACL Auto-Inherited
	SecurityDescriptorFlagSI uint16 = 0x0800 // SACL Auto-Inherited
	SecurityDescriptorFlagPD uint16 = 0x1000 // DACL Protected
	SecurityDescriptorFlagPS uint16 = 0x2000 // SACL Protected
	SecurityDescriptorFlagPM uint16 = 0x4000 // RM Control Valid
	SecurityDescriptorFlagSR uint16 = 0x8000 // Self-Relative
)

// MS-DTYP Section 2.4.4.1 ACE_HEADER
// AceType
const (
	AccessAllowedAceType               byte = 0x00
	AccessDeniedAceType                byte = 0x01
	SystemAuditAceType                 byte = 0x02
	SystemAlarmAceType                 byte = 0x03
	AccessAllowedCompoundAceType       byte = 0x04
	AccessAllowedObjectAceType         byte = 0x05
	AccessDeniedObjectAceType          byte = 0x06
	SystemAuditObjectAceType           byte = 0x07
	SystemAlarmObjectAceType           byte = 0x08
	AccessAllowedCallbackAceType       byte = 0x09
	AccessDeniedCallbackAceType        byte = 0x0a
	AccessAllowedCallbackObjectAceType byte = 0x0b
	AccessDeniedCallbackObjectAceType  byte = 0x0c
	SystemAuditCallbackAceType         byte = 0x0d
	SystemAlarmCallbackAceType         byte = 0x0e
	SystemAuditCallbackObjectAceType   byte = 0x0f
	SystemAlarmCallbackObjectAceType   byte = 0x10
	SystemMandatoryLabelAceType        byte = 0x11
	SystemResourceAttribyteAceType     byte = 0x12
	SystemScopedPolicyIdAceType        byte = 0x13
)

// AceFlags
const (
	ObjectInheritAce        byte = 0x01
	ContainerInheritAce     byte = 0x02
	NoPropagateInheritAce   byte = 0x04
	InheritOnlyAce          byte = 0x08
	InheritedAce            byte = 0x10
	SuccessfulAccessAceFlag byte = 0x40
	FailedAccessAceFlag     byte = 0x80
	DefaultAceFlag          byte = 0x02 // ContainerInheritAce
)

type ReturnCode struct {
	uint32
}

// MS-DTYP Section 2.3.3 FILETIME
type Filetime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// MS-DTYP Section 2.3.3 FILETIME
type PFiletime struct {
	LowDateTime  uint32
	HighDateTime uint32
}

// MS-DTYP Section 2.4.5.1 ACL--RPC Representation
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

// MS-DTYP Section 2.4.4.2 ACCESS_ALLOWED_ACE
type ACE struct {
	Header ACEHeader
	Mask   uint32
	Sid    SID //Must be multiple of 4
}

// MS-DTYP Section 2.4.2.3 RPC_SID
type SID struct {
	Revision       byte
	NumAuth        byte
	Authority      []byte
	SubAuthorities []uint32
}

// MS-DTYP Section 2.3.10 RPC_UNICODE_STRING
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

// MS-DTYP Section 2.4.6.1 SECURITY_DESCRIPTOR
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

func (self *ReturnCode) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for ReturnCode")
}

func (self *ReturnCode) UnmarshalBinary(buf []byte) error {
	self.uint32 = le.Uint32(buf)
	return nil
}

// Specifically to handle all the ref id ptrs and array len and size valus that are lifted out of the structures
func ReadRPCUnicodeStrArray(r *bytes.Reader, nullTerminated bool) (items []string, err error) {
	// Skip ref id
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	count := uint32(0)

	err = binary.Read(r, le, &count)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip Array item len, max size and ref id ptr
	_, err = r.Seek(int64(8*count), io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(count); i++ {
		s := ""
		s, err = ReadConformantVaryingString(r, nullTerminated)
		if err != nil {
			log.Errorln(err)
			return
		}
		items = append(items, s)
	}

	return
}

func ReadRPCUnicodeStr(r *bytes.Reader, nullTerminated bool) (s string, maxLength uint16, err error) {
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
			return
		}
	}

	s, err = ReadConformantVaryingStringPtr(r, nullTerminated)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func ReadRPCUnicodeStrPtr(r *bytes.Reader, nullTerminated bool) (s string, maxLength uint16, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return ReadRPCUnicodeStr(r, nullTerminated)
}

// Not null terminated
func WriteRPCUnicodeStrPtr(w io.Writer, s string, refId *uint32) (n int, err error) {
	unc := ToUnicode(s)

	buflen := uint16(len(unc))
	err = binary.Write(w, le, buflen) // Len
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, buflen) // Max Size
	if err != nil {
		log.Errorln(err)
		return
	}

	//n, err = WriteConformantVaryingArrayPtr(w, unc, uint32(bufMaxSize), refId)
	n, err = WriteConformantVaryingStringPtr(w, s, refId, false)
	if err != nil {
		log.Errorln(err)
		return
	}

	n += 4 // Len and Max Size

	return
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
		self.OwnerSid, err = ReadSID(r)
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
		self.GroupSid, err = ReadSID(r)
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

func ReadSID(r *bytes.Reader) (s *SID, err error) {
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
	sid, err := ReadSID(r)
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

	sid, err := ReadSID(r)
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

func (self *SID) ToString() (s string) {
	return ConvertSIDtoStr(self)
}
