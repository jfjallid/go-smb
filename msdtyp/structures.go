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
	"io"

	"github.com/jfjallid/golog"
)

var (
	le  = binary.LittleEndian
	be  = binary.BigEndian
	log = golog.Get("github.com/jfjallid/go-smb/msdtyp").SetDisplayName("msdtyp")
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
	SystemResourceAttributeAceType     byte = 0x12
	SystemScopedPolicyIdAceType        byte = 0x13
)

var AceTypeMap = map[byte]string{
	AccessAllowedAceType:               "AccessAllowed",
	AccessDeniedAceType:                "AccessDenied",
	SystemAuditAceType:                 "SystemAudit",
	SystemAlarmAceType:                 "SystemAlarm",
	AccessAllowedCompoundAceType:       "AccessAllowedCompound",
	AccessAllowedObjectAceType:         "AccessAllowedObject",
	AccessDeniedObjectAceType:          "AccessDeniedObject",
	SystemAuditObjectAceType:           "SystemAuditObject",
	SystemAlarmObjectAceType:           "SystemAlarmObject",
	AccessAllowedCallbackAceType:       "AccessAllowedCallback",
	AccessDeniedCallbackAceType:        "AccessDeniedCallback",
	AccessAllowedCallbackObjectAceType: "AccessAllowedCallbackObject",
	AccessDeniedCallbackObjectAceType:  "AccessDeniedCallbackObject",
	SystemAuditCallbackAceType:         "SystemAuditCallback",
	SystemAlarmCallbackAceType:         "SystemAlarmCallback",
	SystemAuditCallbackObjectAceType:   "SystemAuditCallbackObject",
	SystemAlarmCallbackObjectAceType:   "SystemAlarmCallbackObject",
	SystemMandatoryLabelAceType:        "SystemMandatoryLabel",
	SystemResourceAttributeAceType:     "SystemResourceAttribute",
	SystemScopedPolicyIdAceType:        "SystemScopedPolicyId",
}

// AceFlags
const (
	ObjectInheritAce        byte = 0x01 // Noncontainer child objects inherit the ACE as an effective ACE
	ContainerInheritAce     byte = 0x02 // Child objects that are containers, such as directories, inherit the ACE as an effective ACE. The inherited ACE is inheritable unless the NO_PROPAGATE_INHERIT_ACE bit flag is also set.
	NoPropagateInheritAce   byte = 0x04 // Ace is only inherited to direct child objects
	InheritOnlyAce          byte = 0x08 // Ace does not control access to the object to which it is attached
	InheritedAce            byte = 0x10 // The ACE was inherited
	SuccessfulAccessAceFlag byte = 0x40 // Generate audit messages for successful access attempts in SACL
	FailedAccessAceFlag     byte = 0x80 // Generate audit messages for failed access attempts in SACL
	DefaultAceFlag          byte = 0x02 // ContainerInheritAce
)

var aceFlagsMap = map[byte]string{
	ObjectInheritAce:        "ObjectInheritAce",
	ContainerInheritAce:     "ContainerInheritAce",
	NoPropagateInheritAce:   "NoPropagateInheritAce",
	InheritOnlyAce:          "InheritOnlyAce",
	InheritedAce:            "InheritedAce",
	SuccessfulAccessAceFlag: "SuccessfulAccessAce",
	FailedAccessAceFlag:     "FailedAccessAce",
}

// MS-DTYP Section 2.4.4.3 ACCESS_ALLOWED_OBJECT_ACE - Flags field bits that
// indicate which of the optional ObjectType / InheritedObjectType GUIDs are
// present in the ACE body.
const (
	AceObjectTypePresent          uint32 = 0x00000001
	AceInheritedObjectTypePresent uint32 = 0x00000002
)

var objectAceTypes = map[byte]bool{
	AccessAllowedObjectAceType:         true,
	AccessDeniedObjectAceType:          true,
	SystemAuditObjectAceType:           true,
	SystemAlarmObjectAceType:           true,
	AccessAllowedCallbackObjectAceType: true,
	AccessDeniedCallbackObjectAceType:  true,
	SystemAuditCallbackObjectAceType:   true,
	SystemAlarmCallbackObjectAceType:   true,
}

// IsObjectAceType reports whether an ACE type carries the optional Flags +
// ObjectType + InheritedObjectType GUID fields (the ACCESS_*_OBJECT_ACE family,
// MS-DTYP 2.4.4.3-2.4.4.6) rather than the plain Mask|SID body.
func IsObjectAceType(t byte) bool {
	return objectAceTypes[t]
}

const (
	AccessMaskGenericRead          = "GENERIC_READ"
	AccessMaskGenericWrite         = "GENERIC_WRITE"
	AccessMaskGenericExecute       = "GENERIC_EXECUTE"
	AccessMaskGenericAll           = "GENERIC_ALL"
	AccessMaskMaximumAllowed       = "MAXIMUM_ALLOWED"
	AccessMaskAccessSystemSecurity = "ACCESS_SYSTEM_SECURITY"
	AccessMaskSynchronize          = "SYNCHRONIZE"
	AccessMaskWriteOwner           = "WRITE_OWNER"
	AccessMaskWriteDACL            = "WRITE_DACL"
	AccessMaskReadControl          = "READ_CONTROL"
	AccessMaskDelete               = "DELETE"
)

var accessMaskMap = map[uint32]string{
	0x80000000: AccessMaskGenericRead,
	0x4000000:  AccessMaskGenericWrite,
	0x20000000: AccessMaskGenericExecute,
	0x10000000: AccessMaskGenericAll,
	0x02000000: AccessMaskMaximumAllowed,
	0x01000000: AccessMaskAccessSystemSecurity,
	0x00100000: AccessMaskSynchronize,
	0x00080000: AccessMaskWriteOwner,
	0x00040000: AccessMaskWriteDACL,
	0x00020000: AccessMaskReadControl,
	0x00010000: AccessMaskDelete,
}

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

// MS-DTYP Section 2.4.4.2 ACCESS_ALLOWED_ACE and 2.4.4.3 ACCESS_ALLOWED_OBJECT_ACE.
// ObjectFlags/ObjectType/InheritedObjectType are only populated (and only
// (un)marshalled) for the object-ACE family, see IsObjectAceType. They are zero
// for basic ACEs, so existing callers reading Mask/Sid are unaffected.
type ACE struct {
	Header              ACEHeader
	Mask                uint32
	ObjectFlags         uint32   // object ACEs only; which GUIDs follow
	ObjectType          [16]byte // present iff ObjectFlags&AceObjectTypePresent
	InheritedObjectType [16]byte // present iff ObjectFlags&AceInheritedObjectTypePresent
	Sid                 SID      //Must be multiple of 4
}

// MS-DTYP Section 2.4.2.3 RPC_SID
type SID struct {
	Revision       byte
	NumAuth        byte
	Authority      [6]byte
	SubAuthorities []uint32 `ndr:"conformant"`
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

type AcePermissions struct {
	AceType             string
	AceFlags            byte
	AceFlagStrings      string
	Permissions         []string
	Sid                 string
	ObjectType          string // GUID string; empty unless an object ACE with ObjectType present
	InheritedObjectType string // GUID string; empty unless an object ACE with InheritedObjectType present
}

type PaclPermissions struct {
	NumAce  uint32
	Entries []AcePermissions
}

func (s *ReturnCode) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("not implemented: MarshalBinary for ReturnCode")
}

func (s *ReturnCode) UnmarshalBinary(buf []byte) error {
	s.uint32 = le.Uint32(buf)
	return nil
}

func (r ReturnCode) Value() uint32 {
	return r.uint32
}

func (s *SecurityDescriptor) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	ptrBuf := make([]byte, 0)
	// Order: 1. SACL, 2. DACL, 3. Owner, 4. Group
	bufOffset := uint32(20)

	if s.Sacl != nil {
		sBuf, err := s.Sacl.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, sBuf...)
		s.Control |= SecurityDescriptorFlagSP
		s.OffsetSacl = bufOffset
		bufOffset += uint32(len(sBuf))
	}
	if s.Dacl != nil {
		dBuf, err := s.Dacl.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, dBuf...)
		s.Control |= SecurityDescriptorFlagDP
		s.OffsetDacl = bufOffset
		bufOffset += uint32(len(dBuf))
	}

	if s.OwnerSid != nil {
		oBuf, err := s.OwnerSid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, oBuf...)
		s.OffsetOwner = bufOffset
		bufOffset += uint32(len(oBuf))
	}

	if s.OffsetGroup != 0 {
		gBuf, err := s.GroupSid.MarshalBinary()
		if err != nil {
			return nil, err
		}
		ptrBuf = append(ptrBuf, gBuf...)
		s.OffsetGroup = bufOffset
	}

	// Encode revision
	err = binary.Write(w, le, s.Revision)
	if err != nil {
		return
	}
	// Encode control
	err = binary.Write(w, le, s.Control)
	if err != nil {
		return
	}
	// Encode  OffsetOwner
	err = binary.Write(w, le, s.OffsetOwner)
	if err != nil {
		return
	}
	// Encode  OffsetGroup
	err = binary.Write(w, le, s.OffsetGroup)
	if err != nil {
		return
	}
	// Encode  OffsetSacl
	err = binary.Write(w, le, s.OffsetSacl)
	if err != nil {
		return
	}
	// Encode  OffsetDacl
	err = binary.Write(w, le, s.OffsetDacl)
	if err != nil {
		return
	}

	// Encode serialized Owner, Group, Sacl and Dacl
	_, err = w.Write(ptrBuf)
	if err != nil {
		return
	}

	return w.Bytes(), nil
}

func (s *SecurityDescriptor) UnmarshalBinary(buf []byte) (err error) {

	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.Revision)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.Control)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.OffsetOwner)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.OffsetGroup)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.OffsetSacl)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.OffsetDacl)
	if err != nil {
		return
	}

	if s.OffsetOwner != 0 {
		_, err = r.Seek(int64(s.OffsetOwner), io.SeekStart)
		if err != nil {
			return
		}
		s.OwnerSid, err = ReadSID(r)
		if err != nil {
			return
		}
	}
	if s.OffsetGroup != 0 {
		_, err = r.Seek(int64(s.OffsetGroup), io.SeekStart)
		if err != nil {
			return
		}
		s.GroupSid, err = ReadSID(r)
		if err != nil {
			return
		}
	}

	if (s.Control & SecurityDescriptorFlagSP) == SecurityDescriptorFlagSP {
		_, err = r.Seek(int64(s.OffsetSacl), io.SeekStart)
		if err != nil {
			return
		}
		s.Sacl, err = readPACL(r)
		if err != nil {
			return
		}
	}

	if (s.Control & SecurityDescriptorFlagDP) == SecurityDescriptorFlagDP {
		_, err = r.Seek(int64(s.OffsetDacl), io.SeekStart)
		if err != nil {
			return
		}
		s.Dacl, err = readPACL(r)
		if err != nil {
			return
		}
	}

	return nil
}

func (s *SID) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	// Encode ACE SID
	err = binary.Write(w, le, s.Revision)
	if err != nil {
		return
	}
	err = binary.Write(w, le, byte(len(s.SubAuthorities)))
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.Authority)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.SubAuthorities)
	if err != nil {
		return
	}

	return w.Bytes(), nil
}

func ReadSID(r *bytes.Reader) (s *SID, err error) {
	s = &SID{}
	// Decode ACE SID
	err = binary.Read(r, le, &s.Revision)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.NumAuth)
	if err != nil {
		return
	}

	//s.Authority = make([]byte, 6)
	err = binary.Read(r, le, &s.Authority)
	if err != nil {
		return
	}

	s.SubAuthorities = make([]uint32, s.NumAuth)
	for i := range s.SubAuthorities {
		err = binary.Read(r, le, &s.SubAuthorities[i])
		if err != nil {
			return
		}
	}

	return
}

func (s *SID) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	sid, err := ReadSID(r)
	if err != nil {
		return
	}

	*s = *sid
	return nil
}

func (s *ACE) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, s.Header.Type)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.Header.Flags)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.Header.Size)
	if err != nil {
		return
	}

	err = binary.Write(w, le, s.Mask)
	if err != nil {
		return
	}

	// Object ACEs carry a Flags field followed by 0-2 GUIDs before the SID.
	if IsObjectAceType(s.Header.Type) {
		err = binary.Write(w, le, s.ObjectFlags)
		if err != nil {
			return
		}
		if s.ObjectFlags&AceObjectTypePresent != 0 {
			err = binary.Write(w, le, s.ObjectType)
			if err != nil {
				return
			}
		}
		if s.ObjectFlags&AceInheritedObjectTypePresent != 0 {
			err = binary.Write(w, le, s.InheritedObjectType)
			if err != nil {
				return
			}
		}
	}

	// Encode ACE SID
	sidBuf, err := s.Sid.MarshalBinary()
	if err != nil {
		return nil, err
	}
	err = binary.Write(w, le, sidBuf)
	if err != nil {
		return
	}
	return w.Bytes(), nil
}

func readACE(r *bytes.Reader) (a *ACE, err error) {
	a = &ACE{}
	err = binary.Read(r, le, &a.Header.Type)
	if err != nil {
		return
	}

	err = binary.Read(r, le, &a.Header.Flags)
	if err != nil {
		return
	}

	err = binary.Read(r, le, &a.Header.Size)
	if err != nil {
		return
	}

	err = binary.Read(r, le, &a.Mask)
	if err != nil {
		return
	}

	// Object ACEs carry a Flags field followed by 0-2 GUIDs before the SID.
	if IsObjectAceType(a.Header.Type) {
		err = binary.Read(r, le, &a.ObjectFlags)
		if err != nil {
			return
		}
		if a.ObjectFlags&AceObjectTypePresent != 0 {
			err = binary.Read(r, le, &a.ObjectType)
			if err != nil {
				return
			}
		}
		if a.ObjectFlags&AceInheritedObjectTypePresent != 0 {
			err = binary.Read(r, le, &a.InheritedObjectType)
			if err != nil {
				return
			}
		}
	}

	sid, err := ReadSID(r)
	if err != nil {
		return
	}
	a.Sid = *sid

	return
}

func (s *ACE) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	ace, err := readACE(r)
	if err != nil {
		return
	}

	*s = *ace
	return nil
}

func (s *PACL) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	err = binary.Write(w, le, s.AclRevision)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.AclSize)
	if err != nil {
		return
	}

	// Encode AceCount at 4 byte boundary
	err = binary.Write(w, le, uint32(len(s.ACLS)))
	if err != nil {
		return
	}

	for _, item := range s.ACLS {
		var aceBuf []byte
		aceBuf, err = item.MarshalBinary()
		if err != nil {
			return
		}
		_, err = w.Write(aceBuf)
		if err != nil {
			return
		}
	}

	return w.Bytes(), nil
}

func readPACL(r *bytes.Reader) (p *PACL, err error) {
	p = &PACL{}
	err = binary.Read(r, le, &p.AclRevision)
	if err != nil {
		return
	}

	err = binary.Read(r, le, &p.AclSize)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &p.AceCount)
	if err != nil {
		return
	}

	p.ACLS = make([]ACE, p.AceCount)
	for i := range p.ACLS {
		var ace *ACE
		ace, err = readACE(r)
		if err != nil {
			return
		}
		p.ACLS[i] = *ace
	}

	return
}

func (s *PACL) UnmarshalBinary(buf []byte) (err error) {
	r := bytes.NewReader(buf)
	pacl, err := readPACL(r)
	if err != nil {
		return
	}
	*s = *pacl

	return nil
}

func (a ACE) Permissions() AcePermissions {
	perms := ParseAccessMask(a.Mask)
	sidStr := a.Sid.ToString()
	p := AcePermissions{
		Sid:            sidStr,
		Permissions:    perms,
		AceType:        AceTypeMap[a.Header.Type],
		AceFlags:       a.Header.Flags,
		AceFlagStrings: ParseAceFlags(a.Header.Flags),
	}
	if IsObjectAceType(a.Header.Type) {
		if a.ObjectFlags&AceObjectTypePresent != 0 {
			p.ObjectType = GuidToString(a.ObjectType)
		}
		if a.ObjectFlags&AceInheritedObjectTypePresent != 0 {
			p.InheritedObjectType = GuidToString(a.InheritedObjectType)
		}
	}
	return p
}

func (s *PACL) Permissions() PaclPermissions {
	var acePerms []AcePermissions
	for _, item := range s.ACLS {
		acePerms = append(acePerms, item.Permissions())
	}
	return PaclPermissions{
		NumAce:  s.AceCount,
		Entries: acePerms,
	}
}

func (s *SID) ToString() string {
	return ConvertSIDtoStr(s)
}

func (s *SID) GetAuthority() uint32 {
	return binary.BigEndian.Uint32(s.Authority[2:])
}

func (s *Filetime) ToWriter(w io.Writer) (n int, err error) {
	err = binary.Write(w, le, s.LowDateTime)
	if err != nil {
		return
	}
	n += 2
	err = binary.Write(w, le, s.HighDateTime)
	if err != nil {
		return
	}
	n += 2
	return
}

func (s *Filetime) FromReader(r *bytes.Reader) (err error) {
	err = binary.Read(r, le, &s.LowDateTime)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.HighDateTime)
	if err != nil {
		return
	}
	return
}

func (s *Filetime) ToString() string {
	t := ConvertFromFiletime(s)
	return t.String()
}
