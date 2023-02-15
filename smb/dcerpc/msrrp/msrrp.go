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
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfjallid/golog"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/go-smb/smb/encoder"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/msrrp")

var (
	MSRRPUuid                       = "338CD001-2244-31F1-AAAA-900038001003"
	MSRRPPipe                       = "winreg"
	MSRRPMajorVersion uint16        = 1
	MSRRPMinorVersion uint16        = 0
	NDRUuid                         = "8a885d04-1ceb-11c9-9fe8-08002b104860"
	re                regexp.Regexp = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)
	ContextItemLen                  = 44
	ContextResItemLen               = 24
)

// MS-RRP Section 2.2.3 REGSAM
const (
	PermKeyQueryValue       uint32 = 0x00000001
	PermKeySetValue         uint32 = 0x00000002
	PermKeyCreateSubKey     uint32 = 0x00000004
	PermKeyEnumerateSubKeys uint32 = 0x00000008
	PermKeyCreateLink       uint32 = 0x00000020
	PermKeyWow6464Key       uint32 = 0x00000100
	PermKeyWow6432Key       uint32 = 0x00000200
)

const PermKeyNotify uint32 = 0x00000010

// MS-DTYP Section 2.4.3 ACCESS_MASK
const (
	PermGenericRead          uint32 = 0x80000000
	PermGenericWrite         uint32 = 0x40000000
	PermGenericExecute       uint32 = 0x20000000
	PermGenericAll           uint32 = 0x10000000
	PermMaximumAllowed       uint32 = 0x02000000
	PermAccessSystemSecurity uint32 = 0x01000000
	PermSynchronize          uint32 = 0x00100000
	PermWriteOwner           uint32 = 0x00080000
	PermWriteDacl            uint32 = 0x00040000
	PermReadControl          uint32 = 0x00020000
	PermDelete               uint32 = 0x00010000
)

var PermMap = map[uint32]string{
	PermKeyQueryValue:        "KEY_QUERY_VALUE",
	PermKeySetValue:          "KEY_SET_VALUE",
	PermKeyCreateSubKey:      "KEY_CREATE_SUB_KEY",
	PermKeyEnumerateSubKeys:  "KEY_ENUMERATE_SUB_KEYS",
	PermKeyNotify:            "KEY_NOTIFY",
	PermKeyCreateLink:        "KEY_CREATE_LINK",
	PermKeyWow6464Key:        "KEY_WOW64_64KEY",
	PermKeyWow6432Key:        "KEY_WOW64_32KEY",
	PermGenericRead:          "GENERIC_READ",
	PermGenericWrite:         "GENERIC_WRITE",
	PermGenericExecute:       "GENERIC_EXECUTE",
	PermGenericAll:           "GENERIC_ALL",
	PermMaximumAllowed:       "MAXIMUM_ALLOW",
	PermAccessSystemSecurity: "ACCESS_SYSTEM_SECURITY",
	PermSynchronize:          "SYNCHRONIZE",
	PermWriteOwner:           "WRITE_OWNER",
	PermWriteDacl:            "WRITE_DACL",
	PermReadControl:          "READ_CONTROL",
	PermDelete:               "DELETE",
}

// MS-RRP Section 2.2.5 RVALENT ve_type
const (
	RegBinary            uint32 = 3
	RegDword             uint32 = 4
	RegDwordLittleEndian uint32 = 4
	RegDwordBigEndian    uint32 = 5
	RegExpandSz          uint32 = 2
	RegLink              uint32 = 6
	RegMultiSz           uint32 = 7
	RegNone              uint32 = 0
	RegQword             uint32 = 11
	RegQwordLittleEndian uint32 = 11
	RegSz                uint32 = 1
)

// MS-RRP Section 2.2.6 Common Error Codes
const (
	ErrorSuccess            uint32 = 0x00000000 // Error success
	ErrorFileNotFound       uint32 = 0x00000002
	ErrorAccessDenied       uint32 = 0x00000005 // Access is denied.
	ErrorOutOfMemory        uint32 = 0x0000000E // Not enough storage available to complete the operation
	ErrorWriteProtect       uint32 = 0x00000013 // A read or write operation was attempted on the volume after it was dismounted.
	ErrorNotReady           uint32 = 0x00000015 // The service is not ready. Calls can be repeated at a later time.
	ErrorInvalidParameter   uint32 = 0x00000057 // The parameter is incorrect.
	ErrorCallNotImplemented uint32 = 0x00000078 // The method is not valid.
	ErrorBusy               uint32 = 0x000000AA // The requested resource is busy.
	ErrorAlreadyExists      uint32 = 0x000000B7 // File already exists.
	ErrorMoreData           uint32 = 0x000000EA // The size of the buffer is not large enough to hold the requested data.
	WaitTimeout             uint32 = 0x00000102 // The wait operation timed out.
	ErrorNoMoreItems        uint32 = 0x00000103 // No more data is available
	ErrorKeyDeleted         uint32 = 0x000003FA // An illegal operation was attempted on a registry key that is pending delete.
)

var ReturnCodeMap = map[uint32]error{
	ErrorSuccess:            fmt.Errorf("ERROR_SUCCESS"),
	ErrorFileNotFound:       fmt.Errorf("ERROR_FILE_NOT_FOUND"),
	ErrorAccessDenied:       fmt.Errorf("ERROR_ACCESS_DENIED"),
	ErrorOutOfMemory:        fmt.Errorf("ERROR_OUT_OF_MEMORY"),
	ErrorWriteProtect:       fmt.Errorf("ERROR_WRITE_PROCTED"),
	ErrorNotReady:           fmt.Errorf("ERROR_NOT_READY"),
	ErrorInvalidParameter:   fmt.Errorf("ERROR_INVALID_PARAMETER"),
	ErrorCallNotImplemented: fmt.Errorf("ERROR_CALL_NOT_IMPLEMENTED"),
	ErrorBusy:               fmt.Errorf("ERROR_BUSY"),
	ErrorAlreadyExists:      fmt.Errorf("ERROR_ALREADY_EXISTS"),
	ErrorMoreData:           fmt.Errorf("ERROR_MORE_DATA"),
	WaitTimeout:             fmt.Errorf("WAIT_TIMEOUT"),
	ErrorNoMoreItems:        fmt.Errorf("ERROR_NO_MORE_ITEMS"),
	ErrorKeyDeleted:         fmt.Errorf("ERROR_KEY_DELETED"),
}

// MS-RRP Section 2.2.9 Security information
const (
	OwnerSecurityInformation uint32 = 0x00000001 // If set, specifies the security identifier (SID) (LSAPR_SID) of the object's owner.
	GroupSecurityInformation uint32 = 0x00000002 // If set, specifies the security identifier (SID) (LSAPR_SID) of the object's primary group.
	DACLSecurityInformation  uint32 = 0x00000004 // If set, the security descriptor MUST include the object's discretionary access control list (DACL).
	SACLSecurityInformation  uint32 = 0x00000008 // If set, the security descriptor MUST include the object's system access control list (SACL).
)

// MS-RRP Section 3.1.5. OP Codes
const (
	OpenClassesRoot             uint16 = 0  // Called by the client. In response, the server opens the HKEYClassesRoot predefined key and returns a handle to the HKEYClassesRoot key.
	OpenCurrentUser             uint16 = 1  // Called by the client. In response, the server opens the HKEYCurrentUser predefined key and returns a handle to the HKEYCurrentUser key.
	OpenLocalMachine            uint16 = 2  // Called by the client. In response, the server opens the HKEYLocalMachine predefined key and returns a handle to the HKEYLocalMachine key.
	OpenPerformanceData         uint16 = 3  // Called by the client. In response, the server opens the HKEYPerformanceData predefined key and returns a handle to the HKEYPerformanceData key.
	OpenUsers                   uint16 = 4  // Called by the client. In response, the server opens the HKEYUsers predefined key and returns a handle to the HKEYUsers key.
	BaseRegCloseKey             uint16 = 5  // Called by the client. In response, the server releases a handle to the specified registry key.
	BaseRegCreateKey            uint16 = 6  // Called by the client. In response, the server creates the specified registry key. If the key already exists in the registry, the function opens it.
	BaseRegDeleteKey            uint16 = 7  // Called by the client. In response, the server deletes the specified subkey.
	BaseRegDeleteValue          uint16 = 8  // Called by the client. In response, the server removes a named value from the specified registry key.
	BaseRegEnumKey              uint16 = 9  // Called by the client. In response, the server returns the requested subkey.
	BaseRegEnumValue            uint16 = 10 // Called by the client. In response, the server enumerates the values for the specified open registry key.
	BaseRegFlushKey             uint16 = 11 // Called by the client. In response, the server writes all the attributes of the specified open registry key into the registry.
	BaseRegGetKeySecurity       uint16 = 12 // Called by the client. In response, the server returns a copy of the security descriptor that protects the specified open registry key.
	BaseRegLoadKey              uint16 = 13 // Called by the client. In response, the server creates a subkey under HKEYUsers or HKEYLocalMachine and stores registration information from a specified file in that subkey.
	BaseRegOpenKey              uint16 = 15 // Called by the client. In response, the server opens the specified key for access, returning a handle to it.
	BaseRegQueryInfoKey         uint16 = 16 // Called by the client. In response, the server returns relevant information about the key that corresponds to the specified key handle.
	BaseRegQueryValue           uint16 = 17 // Called by the client. In response, the server returns the data that is associated with the default value of a specified registry open key.
	BaseRegReplaceKey           uint16 = 18 // Called by the client. In response, the server MUST read the registry information from the specified file and replace the specified key with the content of the file, so that when the system is restarted, the key and subkeys have the same values as those in the specified file.
	BaseRegRestoreKey           uint16 = 19 // Called by the client. In response, the server reads the registry information in a specified file and copies it over the specified key. The registry information can take the form of a key and multiple levels of subkeys.
	BaseRegSaveKey              uint16 = 20 // Called by the client. In response, the server saves the specified key and all its subkeys and values to a new file.
	BaseRegSetKeySecurity       uint16 = 21 // Called by the client. In response, the server sets the security descriptor that protects the specified open registry key.
	BaseRegSetValue             uint16 = 22 // Called by the client. In response, the server sets the data for the default value of a specified registry key. The data MUST be a text string.
	BaseRegUnLoadKey            uint16 = 23 // Called by the client. In response, the server removes the specified discrete body of keys, subkeys, and values that are rooted at the top of the registry hierarchy.
	BaseRegGetVersion           uint16 = 26 // Called by the client. In response, the server returns the version to which a registry key is connected.
	OpenCurrentConfig           uint16 = 27 // Called by the client. In response, the server attempts to open the HKEY_CURRENT_CONFIG predefined key and returns a handle to the HKEY_CURRENT_CONFIG key.
	BaseRegQueryMultipleValues  uint16 = 29 // Called by the client. In response, the server returns the type and data for a list of value names that are associated with the specified registry key.
	BaseRegSaveKeyEx            uint16 = 31 // Called by the client. In response, the server saves the specified key and all its subkeys and values to a new file.
	OpenPerformanceText         uint16 = 32 // Called by the client. In response, the server opens the HKEY_PERFORMANCE_TEXT predefined key and returns a handle to the HKEY_PERFORMANCE_TEXT key.
	OpenPerformanceNlsText      uint16 = 33 // Called by the client. In response, the server opens the HKEY_PERFORMANCE_NLSTEXT predefined key and returns a handle to the HKEY_PERFORMANCE_NLSTEXT key.
	BaseRegQueryMultipleValues2 uint16 = 34 // Called by the client. In response, the server returns the type and data for a list of value names that are associated with the specified registry key.
	BaseRegDeleteKeyEx          uint16 = 35 // Called by the client. In response, the server deletes the specified subkey. This function differs from BaseRegDeleteKey in that either 32-bit or 64-bit keys can be deleted, regardless of what kind of application is running.
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

// Enum of base keys
const (
	HKEYClassesRoot byte = iota
	HKEYCurrentUser
	HKEYLocalMachine
	HKEYPerformanceData
	HKEYUsers
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{sb}
}

func convertSIDtoStr(sid *SID) (s string, err error) {
	// Not sure what the first two bytes are but the
	// Identifier Authority is stored as BigEndian while the rest is little endian
	auth := binary.BigEndian.Uint32(sid.Authority[2:])
	s = fmt.Sprintf("S-%d-%d", sid.Revision, auth)
	//NOTE Seems that perhaps the sid.NumAuth (count) does not always accurately specify number of
	// Sub Authoritys but rather number of DWORDS. E.g., a SubAuthority could take more than 1 DWORD?
	for i := 0; i < int(sid.NumAuth); i++ {
		s = fmt.Sprintf("%s-%d", s, sid.SubAuthorities[i])
	}
	return
}

func convertStrToSID(s string) (sid *SID, err error) {
	sid = &SID{}
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		err = fmt.Errorf("Invalid SID representation")
		return
	}
	rev, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		log.Errorln(err)
		return
	}
	sid.Revision = byte(rev)
	auth, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		log.Errorln(err)
		return
	}
	authBuf := make([]byte, 2, 6)
	authBuf = binary.BigEndian.AppendUint32(authBuf, uint32(auth))
	sid.Authority = authBuf
	subCount := byte(0)
	subAuths := make([]uint32, 0)
	for _, part := range parts[3:] {
		subA, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		subAuths = append(subAuths, uint32(subA))
		subCount += 1
	}
	sid.SubAuthorities = subAuths
	sid.NumAuth = subCount
	return
}

func (r *RPCCon) OpenBaseKey(baseName byte) (handle []byte, err error) {
	req := OpenRootKeyReq{
		DesiredAccess: PermMaximumAllowed,
	}
	var opCode uint16

	log.Debugln("Trying to open basekey (%d)\n", baseName)
	switch baseName {
	case HKEYClassesRoot:
		opCode = OpenClassesRoot
	case HKEYLocalMachine:
		opCode = OpenLocalMachine
	default:
		err = fmt.Errorf("NOT Implemented base key!")
		return
	}

	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(opCode, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Retrieve context handle from response
	res := OpenKeyRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	handle = res.HKey
	return
}

func (r *RPCCon) CloseKeyHandle(hKey []byte) (err error) {
	req := BaseRegCloseKeyReq{
		HKey: hKey,
	}

	log.Debugln("Trying to close basekey handle (0x%x)\n", hKey)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegCloseKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.uint32 != ErrorSuccess {
		err = ReturnCodeMap[res.uint32]
		log.Errorln(err)
	}

	return
}

// Opnum 9
func (r *RPCCon) EnumKey(hKey []byte, index uint32) (info *KeyInfo, err error) {
	req := BaseRegEnumKeyReq{
		HKey:  hKey,
		Index: index,
		NameIn: PRRPUnicodeStr2{
			Length:    0,
			MaxLength: 512,
		},
		ClassIn: PRRPUnicodeStr2{
			Length:    0,
			MaxLength: 512,
		},
		LastWriteTime: &PFiletime{1, 2},
	}

	log.Debugln("Trying to enumerate subkey (%d) for key handle (0x%x)\n", index, hKey)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegEnumKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegEnumKeyRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	info = &KeyInfo{
		KeyName:   res.NameOut.Buffer,
		ClassName: res.ClassOut.Buffer,
	}
	info.ClassName = info.ClassName[:len(info.ClassName)-1] // Remove null byte
	info.KeyName = info.KeyName[:len(info.KeyName)-1]       // Remove null byte

	return
}

// Opnum 10
func (r *RPCCon) EnumValue(hKey []byte, index uint32) (value *ValueInfo, err error) {

	req := BaseRegEnumValueReq{
		HKey:    hKey,
		Index:   index,
		NameIn:  PRRPUnicodeStr2{Length: 0, MaxLength: 1024},
		Type:    1024,
		MaxLen:  1024,
		DataLen: 0,
	}

	log.Debugln("Trying to enumerate value name for index (%d) for key handle (0x%x)\n", index, hKey)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegEnumValue, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegEnumValueRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
		return
	}

	value = &ValueInfo{
		Name:     res.NameOut.Buffer,
		Type:     res.Type,
		ValueLen: res.DataLen,
		Value:    res.Data,
	}
	return
}

func NewAce(sidStr string, mask uint32, aceType, aceFlags byte) (ace *ACE, err error) {
	sid, err := convertStrToSID(sidStr)
	if err != nil {
		log.Errorln(err)
		return
	}
	return &ACE{
		Header: ACEHeader{
			Type:  aceType,
			Flags: aceFlags,
			Size:  uint16(sid.NumAuth*4 + 16),
		},
		Mask: mask,
		Sid:  *sid,
	}, nil
}

func NewACL(acls []ACE) (acl *PACL) {
	numAcls := len(acls)
	aceSize := uint16(8)
	for _, ace := range acls {
		aceSize += ace.Header.Size
	}

	return &PACL{
		AclRevision: 2, // NT4
		AclSize:     aceSize,
		AceCount:    uint32(numAcls),
		ACLS:        acls,
	}
}

func NewSecurityDescriptor(control uint16, owner, group *SID, dacl, sacl *PACL) (sd *SecurityDescriptor, err error) {
	sd = &SecurityDescriptor{
		Revision: 1,
		Control:  control,
	}
	offset := uint32(20) // Struct fields before variable length data
	if owner != nil {
		sd.OwnerSid = owner
		sd.OffsetOwner = offset
		offset += uint32(owner.NumAuth*4 + 8)
	}
	if group != nil {
		sd.GroupSid = group
		sd.OffsetGroup = offset
		offset += uint32(group.NumAuth*4 + 8)
	}
	if sacl != nil {
		sd.Sacl = sacl
		sd.Control |= SecurityDescriptorFlagSP
		sd.OffsetSacl = offset
		offset += uint32(sacl.AclSize)
	}
	if dacl != nil {
		sd.Dacl = dacl
		sd.Control |= SecurityDescriptorFlagDP
		sd.OffsetDacl = offset
	}

	return
}

func (r *RPCCon) OpenSubKey(hKey []byte, subkey string) (handle []byte, err error) {
	name, err := encoder.Utf8ToUtf16(encoder.ToUnicode(subkey + "\x00"))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	req := BaseRegOpenKeyReq{
		HKey:          hKey,
		SubKey:        PRRPUnicodeStr2{Length: uint16(len(name)), MaxLength: uint16(len(name)), Buffer: name},
		Options:       0, // Impacket sets this to 1. Can't find any reference to what that means
		DesiredAccess: PermMaximumAllowed,
		//DesiredAccess: KeyEnumerateSubKeys|KeyQueryValue, // These permissions result in AccessDenied for certain keys
	}

	log.Debugln("Trying to open subkey (%s)\n", subkey)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegOpenKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Retrieve context handle from response
	res := OpenKeyRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	handle = res.HKey
	return
}

func (r *RPCCon) QueryKeyInfo(hKey []byte) (info *KeyInfo, err error) {
	req := BaseRegQueryInfoKeyReq{
		HKey: hKey,
		ClassIn: RRPUnicodeStr3{
			Length:    0,
			MaxLength: 18,
			Buffer:    nil,
		},
	}

	log.Debugln("Trying to Query key info for key handle (0x%x)\n", hKey)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegQueryInfoKey, reqBuf)
	if err != nil {
		return
	}

	res := BaseRegQueryInfoKeyRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	info = &KeyInfo{
		ClassName:       res.ClassOut.Buffer,
		SubKeys:         res.SubKeys,
		MaxSubKeyLen:    res.MaxSubKeyLen,
		MaxClassLen:     res.MaxClassLen,
		Values:          res.Values,
		MaxValueNameLen: res.MaxValueNameLen,
		MaxValueLen:     res.MaxValueLen,
	}
	info.ClassName = info.ClassName[:len(info.ClassName)-1] // Remove null byte

	return
}

func (r *RPCCon) QueryValue(hKey []byte, name string) (result []byte, err error) {

	// If I send the parameter Data (lpData) as nil and the DataLen(lpcbData) and MaxSize(lpcbLen) to 0
	// The server will respond with the size of the requested value in the lpcbData parameter.

	name = NullTerminate(name)
	encodedName, err := encoder.Utf8ToUtf16(encoder.ToUnicode(name))
	if err != nil {
		log.Errorln(err)
		return
	}

	req := BaseRegQueryValueReq{
		HKey:      hKey,
		ValueName: PRRPUnicodeStr2{Length: uint16(len(name)), MaxLength: uint16(len(name)), Buffer: encodedName},
		Type:      1024,
		Data:      nil,
		MaxLen:    1024,
		DataLen:   0,
	}

	log.Debugln("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegQueryValue, reqBuf)
	if err != nil {
		return
	}

	res := BaseRegQueryValueRes{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	return res.Data, nil
}

func (r *RPCCon) QueryValueString(hKey []byte, name string) (result string, err error) {
	data, err := r.QueryValue(hKey, name)
	if err != nil {
		log.Errorln(err)
		return
	}

	return encoder.FromUnicodeString(data[:len(data)-2])
}

func (r *RPCCon) RegSaveKey(hKey []byte, filename string, owner string) (err error) {
	adminSIDStr := "S-1-5-32-544"

	// Restrict access to Local Administrators group.
	if owner != "" {
		_, err = convertStrToSID(owner)
		if err != nil {
			log.Errorln("Invalid Owner SID. Falling back on using local administrators SID")
			owner = adminSIDStr
		}
	} else {
		owner = adminSIDStr
	}
	adminMask := PermGenericRead | PermGenericWrite | PermWriteDacl | PermDelete
	aAce, err := NewAce(owner, adminMask, AccessAllowedAceType, ContainerInheritAce)
	if err != nil {
		log.Errorln(err)
		return
	}
	ownerSid, err := convertStrToSID(owner)
	if err != nil {
		log.Errorln(err)
		return
	}
	acl := NewACL([]ACE{*aAce})

	// OwnerSid is not required. Without it it falls back to Local Administrators?
	// Or perhaps to the user authenticated?
	sd, err := NewSecurityDescriptor(SecurityDescriptorFlagSR, ownerSid, nil, acl, nil)
	//sd, err := NewSecurityDescriptor(SecurityDescriptorFlagSR, nil, nil, acl, nil)
	if err != nil {
		log.Errorln(err)
		return
	}
	sdbuf, err := sd.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	sdbufLen := uint32(len(sdbuf))
	rd := RpcSecurityDescriptor{
		SecurityDescriptor:    *sd,
		InSecurityDescriptor:  sdbufLen,
		OutSecurityDescriptor: sdbufLen,
	}

	sa := &RpcSecurityAttributes{
		SecurityDescriptor: rd,
		Length:             sdbufLen + 12 + 8, // Includes the size of the length parameters
		InheritHandle:      0,
	}
	filenameBuf, err := encoder.Utf8ToUtf16(encoder.ToUnicode(filename))
	if err != nil {
		return
	}
	req := BaseRegSaveKeyReq{
		HKey:               hKey,
		FileName:           PRRPUnicodeStr2{Length: uint16(len(filenameBuf)), MaxLength: uint16(len(filenameBuf)), Buffer: filenameBuf},
		SecurityAttributes: *sa,
	}

	log.Debugln("Trying to save reg key to file (%s)\n", filename)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegSaveKey, reqBuf)
	if err != nil {
		return
	}

	res := ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.uint32 != ErrorSuccess {
		err = ReturnCodeMap[res.uint32]
	}

	return
}

func (r *RPCCon) GetKeySecurity(hKey []byte) (sd *SecurityDescriptor, err error) {

	//TODO check if I can ask for size first and then send another request with that size
	req := BaseRegGetKeySecurityReq{
		HKey:                hKey,
		SecurityInformation: OwnerSecurityInformation | GroupSecurityInformation | DACLSecurityInformation,
		SecurityDescriptorIn: SecurityData{
			Size:            4096, // Perhaps I can figure out what value I need here with some other request? Or should I just set it really high?
			Len:             0,
			KeySecurityData: nil,
		},
	}

	//log.Debugln("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegGetKeySecurity, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegGetKeySecurityRes{
		SecurityDescriptorOut: SecurityData{
			KeySecurityData: &SecurityDescriptor{},
		},
		ReturnCode: ReturnCode{},
	}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode.uint32 != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode.uint32]
		log.Errorln(err)
		return
	}
	log.Infoln("Successfully got the security information")
	sd = res.SecurityDescriptorOut.KeySecurityData

	return
}

func (r *RPCCon) SetKeySecurity(hKey []byte, sd *SecurityDescriptor) (err error) {

	sdbuf, err := sd.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	req := BaseRegSetKeySecurityReq{
		HKey: hKey,
		SecurityDescriptorIn: SecurityData{
			Size:            uint32(len(sdbuf)),
			Len:             uint32(len(sdbuf)),
			KeySecurityData: sd,
		},
	}
	if sd.Sacl != nil {
		req.SecurityInformation |= SACLSecurityInformation
	}
	if sd.Dacl != nil {
		req.SecurityInformation |= DACLSecurityInformation
	}
	if sd.OwnerSid != nil {
		req.SecurityInformation |= OwnerSecurityInformation
	}
	if sd.GroupSid != nil {
		req.SecurityInformation |= GroupSecurityInformation
	}

	//log.Debugln("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeIoCtlRequest(BaseRegSetKeySecurity, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.uint32 != ErrorSuccess {
		err = ReturnCodeMap[res.uint32]
	}
	log.Infoln("Successfully changed the SecurityDescriptor")
	return
}

func (r *RPCCon) GetSubKeyNames(hKey []byte, subkey string) (names []string, err error) {
	hSubKey, err := r.OpenSubKey(hKey, subkey)
	if err != nil {
		log.Errorln(err)
		return
	}
	defer r.CloseKeyHandle(hSubKey)
	res, err := r.QueryKeyInfo(hSubKey)
	if err != nil {
		log.Errorln(err)
		return
	}
	names = make([]string, 0, res.SubKeys)

	var res2 *KeyInfo
	for i := uint32(0); i < res.SubKeys; i++ {
		res2, err = r.EnumKey(hSubKey, i)
		if err != nil {
			log.Errorln(err)
			return
		}

		tmp := encoder.Utf16ToUtf8(res2.KeyName)
		name, err := encoder.FromUnicodeString(tmp)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}

		//names = append(names, subkey + "\\" + name[:len(name)-1]) //Skip trailing null byte
		//names = append(names, subkey + "\\" + name)
		names = append(names, name)
	}

	return
}

func (r *RPCCon) GetValueNames(hKey []byte) (names []string, err error) {
	res, err := r.QueryKeyInfo(hKey)
	if err != nil {
		log.Errorln(err)
		return
	}

	names = make([]string, 0, res.Values)
	for i := uint32(0); i < res.Values; i++ {
		value, err := r.EnumValue(hKey, i)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		name, err := encoder.FromUnicodeString(encoder.Utf16ToUtf8(value.Name))
		if err != nil {
			log.Errorln(err)
			return nil, err
		}

		names = append(names, name[:len(name)-1])
	}
	return
}

func NullTerminate(s string) string {
	if s == "" {
		s = "\x00"
	} else if s[len(s)-1] != 0x00 {
		return s + "\x00"
	}
	return s
}
