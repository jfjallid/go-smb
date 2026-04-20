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
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"
	"github.com/jfjallid/mstypes"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/msrrp")

// fromUnicodeStrArray decodes a REG_MULTI_SZ payload (a sequence of UTF-16LE
// strings each terminated by a null WCHAR, with the list itself terminated by
// a final null WCHAR) into a slice of Go strings.
func fromUnicodeStrArray(buf []byte) (result []string, err error) {
	if len(buf) < 2 {
		return
	}
	var currentString []uint16
	for i := 0; i < len(buf); i += 2 {
		// Ensure we have enough bytes for a uint16
		if i+1 >= len(buf) {
			break
		}

		// Combine two bytes into a UTF-16LE character
		char := (uint16(buf[i+1]) << 8) | uint16(buf[i])

		// Check if this is a null terminator
		if char == 0 {
			// If we have characters, add the string to result
			if len(currentString) > 0 {
				result = append(result, string(utf16.Decode(currentString)))
				currentString = nil
			} else {
				// Double null terminator - end of list
				break
			}
		} else {
			// Add character to current string
			currentString = append(currentString, char)
		}
	}
	return
}

// newRRPString builds an mstypes.RPCUnicodeString for the RRP semantic where
// the wire value is null-terminated. Both Length and MaximumLength include
// the trailing null, matching the pattern used by MS-RRP requests.
func newRRPString(s string) mstypes.RPCUnicodeString {
	ns := msdtyp.NullTerminate(s)
	l := uint16(len(ns)) * 2
	return mstypes.RPCUnicodeString{
		Length:        l,
		MaximumLength: l,
		Value:         ns,
	}
}

// newRRPStringBuffer builds an empty mstypes.RPCUnicodeString with a
// MaximumLength reserved for the given number of WCHARs. Use for [in, out]
// parameters where the client pre-allocates a buffer for the server to fill.
func newRRPStringBuffer(maxChars uint16) mstypes.RPCUnicodeString {
	return mstypes.RPCUnicodeString{
		Length:        0,
		MaximumLength: maxChars * 2,
		Value:         "",
	}
}

// newRRPInBuffer builds an empty rrpInBufferString reserving maxChars WCHARs
// for the server to write into. Used for [in,out] PRRP_UNICODE_STRING /
// PRPC_UNICODE_STRING parameters where the client must transmit a non-NULL
// Buffer pointer (with empty conformant body) so the server can write the
// response in place.
func newRRPInBuffer(maxChars uint16) rrpInBufferString {
	return rrpInBufferString{
		Length:        0,
		MaximumLength: maxChars * 2,
		Buffer:        "",
	}
}

// newRRPInBufferPtr returns a pointer wrapper for newRRPInBuffer, used for
// [in,out,unique] parameters that require the outer pointer to also be
// non-NULL.
func newRRPInBufferPtr(maxChars uint16) *rrpInBufferString {
	b := newRRPInBuffer(maxChars)
	return &b
}

var (
	MSRRPUuid                = "338CD001-2244-31F1-AAAA-900038001003"
	MSRRPPipe                = "winreg"
	MSRRPMajorVersion uint16 = 1
	MSRRPMinorVersion uint16 = 0
	NDRUuid                  = "8a885d04-1ceb-11c9-9fe8-08002b104860"
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
	RegNone              uint32 = 0
	RegSz                uint32 = 1 // A null-terminated string.
	RegExpandSz          uint32 = 2 // A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%").
	RegBinary            uint32 = 3 // Binary data in any form.
	RegDword             uint32 = 4 // A 32-bit number.
	RegDwordLittleEndian uint32 = 4
	RegDwordBigEndian    uint32 = 5
	RegLink              uint32 = 6  // A symbolic link.
	RegMultiSz           uint32 = 7  // A sequence of null-terminated strings, terminated by an empty string (\0).
	RegQword             uint32 = 11 // A 64-bit number.
	RegQwordLittleEndian uint32 = 11
)

var RegValueTypeMap = map[uint32]string{
	RegNone:           "RegNone",
	RegSz:             "RegSz",
	RegExpandSz:       "RegExpandSz",
	RegBinary:         "RegBinary",
	RegDword:          "RegDword",
	RegDwordBigEndian: "RegDwordBigEndian",
	RegLink:           "RegLink",
	RegMultiSz:        "RegMultiSz",
	RegQword:          "RegQword",
}

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
	ErrorBadPathName        uint32 = 0x000000A1
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
	ErrorBadPathName:        fmt.Errorf("ERROR_BAD_PATH_NAME"),
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

// Enum of base keys
const (
	HKEYClassesRoot byte = iota
	HKEYCurrentUser
	HKEYLocalMachine
	HKEYPerformanceData
	HKEYUsers
	HKEYCurrentConfig
)

const (
	RegOptionBackupRestore uint32 = 0x04
	RegOptionOpenLink      uint32 = 0x08
)

const (
	RegCreatedNewKey     uint32 = 0x01
	RegOpenedExistingKey uint32 = 0x02
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{sb}
}

func (r *RPCCon) OpenBaseKey(baseName byte) (handle []byte, err error) {
	req := OpenRootKeyReq{
		DesiredAccess: PermMaximumAllowed,
	}
	var opCode uint16

	log.Debugf("Trying to open basekey (%d)\n", baseName)
	switch baseName {
	case HKEYClassesRoot:
		opCode = OpenClassesRoot
	case HKEYLocalMachine:
		opCode = OpenLocalMachine
	case HKEYCurrentUser:
		opCode = OpenCurrentUser
	case HKEYUsers:
		opCode = OpenUsers
	case HKEYCurrentConfig:
		opCode = OpenCurrentConfig
	default:
		err = fmt.Errorf("NOT Implemented base key!")
		return
	}

	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(opCode, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Retrieve context handle from response
	res := OpenKeyRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	handle = res.HKey[:]
	return
}

func (r *RPCCon) CloseKeyHandle(hKey []byte) (err error) {
	req := BaseRegCloseKeyReq{}
	if len(hKey) != 20 {
		return fmt.Errorf("Invalid length of HKey in CloseKeyHandle")
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to close basekey handle (0x%x)\n", hKey)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegCloseKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := msdtyp.ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.Value() != ErrorSuccess {
		err = ReturnCodeMap[res.Value()]
		log.Errorln(err)
	}

	return
}

// Opnum 6
func (r *RPCCon) CreateKey(hKey []byte, name, class string, options, desiredAccess uint32, sa *RpcSecurityAttributes) (hSubKey []byte, disposition uint32, err error) {
	if desiredAccess == 0 {
		desiredAccess = PermMaximumAllowed
	}
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in CreateKey")
		return
	}

	dispIn := RegCreatedNewKey
	req := BaseRegCreateKeyReq{
		SubKey:        newRRPString(name),
		Class:         newRRPString(class),
		Options:       options,
		DesiredAccess: desiredAccess,
		SecurityAttr:  sa,
		Disposition:   &dispIn,
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to create registry key (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegCreateKey, reqBuf)
	if err != nil {
		return
	}
	if len(buffer) < 28 {
		err = fmt.Errorf("Response to BaseRegCreateKey was too short")
		log.Errorln(err)
		return
	}
	var res BaseRegCreateKeyRes
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	hSubKey = res.HKey[:]
	if res.Disposition != nil {
		disposition = *res.Disposition
	}
	return
}

// Opnum 7
func (r *RPCCon) DeleteKey(hKey []byte, name string) (err error) {
	if len(hKey) != 20 {
		return fmt.Errorf("Invalid length of HKey in DeleteKey")
	}
	req := BaseRegDeleteKeyReq{
		SubKey: newRRPString(name),
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to delete registry key (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegDeleteKey, reqBuf)
	if err != nil {
		return
	}
	if len(buffer) < 4 {
		err = fmt.Errorf("Response to BaseRegDeleteKey was too short")
		log.Errorln(err)
		return
	}
	returnCode := binary.LittleEndian.Uint32(buffer[:4])
	if returnCode != ErrorSuccess {
		if returnCode == ErrorFileNotFound {
			err = fmt.Errorf("Registry Key does not exist")
		} else {
			err = ReturnCodeMap[returnCode]
			log.Errorln(err)
		}
		return
	}
	return
}

// Opnum 8
func (r *RPCCon) DeleteValue(hKey []byte, name string) (err error) {
	if len(hKey) != 20 {
		return fmt.Errorf("Invalid length of HKey in DeleteValue")
	}
	req := BaseRegDeleteValueReq{
		ValueName: newRRPString(name),
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to delete registry key value (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegDeleteValue, reqBuf)
	if err != nil {
		return
	}
	if len(buffer) < 4 {
		err = fmt.Errorf("Response to BaseRegDeleteValue was too short")
		log.Errorln(err)
		return
	}
	returnCode := binary.LittleEndian.Uint32(buffer[:4])
	if returnCode != ErrorSuccess {
		if returnCode == ErrorFileNotFound {
			err = fmt.Errorf("Registry value does not exist")
		} else {
			err = ReturnCodeMap[returnCode]
			log.Errorln(err)
		}
		return
	}
	return
}

// Opnum 9
func (r *RPCCon) EnumKey(hKey []byte, index uint32) (info *KeyInfo, err error) {
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in EnumKey")
		return
	}
	req := BaseRegEnumKeyReq{
		Index:         index,
		NameIn:        newRRPInBuffer(256),
		ClassIn:       newRRPInBufferPtr(256),
		LastWriteTime: &mstypes.FileTime{LowDateTime: 1, HighDateTime: 2},
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to enumerate subkey (%d) for key handle (0x%x)\n", index, hKey)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegEnumKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegEnumKeyRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	info = &KeyInfo{
		KeyName: res.NameOut.Value,
	}
	if res.ClassOut != nil {
		info.ClassName = res.ClassOut.Value
	}
	return
}

// Opnum 10
func (r *RPCCon) EnumValue(hKey []byte, index uint32) (value *ValueInfo, err error) {

	keyType := uint32(1024)
	maxLen := uint32(4096)
	dataLen := uint32(0)
	req := BaseRegEnumValueReq{
		Index:   index,
		NameIn:  rrpInBufferString{MaximumLength: 4096},
		Type:    &keyType,
		MaxLen:  &maxLen,
		DataLen: &dataLen,
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to enumerate value name for index (%d) for key handle (0x%x)\n", index, hKey)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegEnumValue, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegEnumValueRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode == ErrorMoreData {
		log.Debugln("EnumValue failed with ERROR_MORE_DATA. Making another request with a larger buffer.")
		// Make another request with the correct buffer size
		req.MaxLen = res.DataLen
		reqBuf, err = req.Marshal()
		if err != nil {
			log.Errorln(err)
			return
		}
		buffer, err = r.MakeRequest(BaseRegEnumValue, reqBuf)
		if err != nil {
			log.Errorln(err)
			return
		}
		res = BaseRegEnumValueRes{}
		err = res.Unmarshal(buffer)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if res.ReturnCode != ErrorSuccess {
		if res.ReturnCode == ErrorMoreData {
			log.Debugf("EnumValue failed with ERROR_MORE_DATA. Here is the response: %+v\n", res)
		}
		err = ReturnCodeMap[res.ReturnCode]
		log.Errorf("EnumValue failed with return code: %s\n", err.Error())
		return
	}

	typeName, found := RegValueTypeMap[*res.Type]
	if !found {
		typeName = "<Unknown>"
	}
	value = &ValueInfo{
		Name:     res.NameOut.Value,
		Type:     *res.Type,
		TypeName: typeName,
		ValueLen: *res.DataLen,
		Value:    res.Data,
	}
	return
}

func NewAce(sidStr string, mask uint32, aceType, aceFlags byte) (ace *msdtyp.ACE, err error) {
	sid, err := msdtyp.ConvertStrToSID(sidStr)
	if err != nil {
		log.Errorln(err)
		return
	}
	return &msdtyp.ACE{
		Header: msdtyp.ACEHeader{
			Type:  aceType,
			Flags: aceFlags,
			Size:  uint16(sid.NumAuth*4 + 16),
		},
		Mask: mask,
		Sid:  *sid,
	}, nil
}

func NewACL(acls []msdtyp.ACE) (acl *msdtyp.PACL) {
	numAcls := len(acls)
	aceSize := uint16(8)
	for _, ace := range acls {
		aceSize += ace.Header.Size
	}

	return &msdtyp.PACL{
		AclRevision: 2, // NT4
		AclSize:     aceSize,
		AceCount:    uint32(numAcls),
		ACLS:        acls,
	}
}

func NewSecurityDescriptor(control uint16, owner, group *msdtyp.SID, dacl, sacl *msdtyp.PACL) (sd *msdtyp.SecurityDescriptor, err error) {
	sd = &msdtyp.SecurityDescriptor{
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
		sd.Control |= msdtyp.SecurityDescriptorFlagSP
		sd.OffsetSacl = offset
		offset += uint32(sacl.AclSize)
	}
	if dacl != nil {
		sd.Dacl = dacl
		sd.Control |= msdtyp.SecurityDescriptorFlagDP
		sd.OffsetDacl = offset
	}

	return
}

func (r *RPCCon) OpenSubKey(hKey []byte, subkey string) ([]byte, error) {
	return r.OpenSubKeyExt(hKey, subkey, 0, PermMaximumAllowed)
}

func (r *RPCCon) OpenSubKeyExt(hKey []byte, subkey string, opts, desiredAccess uint32) (handle []byte, err error) {
	if desiredAccess == 0 {
		desiredAccess = PermMaximumAllowed
	}
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in OpenSubKeyExt")
		return
	}
	req := BaseRegOpenKeyReq{
		SubKey:        newRRPString(subkey),
		Options:       opts,
		DesiredAccess: desiredAccess,
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to open subkey (%s)\n", subkey)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegOpenKey, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Retrieve context handle from response
	res := OpenKeyRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		status, found := ReturnCodeMap[res.ReturnCode]
		if !found {
			err = fmt.Errorf("Received unknown return code in BaseRegOpenKey response: 0x%x\n", res.ReturnCode)
			log.Errorln(err)
			return
		}
		err = status
		return
	}

	handle = res.HKey[:]
	return
}

func (r *RPCCon) QueryKeyInfo(hKey []byte) (info *KeyInfo, err error) {
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in QueryKeyInfo")
		return
	}
	req := BaseRegQueryInfoKeyReq{
		ClassIn: newRRPStringBuffer(18),
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to Query key info for key handle (0x%x)\n", hKey)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegQueryInfoKey, reqBuf)
	if err != nil {
		return
	}

	res := BaseRegQueryInfoKeyRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
	}

	info = &KeyInfo{
		ClassName:       res.ClassOut.Value,
		SubKeys:         res.SubKeys,
		MaxSubKeyLen:    res.MaxSubKeyLen,
		MaxClassLen:     res.MaxClassLen,
		Values:          res.Values,
		MaxValueNameLen: res.MaxValueNameLen,
		MaxValueLen:     res.MaxValueLen,
	}
	if len(info.ClassName) > 0 {
		info.ClassName = info.ClassName[:len(info.ClassName)-1] // Remove null byte
	}

	return
}

func (r *RPCCon) QueryValueExt(hKey []byte, name string) (result any, dataType uint32, err error) {
	var data []byte
	data, dataType, _, err = r.QueryValue2(hKey, name)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch dataType {
	case RegNone:
		result = data
	case RegSz, RegExpandSz:
		var s string
		s, err = msdtyp.FromUnicodeString(data)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Optionally remove null terminator
		if s[len(s)-1] == 0x00 {
			s = s[:len(s)-1]
		}
		result = s
		return
	case RegBinary:
		result = data
	case RegDword:
		if len(data) != 4 {
			err = fmt.Errorf("Invalid length for DWORD type registry value")
			log.Errorln(err)
			return
		}
		result = binary.LittleEndian.Uint32(data)
	case RegDwordBigEndian:
		if len(data) != 4 {
			err = fmt.Errorf("Invalid length for DWORD big endian type registry value")
			log.Errorln(err)
			return
		}
		result = binary.BigEndian.Uint32(data)
	//case RegLink:
	case RegMultiSz:
		result, err = fromUnicodeStrArray(data)
		if err != nil {
			log.Errorln(err)
			return
		}
	case RegQword:
		if len(data) != 8 {
			err = fmt.Errorf("Invalid length for QWORD type registry value")
			log.Errorln(err)
			return
		}
		result = binary.LittleEndian.Uint64(data)
	default:
		log.Errorf("Unknown type %d of registry value", dataType)
		result = data
	}
	return
}

func (r *RPCCon) QueryValue2(hKey []byte, name string) (result []byte, dataType uint32, found bool, err error) {
	// If I send the parameter Data (lpData) as nil and the DataLen(lpcbData) and MaxSize(lpcbLen) to 0
	// The server will respond with the size of the requested value in the lpcbData parameter.

	name = msdtyp.NullTerminate(name)

	keyType := uint32(1024)
	maxLen := uint32(1024)
	dataLen := uint32(0)
	req := BaseRegQueryValueReq{
		ValueName: newRRPString(name),
		Type:      &keyType,
		Data:      nil,
		MaxLen:    &maxLen,
		DataLen:   &dataLen,
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegQueryValue, reqBuf)
	if err != nil {
		return
	}

	res := BaseRegQueryValueRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode == ErrorMoreData {
		log.Debugln("EnumValue failed with ERROR_MORE_DATA. Making another request with a larger buffer.")
		// Make another request with the correct buffer size
		req.MaxLen = res.DataLen
		reqBuf, err = req.Marshal()
		if err != nil {
			log.Errorln(err)
			return
		}
		buffer, err = r.MakeRequest(BaseRegQueryValue, reqBuf)
		if err != nil {
			log.Errorln(err)
			return
		}
		res = BaseRegQueryValueRes{}
		err = res.Unmarshal(buffer)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
		if err == ReturnCodeMap[ErrorFileNotFound] {
			if name == "" {
				err = fmt.Errorf("Default value has not been defined")
			} else {
				err = fmt.Errorf("Provided name of registry key value not found")
			}
		}
		log.Debugln(err)
		return
	}
	if res.Type != nil {
		dataType = *res.Type
	}

	return res.Data, dataType, true, nil
}

func (r *RPCCon) QueryValue(hKey []byte, name string) (result []byte, err error) {
	result, _, _, err = r.QueryValue2(hKey, name)
	return
}

func (r *RPCCon) QueryValueString(hKey []byte, name string) (result string, err error) {
	data, dataType, found, err := r.QueryValue2(hKey, name)
	if !found {
		// No need to log a missing reg key as an error here
		return
	}
	if err != nil {
		log.Errorln(err)
		return
	}
	if dataType != RegSz {
		err = fmt.Errorf("Registry value is not of type string")
		log.Errorln(err)
		return
	}

	// All strings in the registry should be null terminated
	// but not necessarily Unicode so this could be problematic
	return msdtyp.FromUnicodeString(data[:len(data)-2])
}

func (r *RPCCon) RegSaveKey(hKey []byte, filename string, owner string) (err error) {
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in RegSaveKey")
		return
	}
	var ownerSid *msdtyp.SID
	var acl *msdtyp.PACL

	// If owner is empty, use a default DACL and owner for the registry dump on disk
	if owner != "" {
		ownerSid, err = msdtyp.ConvertStrToSID(owner)
		if err != nil {
			log.Errorln(err)
			return
		}
		adminMask := PermGenericRead | PermGenericWrite | PermWriteDacl | PermDelete
		var adminAce *msdtyp.ACE
		adminAce, err = NewAce(owner, adminMask, msdtyp.AccessAllowedAceType, msdtyp.ContainerInheritAce)
		if err != nil {
			log.Errorln(err)
			return
		}
		acl = NewACL([]msdtyp.ACE{*adminAce})
	}
	sd, err := NewSecurityDescriptor(msdtyp.SecurityDescriptorFlagSR, ownerSid, nil, acl, nil)
	if err != nil {
		log.Errorln(err)
		return
	}
	sdBytes, err := sd.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	sdLen := uint32(len(sdBytes))
	sa := &RpcSecurityAttributes{
		SecurityDescriptor: RpcSecurityDescriptor{
			Data:    sdBytes,
			InSize:  sdLen,
			OutSize: sdLen,
		},
		InheritHandle: 0,
	}
	// Length is the total RPC_SECURITY_ATTRIBUTES size: SD bytes + the two
	// DWORD descriptor length fields + the Length field itself + the
	// 4-byte-aligned InheritHandle. Kept for wire parity with older builds.
	sa.Length = sdLen + 12 + 8

	req := BaseRegSaveKeyReq{
		FileName:           newRRPString(filename),
		SecurityAttributes: sa,
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to save reg key to file (%s)\n", filename)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegSaveKey, reqBuf)
	if err != nil {
		return
	}

	res := msdtyp.ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.Value() != ErrorSuccess {
		err = ReturnCodeMap[res.Value()]
	}

	return
}

func (r *RPCCon) GetKeySecurity(hKey []byte) (sd *msdtyp.SecurityDescriptor, err error) {
	return r.GetKeySecurityExt(hKey, OwnerSecurityInformation|GroupSecurityInformation|DACLSecurityInformation)
}

func (r *RPCCon) GetKeySecurityExt(hKey []byte, securityInformation uint32) (sd *msdtyp.SecurityDescriptor, err error) {
	if securityInformation == 0 {
		securityInformation = OwnerSecurityInformation
	}
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in GetKeySecurityExt")
		return
	}

	//TODO check if I can ask for size first and then send another request with that size
	// Suggest a pretty big security descriptor like 4096 bytes, but check if server responds with error
	// that the buffer was too small and if so, send another request with as big of a buffer as the server demands
	req := BaseRegGetKeySecurityReq{
		SecurityInformation: securityInformation,
		SecurityDescriptorIn: RpcSecurityDescriptor{
			InSize: 4096,
		},
	}
	copy(req.HKey[:], hKey)

	//log.Debugf("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegGetKeySecurity, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := BaseRegGetKeySecurityRes{}
	err = res.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.ReturnCode != ErrorSuccess {
		err = ReturnCodeMap[res.ReturnCode]
		log.Errorln(err)
		return
	}
	log.Debugln("Successfully got the security information")
	if len(res.SecurityDescriptorOut.Data) == 0 {
		err = fmt.Errorf("BaseRegGetKeySecurity response contained an empty security descriptor")
		return
	}
	sdOut := &msdtyp.SecurityDescriptor{}
	if err = sdOut.UnmarshalBinary(res.SecurityDescriptorOut.Data); err != nil {
		log.Errorln(err)
		return
	}
	sd = sdOut

	return
}

func (r *RPCCon) SetKeySecurity(hKey []byte, sd *msdtyp.SecurityDescriptor) (err error) {
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in SetKeySecurity")
		return
	}
	sdBytes, err := sd.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	sdLen := uint32(len(sdBytes))
	req := BaseRegSetKeySecurityReq{
		SecurityDescriptorIn: RpcSecurityDescriptor{
			Data:    sdBytes,
			InSize:  sdLen,
			OutSize: sdLen,
		},
	}
	copy(req.HKey[:], hKey)
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

	//log.Debugf("Trying to Query key value for (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegSetKeySecurity, reqBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	res := msdtyp.ReturnCode{}
	err = res.UnmarshalBinary(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if res.Value() != ErrorSuccess {
		err = ReturnCodeMap[res.Value()]
	}
	log.Debugln("Successfully changed the SecurityDescriptor")
	return
}

func (r *RPCCon) GetSubKeyNames(hKey []byte, subkey string) ([]string, error) {
	return r.GetSubKeyNamesExt(hKey, subkey, 0, PermMaximumAllowed)
}

func (r *RPCCon) GetSubKeyNamesExt(hKey []byte, subkey string, opts, desiredAccess uint32) (names []string, err error) {
	var hSubKey []byte
	if subkey != "" {
		hSubKey, err = r.OpenSubKeyExt(hKey, subkey, opts, desiredAccess)
		if err != nil {
			log.Errorln(err)
			return
		}
		defer r.CloseKeyHandle(hSubKey)
	} else {
		hSubKey = hKey
	}
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

		name := res2.KeyName
		names = append(names, name)
	}

	return
}

func (r *RPCCon) GetKeyValues(hKey []byte) (items []ValueInfo, err error) {
	res, err := r.QueryKeyInfo(hKey)
	if err != nil {
		log.Errorln(err)
		return
	}

	items = make([]ValueInfo, 0, res.Values)
	for i := uint32(0); i < res.Values; i++ {
		value, err := r.EnumValue(hKey, i)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		value.Name = value.Name[:len(value.Name)-1]
		items = append(items, *value)
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
		name := value.Name
		names = append(names, name[:len(name)-1])
	}
	return
}

func (r *RPCCon) SetValue(hKey []byte, name string, value any, dataType uint32) (err error) {
	name = msdtyp.NullTerminate(name)
	var data []byte
	switch dataType {
	case RegSz:
		s, ok := value.(string)
		if !ok {
			err = fmt.Errorf("Provided value is not of type string")
			log.Errorln(err)
			return
		}
		data = msdtyp.ToUnicode(msdtyp.NullTerminate(s))
	//case RegExpandSz:
	case RegBinary:
		b, ok := value.([]byte)
		if !ok {
			err = fmt.Errorf("Provided value is not of type []byte")
			log.Errorln(err)
			return
		}
		data = b
	case RegDword:
		d, ok := value.(uint32)
		if !ok {
			err = fmt.Errorf("Provided value is not of type uint32")
			log.Errorln(err)
			return
		}
		data = make([]byte, 4)
		binary.LittleEndian.PutUint32(data, d)
	case RegDwordBigEndian:
		d, ok := value.(uint32)
		if !ok {
			err = fmt.Errorf("Provided value is not of type uint32")
			log.Errorln(err)
			return
		}
		data = make([]byte, 4)
		binary.BigEndian.PutUint32(data, d)
	//case RegLink:
	//case RegMultiSz:
	case RegQword:
		d, ok := value.(uint64)
		if !ok {
			err = fmt.Errorf("Provided value is not of type uint64")
			log.Errorln(err)
			return
		}
		data = make([]byte, 8)
		binary.LittleEndian.PutUint64(data, d)
	default:
		err = fmt.Errorf("Unknown type %d of registry value", dataType)
		log.Errorln(err)
		return
	}
	if len(hKey) != 20 {
		err = fmt.Errorf("Invalid length of HKey in SetValue")
		return
	}
	req := BaseRegSetValueReq{
		ValueName: newRRPString(name),
		Type:      dataType,
		Data:      data,
		DataLen:   uint32(len(data)),
	}
	copy(req.HKey[:], hKey)

	log.Debugf("Trying to Set the key value for (%s)\n", name)
	reqBuf, err := req.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := r.MakeRequest(BaseRegSetValue, reqBuf)
	if err != nil {
		return
	}

	if len(buffer) < 4 {
		err = fmt.Errorf("Response to BaseRegSetValue was too short")
		log.Errorln(err)
		return
	}
	returnCode := binary.LittleEndian.Uint32(buffer[:4])
	if returnCode != ErrorSuccess {
		err = ReturnCodeMap[returnCode]
		log.Errorln(err)
		return
	}

	return
}
