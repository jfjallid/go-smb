// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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
// MS-DCOM structures for Distributed COM Object RPC.
// References: [MS-DCOM] Sections 2.2.x

package msdcom

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/msdcom").SetDisplayName("msdcom")
	le  binary.ByteOrder = binary.LittleEndian
)

// GUIDFromString converts a UUID string (e.g. "000001a0-0000-0000-c000-000000000046")
// to a 16-byte binary GUID in MS wire format (little-endian Data1/Data2/Data3).
func GUIDFromString(s string) ([16]byte, error) {
	var g [16]byte
	b, err := dcerpc.UUIDToBin(s)
	if err != nil {
		return g, err
	}
	if len(b) != 16 {
		return g, fmt.Errorf("UUID binary must be 16 bytes, got %d", len(b))
	}
	copy(g[:], b)
	return g, nil
}

// COMVERSION (MS-DCOM 2.2.11)
type COMVERSION struct {
	MajorVersion uint16
	MinorVersion uint16
}

// MarshalBinary serializes COMVERSION to 4 bytes.
func (v COMVERSION) MarshalBinary() []byte {
	buf := make([]byte, 4)
	le.PutUint16(buf[0:2], v.MajorVersion)
	le.PutUint16(buf[2:4], v.MinorVersion)
	return buf
}

// UnmarshalCOMVERSION parses a COMVERSION from buf.
func UnmarshalCOMVERSION(buf []byte) (COMVERSION, error) {
	if len(buf) < 4 {
		return COMVERSION{}, fmt.Errorf("COMVERSION: buffer too short (%d < 4)", len(buf))
	}
	return COMVERSION{
		MajorVersion: le.Uint16(buf[0:2]),
		MinorVersion: le.Uint16(buf[2:4]),
	}, nil
}

// ORPCTHIS flags (MS-DCOM 2.2.13)
const (
	ORPCFlagsLocal uint32 = 0x00000001 // ORPCFLAGS_REQUEST_LOCAL
)

// ORPCTHIS (MS-DCOM 2.2.13) — prepended to every DCOM request stub.
// When extensions is NULL (the common case), this is 32 bytes.
type ORPCTHIS struct {
	Version     COMVERSION // {5, 7}
	Flags       uint32
	Reserved1   uint32
	CausalityId [16]byte // Random, constant per DCOM session
}

// MarshalBinary serializes ORPCTHIS to 32 bytes (with NULL extensions pointer).
func (o *ORPCTHIS) MarshalBinary() []byte {
	buf := make([]byte, 32)
	copy(buf[0:4], o.Version.MarshalBinary())
	le.PutUint32(buf[4:8], o.Flags)
	le.PutUint32(buf[8:12], o.Reserved1)
	copy(buf[12:28], o.CausalityId[:])
	// extensions pointer = NULL (bytes 28-31 are zero)
	return buf
}

// ORPCTHISSize is the marshaled size of ORPCTHIS with NULL extensions.
const ORPCTHISSize = 32

// ORPCTHAT (MS-DCOM 2.2.14) — prepended to every DCOM response stub.
type ORPCTHAT struct {
	Flags      uint32
	Extensions []byte // Raw extension data (may be nil if pointer was NULL)
}

// UnmarshalORPCTHAT parses an ORPCTHAT from buf and returns it along with
// the number of bytes consumed.
func UnmarshalORPCTHAT(buf []byte) (ORPCTHAT, int, error) {
	if len(buf) < 8 {
		return ORPCTHAT{}, 0, fmt.Errorf("ORPCTHAT: buffer too short (%d < 8)", len(buf))
	}
	result := ORPCTHAT{
		Flags: le.Uint32(buf[0:4]),
	}
	extPtr := le.Uint32(buf[4:8])
	offset := 8

	if extPtr != 0 {
		// Parse and skip ORPC_EXTENT_ARRAY
		consumed, err := skipORPCExtentArray(buf[offset:])
		if err != nil {
			return ORPCTHAT{}, 0, fmt.Errorf("ORPCTHAT extensions: %w", err)
		}
		result.Extensions = buf[offset : offset+consumed]
		offset += consumed
	}

	return result, offset, nil
}

// skipORPCExtentArray parses enough of an ORPC_EXTENT_ARRAY to skip over it.
// Returns the number of bytes consumed.
//
// ORPC_EXTENT_ARRAY (MS-DCOM 2.2.21.2):
//
//	unsigned long size                                           (4)
//	unsigned long reserved                                      (4)
//	[size_is((size+1)&~1), unique] ORPC_EXTENT** extent         (4, referent ID)
//	If extent non-null, deferred conformant array:
//	  max_count                                                  (4)
//	  [max_count] ORPC_EXTENT* referent IDs                     (4 each)
//	  For each non-null referent, deferred ORPC_EXTENT body
//
// ORPC_EXTENT (MS-DCOM 2.2.21.1) is a conformant struct:
//
//	data_max_count (hoisted from data[])                         (4)
//	GUID id                                                      (16)
//	unsigned long size                                           (4)
//	byte data[data_max_count]
func skipORPCExtentArray(buf []byte) (int, error) {
	if len(buf) < 12 {
		return 0, fmt.Errorf("ORPC_EXTENT_ARRAY: buffer too short (%d < 12)", len(buf))
	}
	//_ = le.Uint32(buf[0:4]) // size
	//_ = le.Uint32(buf[4:8]) // reserved
	extentPtr := le.Uint32(buf[8:12])
	offset := 12

	if extentPtr == 0 {
		return offset, nil
	}

	// Deferred conformant array of [unique] ORPC_EXTENT* pointers
	if len(buf) < offset+4 {
		return 0, fmt.Errorf("ORPC_EXTENT_ARRAY: buffer too short for max_count")
	}
	maxCount := le.Uint32(buf[offset:])
	offset += 4

	// Read referent IDs for each array element
	refIdEnd := offset + int(maxCount)*4
	if len(buf) < refIdEnd {
		return 0, fmt.Errorf("ORPC_EXTENT_ARRAY: buffer too short for referent IDs")
	}
	refIDs := make([]uint32, maxCount)
	for i := uint32(0); i < maxCount; i++ {
		refIDs[i] = le.Uint32(buf[offset:])
		offset += 4
	}

	// Deferred ORPC_EXTENT bodies for non-null referents.
	// ORPC_EXTENT is a conformant struct, so max_count for data[] is
	// hoisted before the struct fields.
	for i := uint32(0); i < maxCount; i++ {
		if refIDs[i] == 0 {
			continue
		}
		// data_max_count(4) + GUID(16) + size(4) = 24 bytes minimum
		if len(buf) < offset+24 {
			return 0, fmt.Errorf("ORPC_EXTENT: buffer too short at extent %d", i)
		}
		dataMaxCount := le.Uint32(buf[offset:])
		offset += 4
		offset += 16 // GUID id
		offset += 4  // size
		if len(buf) < offset+int(dataMaxCount) {
			return 0, fmt.Errorf("ORPC_EXTENT: buffer too short for extent data (%d)", i)
		}
		offset += int(dataMaxCount)
	}

	return offset, nil
}

// STDOBJREF (MS-DCOM 2.2.18.1) — Standard Object Reference, 40 bytes.
type STDOBJREF struct {
	Flags       uint32
	CPublicRefs uint32
	OXID        uint64
	OID         uint64
	IPID        [16]byte
}

// STDOBJREFSize is the marshaled size of a STDOBJREF.
const STDOBJREFSize = 40

// MarshalBinary serializes STDOBJREF to 40 bytes.
func (s *STDOBJREF) MarshalBinary() []byte {
	buf := make([]byte, STDOBJREFSize)
	le.PutUint32(buf[0:4], s.Flags)
	le.PutUint32(buf[4:8], s.CPublicRefs)
	le.PutUint64(buf[8:16], s.OXID)
	le.PutUint64(buf[16:24], s.OID)
	copy(buf[24:40], s.IPID[:])
	return buf
}

// UnmarshalSTDOBJREF parses a STDOBJREF from buf.
func UnmarshalSTDOBJREF(buf []byte) (STDOBJREF, error) {
	if len(buf) < STDOBJREFSize {
		return STDOBJREF{}, fmt.Errorf("STDOBJREF: buffer too short (%d < %d)", len(buf), STDOBJREFSize)
	}
	var s STDOBJREF
	s.Flags = le.Uint32(buf[0:4])
	s.CPublicRefs = le.Uint32(buf[4:8])
	s.OXID = le.Uint64(buf[8:16])
	s.OID = le.Uint64(buf[16:24])
	copy(s.IPID[:], buf[24:40])
	return s, nil
}

// DUALSTRINGARRAY (MS-DCOM 2.2.19.1)
type DUALSTRINGARRAY struct {
	NumEntries     uint16
	SecurityOffset uint16
	StringArray    []uint16 // NumEntries uint16 values
}

// StringBinding represents a parsed string binding entry from a DUALSTRINGARRAY.
type StringBinding struct {
	TowerId uint16
	Address string
}

// SecurityBinding represents a parsed security binding entry from a DUALSTRINGARRAY.
type SecurityBinding struct {
	AuthnSvc  uint16
	AuthzSvc  uint16
	Principal string
}

// UnmarshalDUALSTRINGARRAY parses a DUALSTRINGARRAY from buf.
// Returns the parsed structure and the number of bytes consumed.
func UnmarshalDUALSTRINGARRAY(buf []byte) (DUALSTRINGARRAY, int, error) {
	if len(buf) < 4 {
		return DUALSTRINGARRAY{}, 0, fmt.Errorf("DUALSTRINGARRAY: buffer too short (%d < 4)", len(buf))
	}
	dsa := DUALSTRINGARRAY{
		NumEntries:     le.Uint16(buf[0:2]),
		SecurityOffset: le.Uint16(buf[2:4]),
	}

	arrayBytes := int(dsa.NumEntries) * 2
	if len(buf) < 4+arrayBytes {
		return DUALSTRINGARRAY{}, 0, fmt.Errorf("DUALSTRINGARRAY: buffer too short for array (%d < %d)", len(buf), 4+arrayBytes)
	}

	dsa.StringArray = make([]uint16, dsa.NumEntries)
	for i := 0; i < int(dsa.NumEntries); i++ {
		dsa.StringArray[i] = le.Uint16(buf[4+i*2 : 4+i*2+2])
	}

	return dsa, 4 + arrayBytes, nil
}

// MarshalBinary serializes DUALSTRINGARRAY.
func (d *DUALSTRINGARRAY) MarshalBinary() []byte {
	buf := make([]byte, 4+int(d.NumEntries)*2)
	le.PutUint16(buf[0:2], d.NumEntries)
	le.PutUint16(buf[2:4], d.SecurityOffset)
	for i, v := range d.StringArray {
		le.PutUint16(buf[4+i*2:4+i*2+2], v)
	}
	return buf
}

// ParseStringBindings extracts StringBinding entries from the string binding
// portion of the DUALSTRINGARRAY (before SecurityOffset).
func (d *DUALSTRINGARRAY) ParseStringBindings() []StringBinding {
	var bindings []StringBinding
	arr := d.StringArray
	if int(d.SecurityOffset) < len(arr) {
		arr = arr[:d.SecurityOffset]
	}

	i := 0
	for i < len(arr) {
		towerId := arr[i]
		if towerId == 0 {
			// Null terminator for string bindings section
			break
		}
		i++
		// Read null-terminated UTF-16 string
		start := i
		for i < len(arr) && arr[i] != 0 {
			i++
		}
		// Convert uint16 slice to string
		runes := make([]rune, i-start)
		for j := start; j < i; j++ {
			runes[j-start] = rune(arr[j])
		}
		bindings = append(bindings, StringBinding{
			TowerId: towerId,
			Address: string(runes),
		})
		if i < len(arr) {
			i++ // skip null terminator
		}
	}
	return bindings
}

// ParseSecurityBindings extracts SecurityBinding entries from the security
// binding portion of the DUALSTRINGARRAY (after SecurityOffset).
func (d *DUALSTRINGARRAY) ParseSecurityBindings() []SecurityBinding {
	var bindings []SecurityBinding
	if int(d.SecurityOffset) >= len(d.StringArray) {
		return bindings
	}
	arr := d.StringArray[d.SecurityOffset:]

	i := 0
	for i < len(arr) {
		authnSvc := arr[i]
		if authnSvc == 0 {
			break
		}
		if i+1 >= len(arr) {
			break
		}
		authzSvc := arr[i+1]
		i += 2
		// Read null-terminated principal string
		start := i
		for i < len(arr) && arr[i] != 0 {
			i++
		}
		runes := make([]rune, i-start)
		for j := start; j < i; j++ {
			runes[j-start] = rune(arr[j])
		}
		bindings = append(bindings, SecurityBinding{
			AuthnSvc:  authnSvc,
			AuthzSvc:  authzSvc,
			Principal: string(runes),
		})
		if i < len(arr) {
			i++ // skip null terminator
		}
	}
	return bindings
}

// OBJREF flags (MS-DCOM 2.2.18)
const (
	OBJREFSignature uint32 = 0x574f454d // "MEOW"

	OBJREFStandard uint32 = 0x00000001
	OBJREFHandler  uint32 = 0x00000002
	OBJREFCustom   uint32 = 0x00000004
)

// OBJREF (MS-DCOM 2.2.18) — Object Reference.
type OBJREF struct {
	Signature uint32
	Flags     uint32
	IID       [16]byte

	// Only one of the following is set, depending on Flags:
	Std    *STDOBJREF        // OBJREF_STANDARD
	StdDSA *DUALSTRINGARRAY  // OBJREF_STANDARD: resolver string bindings
	Custom *OBJREFCustomData // OBJREF_CUSTOM
}

// OBJREFCustomData holds the fields for an OBJREF with OBJREF_CUSTOM flag.
type OBJREFCustomData struct {
	CLSID       [16]byte
	CbExtension uint32
	Size        uint32
	Data        []byte // The custom marshaled data
}

// UnmarshalOBJREF parses an OBJREF from buf. Returns the parsed OBJREF
// and the number of bytes consumed.
func UnmarshalOBJREF(buf []byte) (OBJREF, int, error) {
	if len(buf) < 24 {
		return OBJREF{}, 0, fmt.Errorf("OBJREF: buffer too short (%d < 24)", len(buf))
	}

	var obj OBJREF
	obj.Signature = le.Uint32(buf[0:4])
	if obj.Signature != OBJREFSignature {
		return OBJREF{}, 0, fmt.Errorf("OBJREF: invalid signature 0x%08x (expected 0x%08x)", obj.Signature, OBJREFSignature)
	}
	obj.Flags = le.Uint32(buf[4:8])
	copy(obj.IID[:], buf[8:24])

	offset := 24

	switch obj.Flags {
	case OBJREFStandard:
		if len(buf) < offset+STDOBJREFSize {
			return OBJREF{}, 0, fmt.Errorf("OBJREF_STANDARD: buffer too short for STDOBJREF")
		}
		std, err := UnmarshalSTDOBJREF(buf[offset:])
		if err != nil {
			return OBJREF{}, 0, err
		}
		obj.Std = &std
		offset += STDOBJREFSize

		dsa, n, err := UnmarshalDUALSTRINGARRAY(buf[offset:])
		if err != nil {
			return OBJREF{}, 0, fmt.Errorf("OBJREF_STANDARD DUALSTRINGARRAY: %w", err)
		}
		obj.StdDSA = &dsa
		offset += n

	case OBJREFCustom:
		if len(buf) < offset+36 {
			return OBJREF{}, 0, fmt.Errorf("OBJREF_CUSTOM: buffer too short for header")
		}
		custom := &OBJREFCustomData{}
		copy(custom.CLSID[:], buf[offset:offset+16])
		custom.CbExtension = le.Uint32(buf[offset+16 : offset+20])
		custom.Size = le.Uint32(buf[offset+20 : offset+24])
		offset += 24

		// Skip extension data if present
		offset += int(custom.CbExtension)

		// The size field may include the cbExtension(4) + size(4) fields
		// themselves (Windows convention). Use the remaining
		// buffer as the actual data length when size exceeds it.
		dataLen := int(custom.Size)
		remaining := len(buf) - offset
		if dataLen > remaining {
			dataLen = remaining
		}
		if dataLen < 0 {
			return OBJREF{}, 0, fmt.Errorf("OBJREF_CUSTOM: buffer too short for data (%d)", custom.Size)
		}
		custom.Data = make([]byte, dataLen)
		copy(custom.Data, buf[offset:offset+dataLen])
		offset += dataLen
		obj.Custom = custom

	case OBJREFHandler:
		return OBJREF{}, 0, fmt.Errorf("OBJREF_HANDLER not implemented")

	default:
		return OBJREF{}, 0, fmt.Errorf("OBJREF: unknown flags 0x%08x", obj.Flags)
	}

	return obj, offset, nil
}

// MInterfacePointer (MS-DCOM 2.2.20) — NDR-encoded wrapper for OBJREF.
// Wire format:
//
//	uint32 ulCntData (conformant max_count)
//	uint32 ulCntData (actual size field)
//	[ulCntData]byte abData (OBJREF)
type MInterfacePointer struct {
	CntData uint32
	Data    []byte // Contains a marshaled OBJREF
}

// UnmarshalMInterfacePointer parses an MInterfacePointer from buf.
// Returns the parsed structure and the number of bytes consumed.
func UnmarshalMInterfacePointer(buf []byte) (MInterfacePointer, int, error) {
	if len(buf) < 8 {
		return MInterfacePointer{}, 0, fmt.Errorf("MInterfacePointer: buffer too short (%d < 8)", len(buf))
	}

	maxCount := le.Uint32(buf[0:4])
	cntData := le.Uint32(buf[4:8])
	offset := 8

	// Use the smaller of maxCount and cntData for safety
	size := cntData
	if maxCount < size {
		size = maxCount
	}

	if len(buf) < offset+int(size) {
		return MInterfacePointer{}, 0, fmt.Errorf("MInterfacePointer: buffer too short for data (%d < %d)", len(buf), offset+int(size))
	}

	mip := MInterfacePointer{
		CntData: cntData,
		Data:    make([]byte, size),
	}
	copy(mip.Data, buf[offset:offset+int(size)])
	offset += int(size)

	return mip, offset, nil
}

// MarshalMInterfacePointer serializes an MInterfacePointer.
func MarshalMInterfacePointer(data []byte) []byte {
	size := uint32(len(data))
	buf := make([]byte, 8+len(data))
	le.PutUint32(buf[0:4], size) // conformant max_count
	le.PutUint32(buf[4:8], size) // ulCntData
	copy(buf[8:], data)
	return buf
}

// REMQIRESULT (MS-DCOM 2.2.23) — result from RemQueryInterface.
type REMQIRESULT struct {
	HResult uint32
	Std     STDOBJREF
}

// UnmarshalREMQIRESULT parses a REMQIRESULT from buf.
func UnmarshalREMQIRESULT(buf []byte) (REMQIRESULT, error) {
	if len(buf) < 4+STDOBJREFSize {
		return REMQIRESULT{}, fmt.Errorf("REMQIRESULT: buffer too short (%d < %d)", len(buf), 4+STDOBJREFSize)
	}
	r := REMQIRESULT{
		HResult: le.Uint32(buf[0:4]),
	}
	std, err := UnmarshalSTDOBJREF(buf[4:])
	if err != nil {
		return REMQIRESULT{}, err
	}
	r.Std = std
	return r, nil
}

// REMQIRESULTSize is the marshaled size of a REMQIRESULT.
const REMQIRESULTSize = 4 + STDOBJREFSize

// REMINTERFACEREF (MS-DCOM 2.2.24) — used in RemRelease.
type REMINTERFACEREF struct {
	IPID         [16]byte
	CPublicRefs  uint32
	CPrivateRefs uint32
}

// MarshalBinary serializes a REMINTERFACEREF to 24 bytes.
func (r *REMINTERFACEREF) MarshalBinary() []byte {
	buf := make([]byte, 24)
	copy(buf[0:16], r.IPID[:])
	le.PutUint32(buf[16:20], r.CPublicRefs)
	le.PutUint32(buf[20:24], r.CPrivateRefs)
	return buf
}

// Well-known protocol sequence tower IDs for DUALSTRINGARRAY
const (
	TowerIDTCP   uint16 = 7  // ncacn_ip_tcp
	TowerIDNPipe uint16 = 15 // ncacn_np
)

// --- Generic helpers ---

func mustGUID(s string) [16]byte {
	g, err := GUIDFromString(s)
	if err != nil {
		panic("invalid GUID: " + s + ": " + err.Error())
	}
	return g
}

// MarshalOBJREFCustom builds an OBJREF with OBJREF_CUSTOM flag.
func MarshalOBJREFCustom(iid, clsid [16]byte, data []byte) []byte {
	buf := make([]byte, 0, 48+len(data))

	buf = binary.LittleEndian.AppendUint32(buf, OBJREFSignature)   // "MEOW"
	buf = binary.LittleEndian.AppendUint32(buf, OBJREFCustom)      // flags
	buf = append(buf, iid[:]...)                                   // IID
	buf = append(buf, clsid[:]...)                                 // CLSID
	buf = binary.LittleEndian.AppendUint32(buf, 0)                 // cbExtension
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(data))) // size
	buf = append(buf, data...)                                     // data

	return buf
}

// MarshalBSTRBody marshals a string as a FLAGGED_WORD_BLOB body (the deferred
// part of a BSTR unique pointer, per MS-OAUT 2.2.23.2.1).
//
// MS-OAUT 2.2.23.1:
//
//	typedef struct _FLAGGED_WORD_BLOB {
//	    unsigned long cBytes;
//	    unsigned long clSize;
//	    [size_is(clSize)] unsigned short asData[];
//	} FLAGGED_WORD_BLOB;
//
// Wire format (conformant struct):
//
//	uint32 maxCount  (hoisted conformant dimension = clSize)
//	uint32 cBytes    (size in bytes of asData)
//	uint32 clSize    (number of unsigned shorts in asData)
//	[]uint16 asData  (UTF-16LE characters, NOT null-terminated)
func MarshalBSTRBody(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	charCount := uint32(len(u16))

	buf := make([]byte, 0, 12+int(charCount)*2)
	buf = binary.LittleEndian.AppendUint32(buf, charCount)   // maxCount (hoisted conformant dimension)
	buf = binary.LittleEndian.AppendUint32(buf, charCount*2) // cBytes: byte count of string data
	buf = binary.LittleEndian.AppendUint32(buf, charCount)   // clSize (struct field)
	for _, ch := range u16 {
		buf = binary.LittleEndian.AppendUint16(buf, ch)
	}
	return buf
}

// MarshalLPWSTRBody marshals a string as a conformant varying wide string
// (the deferred part of a [unique, string] wchar_t* pointer).
// This encoding is used for WMI [string] BSTR parameters where the [string]
// attribute causes NDR to use conformant varying encoding rather than
// FLAGGED_WORD_BLOB.
//
// Wire format:
//
//	uint32 maxCount     (conformant max, includes null terminator)
//	uint32 offset       (always 0)
//	uint32 actualCount  (same as maxCount for full strings)
//	[]uint16 data       (UTF-16LE characters + null terminator)
func MarshalLPWSTRBody(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	strLen := uint32(len(u16) + 1) // +1 for null terminator

	buf := make([]byte, 0, 12+int(strLen)*2)
	buf = binary.LittleEndian.AppendUint32(buf, strLen) // maxCount
	buf = binary.LittleEndian.AppendUint32(buf, 0)      // offset
	buf = binary.LittleEndian.AppendUint32(buf, strLen) // actualCount
	for _, ch := range u16 {
		buf = binary.LittleEndian.AppendUint16(buf, ch)
	}
	buf = binary.LittleEndian.AppendUint16(buf, 0) // null terminator
	return buf
}

func padTo4(data []byte) []byte {
	remainder := len(data) % 4
	if remainder == 0 {
		return data
	}
	padding := 4 - remainder
	return append(data, make([]byte, padding)...)
}

func padTo8(data []byte) []byte {
	remainder := len(data) % 8
	if remainder == 0 {
		return data
	}
	padding := 8 - remainder
	return append(data, make([]byte, padding)...)
}

func padTo8Size(n int) int {
	remainder := n % 8
	if remainder == 0 {
		return n
	}
	return n + 8 - remainder
}
