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

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
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
	HKey       [20]byte
	ReturnCode uint32
}

// Opnum 5
type BaseRegCloseKeyReq struct {
	HKey [20]byte
}

// RpcSecurityDescriptor mirrors MS-RRP 2.2.8 RPC_SECURITY_DESCRIPTOR. Data is
// the marshaled msdtyp.SecurityDescriptor bytes; InSize is the buffer size
// allocated by the client (cbInSecurityDescriptor); OutSize is the transmitted
// length (cbOutSecurityDescriptor). Callers populate Data via
// msdtyp.SecurityDescriptor.MarshalBinary and parse it back with
// msdtyp.SecurityDescriptor.UnmarshalBinary.
type RpcSecurityDescriptor struct {
	Data    []byte `ndr:"pointer,fullpointer,conformant,varying,maxcount:InSize"`
	InSize  uint32
	OutSize uint32
}

// RpcSecurityAttributes mirrors MS-DTYP RPC_SECURITY_ATTRIBUTES as used by
// MS-RRP BaseRegCreateKey and BaseRegSaveKey. InheritHandle is encoded as a
// single byte (BOOLEAN); NDR alignment pads it to the 4-byte boundary before
// the deferred SecurityDescriptor body.
type RpcSecurityAttributes struct {
	Length             uint32
	SecurityDescriptor RpcSecurityDescriptor
	InheritHandle      byte
}

// Opnum 6
type BaseRegCreateKeyReq struct {
	HKey          [20]byte
	SubKey        mstypes.RPCUnicodeString `ndr:"toplevel"` // [in] PRRP_UNICODE_STRING (ref)
	Class         mstypes.RPCUnicodeString `ndr:"toplevel"` // [in] PRRP_UNICODE_STRING (ref)
	Options       uint32
	DesiredAccess uint32                 // REGSAM
	SecurityAttr  *RpcSecurityAttributes `ndr:"toplevel,fullpointer"` // [in, unique] PRPC_SECURITY_ATTRIBUTES
	Disposition   *uint32                `ndr:"toplevel,fullpointer"` // [in, out, unique] LPDWORD
}

// Opnum 6
type BaseRegCreateKeyRes struct {
	HKey        [20]byte
	Disposition *uint32 `ndr:"toplevel,fullpointer"`
	ReturnCode  uint32
}

// Opnum 7
type BaseRegDeleteKeyReq struct {
	HKey   [20]byte
	SubKey mstypes.RPCUnicodeString `ndr:"toplevel"`
}

// Opnum 8
type BaseRegDeleteValueReq struct {
	HKey      [20]byte
	ValueName mstypes.RPCUnicodeString `ndr:"toplevel"`
}

// rrpInBufferString mirrors the wire format of an RRP/RPC_UNICODE_STRING used
// as an [in,out] buffer reservation parameter, where the client must always
// emit a non-NULL Buffer pointer (with an empty conformant body) so the server
// has somewhere to write its output. Standard mstypes.RPCUnicodeString writes
// a NULL pointer when the Go string is empty, which does not match the
// MS-RRP buffer-reservation convention; the notnullptr tag forces a non-NULL
// referent ID even for the zero-value string.
type rrpInBufferString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        string `ndr:"pointer,notnullptr,conformant,varying,skipnull,maxcount:MaximumLength"`
}

// Opnum 9
type BaseRegEnumKeyReq struct {
	HKey          [20]byte
	Index         uint32
	NameIn        rrpInBufferString  `ndr:"toplevel"`             // [in] PRRP_UNICODE_STRING (ref)
	ClassIn       *rrpInBufferString `ndr:"toplevel,fullpointer"` // [in,out,unique] PRPC_UNICODE_STRING
	LastWriteTime *mstypes.FileTime  `ndr:"toplevel,fullpointer"` // [in,out,unique] PFILETIME
}

type BaseRegEnumKeyRes struct {
	NameOut       mstypes.RPCUnicodeString  `ndr:"toplevel"`             // [out] PRPC_UNICODE_STRING (ref)
	ClassOut      *mstypes.RPCUnicodeString `ndr:"toplevel,fullpointer"` // [in,out,unique] PRPC_UNICODE_STRING
	LastWriteTime *mstypes.FileTime         `ndr:"toplevel,fullpointer"` // [in,out,unique] PFILETIME
	ReturnCode    uint32
}

// Opnum 10
type BaseRegEnumValueReq struct {
	HKey    [20]byte
	Index   uint32
	NameIn  rrpInBufferString `ndr:"toplevel"`
	Type    *uint32           `ndr:"toplevel,fullpointer"`
	Data    []byte            `ndr:"toplevel,fullpointer,conformant,varying,maxcount:MaxLen"` // Need ReferentId ptr, maxCount, offset and actualCount
	MaxLen  *uint32           `ndr:"toplevel,fullpointer"`                                    // How many bytes are allocated .e.g., ActualSize or ActualCount
	DataLen *uint32           `ndr:"toplevel,fullpointer"`                                    // How many bytes are transmitted in Data. E.g., ActualSize
}

type BaseRegEnumValueRes struct {
	/*NOTE that NameOut according to MS-RRP is an RPC_UNICODE_STRING which is
	 * defined in MS-DTYP Section 2.3.10 RPC_UNICODE_STRING and as such MUST NOT
	 * be null-terminated. However, of course Microsoft's implementation of SMB
	 * null terminates the names...
	 */
	NameOut    mstypes.RPCUnicodeString `ndr:"toplevel"` // Cannot be null terminated?
	Type       *uint32                  `ndr:"toplevel,fullpointer"`
	Data       []byte                   `ndr:"toplevel,fullpointer,conformant,varying"`
	DataLen    *uint32                  `ndr:"toplevel,fullpointer"`
	MaxLen     *uint32                  `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

// Opnum 12
type BaseRegGetKeySecurityReq struct {
	HKey                 [20]byte
	SecurityInformation  uint32
	SecurityDescriptorIn RpcSecurityDescriptor `ndr:"toplevel"` // [in, out] PRPC_SECURITY_DESCRIPTOR (ref)
}

type BaseRegGetKeySecurityRes struct {
	SecurityDescriptorOut RpcSecurityDescriptor `ndr:"toplevel"` // [out] PRPC_SECURITY_DESCRIPTOR (ref)
	ReturnCode            uint32
}

// Opnum 15
type BaseRegOpenKeyReq struct {
	HKey          [20]byte
	SubKey        mstypes.RPCUnicodeString `ndr:"toplevel"`
	Options       uint32
	DesiredAccess uint32 // REGSAM
}

// Opnum 16
type BaseRegQueryInfoKeyReq struct {
	HKey    [20]byte
	ClassIn mstypes.RPCUnicodeString `ndr:"toplevel"` // Optional, can be null
}

type BaseRegQueryInfoKeyRes struct {
	ClassOut           mstypes.RPCUnicodeString `ndr:"toplevel"`
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
	HKey      [20]byte
	ValueName mstypes.RPCUnicodeString `ndr:"toplevel"`
	Type      *uint32                  `ndr:"toplevel,fullpointer"`
	Data      []byte                   `ndr:"toplevel,fullpointer,conformant,varying,maxcount:MaxLen"` // Need ReferentId ptr, maxCount, offset and actualCount
	MaxLen    *uint32                  `ndr:"toplevel,fullpointer"`                                    // How many bytes are allocated .e.g., ActualSize or ActualCount
	DataLen   *uint32                  `ndr:"toplevel,fullpointer"`                                    // How many bytes are transmitted in Data. E.g., ActualSize
}

type BaseRegQueryValueRes struct {
	Type       *uint32 `ndr:"toplevel,fullpointer"`
	Data       []byte  `ndr:"toplevel,fullpointer,conformant,varying"`
	DataLen    *uint32 `ndr:"toplevel,fullpointer"`
	MaxLen     *uint32 `ndr:"toplevel,fullpointer"`
	ReturnCode uint32
}

// Opnum 20
type BaseRegSaveKeyReq struct {
	HKey               [20]byte
	FileName           mstypes.RPCUnicodeString `ndr:"toplevel"`             // [in] PRRP_UNICODE_STRING (ref)
	SecurityAttributes *RpcSecurityAttributes   `ndr:"toplevel,fullpointer"` // [in, unique] PRPC_SECURITY_ATTRIBUTES
}

// Opnum 21
type BaseRegSetKeySecurityReq struct {
	HKey                 [20]byte
	SecurityInformation  uint32
	SecurityDescriptorIn RpcSecurityDescriptor `ndr:"toplevel"` // [in] PRPC_SECURITY_DESCRIPTOR (ref)
}

// Opnum 22
type BaseRegSetValueReq struct {
	HKey      [20]byte
	ValueName mstypes.RPCUnicodeString `ndr:"toplevel"` // [in] PRRP_UNICODE_STRING (ref)
	Type      uint32                   // [in] DWORD
	Data      []byte                   `ndr:"toplevel,conformant"` // [in, size_is(cbData)] LPBYTE (ref conformant array)
	DataLen   uint32                   // [in] DWORD cbData
}

// Opnums 0-4
func (s *OpenRootKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for OpenRootKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling OpenRootKeyReq: %w", err)
	}
	return b, nil
}

func (s *OpenKeyRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for OpenKeyRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling OpenKeyRes: %w", err)
	}
	return nil
}

// Opnum 5
func (s *BaseRegCloseKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegCloseKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegCloseKeyReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegCreateKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegCreateKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegCreateKeyReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegCreateKeyRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for BaseRegCreateKeyRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegCreateKeyRes: %w", err)
	}
	return nil
}

func (s *BaseRegDeleteKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegDeleteKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegDeleteKeyReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegDeleteValueReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegDeleteValueReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegDeleteValueReq: %w", err)
	}
	return b, nil
}

// Opnum 9
func (s *BaseRegEnumKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegEnumKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegEnumKeyReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegEnumKeyRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for BaseRegEnumKeyRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegEnumKeyRes: %w", err)
	}
	return nil
}

// Opnum 10
func (s *BaseRegEnumValueReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegEnumValueReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegEnumValueReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegEnumValueRes) Unmarshal(buf []byte) error {
	if len(buf) < 36 {
		return fmt.Errorf("Buffer to short for BaseRegEnumValueRes")
	}
	log.Traceln("In Unmarshal for BaseRegEnumValueRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegEnumValueRes: %w", err)
	}
	return nil
}

// Opnum 12
func (s *BaseRegGetKeySecurityReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegGetKeySecurityReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegGetKeySecurityReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegGetKeySecurityRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for BaseRegGetKeySecurityRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegGetKeySecurityRes: %w", err)
	}
	return nil
}

// Opnum 15
func (s *BaseRegOpenKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegOpenKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegOpenKeyReq: %w", err)
	}
	return b, nil
}

// Opnum 16
func (s *BaseRegQueryInfoKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegQueryInfoKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegQueryInfoKeyReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegQueryInfoKeyRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for BaseRegQueryInfoKeyRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegQueryInfoKeyRes: %w", err)
	}
	return nil
}

// Opnum 17
func (s *BaseRegQueryValueReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegQueryValueReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegQueryValueReq: %w", err)
	}
	return b, nil
}

func (s *BaseRegQueryValueRes) Unmarshal(buf []byte) error {
	log.Traceln("In Unmarshal for BaseRegQueryValueRes")
	dec := ndr.NewDecoder(bytes.NewReader(buf), false)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling BaseRegQueryValueRes: %w", err)
	}
	return nil
}

// Opnum 20
func (s *BaseRegSaveKeyReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegSaveKeyReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegSaveKeyReq: %w", err)
	}
	return b, nil
}

// Opnum 21
func (s *BaseRegSetKeySecurityReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegSetKeySecurityReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegSetKeySecurityReq: %w", err)
	}
	return b, nil
}

// Opnum 22
func (s *BaseRegSetValueReq) Marshal() ([]byte, error) {
	log.Traceln("In Marshal for BaseRegSetValueReq")
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling BaseRegSetValueReq: %w", err)
	}
	return b, nil
}
