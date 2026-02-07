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
//
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package mslsad

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

// MS-LSAT opnum 45
type LsarGetUserNameReq struct {
	SystemName string                     `ndr:"toppointer,fullpointer,conformant,varying"`
	UserName   *mstypes.PRPCUnicodeString `ndr:"toppointer"` // Top-level ref ptr, so can never be NULL
	DomainName *mstypes.PRPCUnicodeString `ndr:"toppointer,fullpointer"`
}

// MS-LSAT opnum 45
type LsarGetUserNameRes struct {
	UserName   *mstypes.PRPCUnicodeString `ndr:"toppointer"` // Top-level ref ptr, so can never be NULL
	DomainName *mstypes.PRPCUnicodeString `ndr:"toppointer,fullpointer"`
	ReturnCode uint32
}

//[in, unique, string] wchar_t* SystemName,
//[in, out] PRPC_UNICODE_STRING* UserName,
//[in, out, unique] PRPC_UNICODE_STRING* DomainName
//);

// MS-LSAT opnum 57
type LsarLookupSids2Req struct {
	PolicyHandle    []byte
	SidEnumBuffer   LsaprSidEnumBuffer     `ndr:"toppointer"`
	TranslatedNames LsaprTranslatedNamesEx `ndr:"toppointer"`
	LookupLevel     LsapLookupLevel
	MappedCount     uint32 `ndr:"toppointer"`
	LookupOptions   uint32 // Must be 0
	ClientRevision  uint32
}

// MS-LSAT opnum 57
type LsarLookupSids2Res struct {
	ReferencedDomains PlsaprReferencedDomainList `ndr:"toppointer"`
	TranslatedNames   LsaprTranslatedNamesEx     `ndr:"toppointer"`
	MappedCount       uint32                     `ndr:"toppointer"`
	ReturnCode        uint32
}

//NTSTATUS LsarLookupSids2(
//[in] LSAPR_HANDLE PolicyHandle,
//[in] PLSAPR_SID_ENUM_BUFFER SidEnumBuffer,
//[out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
//[in, out] PLSAPR_TRANSLATED_NAMES_EX TranslatedNames,
//[in] LSAP_LOOKUP_LEVEL LookupLevel,
//[in, out] unsigned long* MappedCount,
//[in] unsigned long LookupOptions,
//[in] unsigned long ClientRevision
//);

// MS-LSAT opnum 68
type LsarLookupNames3Req struct {
	PolicyHandle   []byte
	Count          uint32
	Names          []mstypes.RPCUnicodeString `ndr:"toppointer,conformant"`
	TranslatedSids LsaprTranslatedSidsEx2     `ndr:"toppointer"`
	LookupLevel    LsapLookupLevel
	MappedCount    uint32 `ndr:"toppointer"`
	LookupOptions  uint32
	ClientRevision uint32
}

// MS-LSAT opnum 68
type LsarLookupNames3Res struct {
	ReferencedDomains PlsaprReferencedDomainList `ndr:"toppointer"`
	TranslatedSids    LsaprTranslatedSidsEx2     `ndr:"toppointer"`
	MappedCount       uint32                     `ndr:"toppointer"`
	ReturnCode        uint32
}

//NTSTATUS LsarLookupNames3(
//[in] LSAPR_HANDLE PolicyHandle,
//[in, range(0,1000)] unsigned long Count,
//[in, size_is(Count)] PRPC_UNICODE_STRING Names,
//[out] PLSAPR_REFERENCED_DOMAIN_LIST* ReferencedDomains,
//[in, out] PLSAPR_TRANSLATED_SIDS_EX2 TranslatedSids,
//[in] LSAP_LOOKUP_LEVEL LookupLevel,
//[in, out] unsigned long* MappedCount,
//[in] unsigned long LookupOptions,
//[in] unsigned long ClientRevision
//);

type LsaprSidInformation struct {
	Sid mstypes.RPCSID `ndr:"pointer"`
}

//typedef struct _LSAPR_SID_INFORMATION {
//PRPC_SID Sid;
//} LSAPR_SID_INFORMATION, *PLSAPR_SID_INFORMATION;

type LsaprSidEnumBuffer struct {
	Entries uint32
	SidInfo []LsaprSidInformation `ndr:"pointer,conformant"`
}

//typedef struct _LSAPR_SID_ENUM_BUFFER {
//unsigned long Entries = {3};
//[size_is(Entries)] PLSAPR_SID_INFORMATION SidInfo;
//} LSAPR_SID_ENUM_BUFFER, *PLSAPR_SID_ENUM_BUFFER;

type LsaprTranslatedNameEx struct {
	Use         SidNameUse
	Name        mstypes.RPCUnicodeString
	DomainIndex int32
	Flags       uint32
}

//typedef struct _LSAPR_TRANSLATED_NAME_EX {
//SID_NAME_USE Use;
//RPC_UNICODE_STRING Name;
//long DomainIndex;
//unsigned long Flags;
//} LSAPR_TRANSLATED_NAME_EX,
//*PLSAPR_TRANSLATED_NAME_EX;

type LsaprTranslatedNamesEx struct {
	Entries uint32
	Names   []LsaprTranslatedNameEx `ndr:"pointer,conformant"`
}

//typedef struct _LSAPR_TRANSLATED_NAMES_EX {
//[range(0,20480)] unsigned long Entries;
//[size_is(Entries)] PLSAPR_TRANSLATED_NAME_EX Names;
//} LSAPR_TRANSLATED_NAMES_EX,
//*PLSAPR_TRANSLATED_NAMES_EX;

type LsaprTrustInformation struct {
	Name mstypes.RPCUnicodeString
	Sid  mstypes.RPCSID `ndr:"pointer"`
}

//typedef struct _LSAPR_TRUST_INFORMATION {
//RPC_UNICODE_STRING Name;
//PRPC_SID Sid;
//} LSAPR_TRUST_INFORMATION,
//*PLSAPR_TRUST_INFORMATION;

type LsaprReferencedDomainList struct {
	Entries    uint32
	Domains    []LsaprTrustInformation `ndr:"pointer,conformant"`
	MaxEntries uint32                  // This field MUST be ignored. The content is unspecified
}

type PlsaprReferencedDomainList struct {
	LsaprReferencedDomainList `ndr:"pointer"`
}

//typedef struct _LSAPR_REFERENCED_DOMAIN_LIST {
//unsigned long Entries;
//[size_is(Entries)] PLSAPR_TRUST_INFORMATION Domains;
//unsigned long MaxEntries;
//} LSAPR_REFERENCED_DOMAIN_LIST,
//*PLSAPR_REFERENCED_DOMAIN_LIST;

type LsaprTranslatedSidEx2 struct {
	Use         SidNameUse
	Sid         mstypes.RPCSID `ndr:"pointer"` // Pointer?
	DomainIndex int32
	Flags       uint32
}

//typedef struct _LSAPR_TRANSLATED_SID_EX2 {
//SID_NAME_USE Use;
//PRPC_SID Sid;
//long DomainIndex;
//unsigned long Flags;
//} LSAPR_TRANSLATED_SID_EX2, *PLSAPR_TRANSLATED_SID_EX2;

type LsaprTranslatedSidsEx2 struct {
	Entries uint32
	Sids    []LsaprTranslatedSidEx2 `ndr:"pointer,conformant"`
}

//typedef struct _LSAPR_TRANSLATED_SIDS_EX2 {
//[range (0,1000)] unsigned long Entries;
//[size_is(Entries)] PLSAPR_TRANSLATED_SID_EX2 Sids;
//} LSAPR_TRANSLATED_SIDS_EX2, *PLSAPR_TRANSLATED_SIDS_EX2;

// Client struct
type DomainTranslation struct {
	Name string
	Sid  string
}

// Client struct
type SidNameTranslation struct {
	Use         SidNameUse
	Name        string
	Sid         string
	DomainIndex int32
	Flags       uint32
}

// Client struct
type SidTranslations struct {
	ReferencedDomains []DomainTranslation
	TranslatedNames   []SidNameTranslation
	ReturnCode        uint32
}

// Client struct
type NameTranslations struct {
	ReferencedDomains []DomainTranslation
	TranslatedSids    []SidNameTranslation
	ReturnCode        uint32
}

func (self *LsarGetUserNameReq) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarGetUserNameReq: %v", err)
	}
	return
}

func (self *LsarGetUserNameReq) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarGetUserNameReq: %v", err)
	}
	return
}

func (self *LsarGetUserNameRes) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarGetUserNameRes: %v", err)
	}
	return
}

func (self *LsarGetUserNameRes) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarGetUserNameRes: %v", err)
	}
	return
}

func (self *LsarLookupSids2Req) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarLookupSids2Req: %v", err)
	}
	return
}

func (self *LsarLookupSids2Req) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarLookupSids2Req: %v", err)
	}
	return
}

func (self *LsarLookupSids2Res) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarLookupSids2Res: %v", err)
	}
	return
}

func (self *LsarLookupSids2Res) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarLookupSids2Res: %v", err)
	}
	return
}

func (self *LsarLookupNames3Req) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarLookupNames3Req: %v", err)
	}
	return
}

func (self *LsarLookupNames3Req) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarLookupNames3Req: %v", err)
	}
	return
}

func (self *LsarLookupNames3Res) Marshal() (b []byte, err error) {
	enc := ndr.NewEncoder(bytes.NewBuffer(([]byte{})), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err = enc.Encode(self)
	if err != nil {
		err = fmt.Errorf("error marshaling LsarLookupNames3Res: %v", err)
	}
	return
}

func (self *LsarLookupNames3Res) Unmarshal(b []byte) (err error) {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err = dec.Decode(self)
	if err != nil {
		err = fmt.Errorf("error unmarshaling LsarLookupNames3Res: %v", err)
	}
	return
}
