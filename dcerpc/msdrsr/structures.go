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

package msdrsr

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"

	"github.com/jfjallid/ndr"
)

// Well-known attribute IDs (MS-DRSR / MS-ADA*)
type ATTRTYP uint32

const (
	AttUserAccountControl      ATTRTYP = 589832
	AttDBCSPwd                 ATTRTYP = 589879
	AttUnicodePwd              ATTRTYP = 589914
	AttNTPwdHistory            ATTRTYP = 589918
	AttPwdLastSet              ATTRTYP = 589920
	AttSupplementalCredentials ATTRTYP = 589949
	AttObjectSid               ATTRTYP = 589970
	AttAccountExpires          ATTRTYP = 589983
	AttLMPwdHistory            ATTRTYP = 589984
	AttSAMAccountName          ATTRTYP = 590045
	AttSAMAccountType          ATTRTYP = 590126
	AttSidHistory              ATTRTYP = 590433
	AttUserPrincipalName       ATTRTYP = 590480
)

// DRSExtensionsInt represents DRS_EXTENSIONS_INT (MS-DRSR 4.1.10.2.7).
// This is a variable-length structure where the cb field determines which
// fields are present.
type DRSExtensionsInt struct {
	Flags            uint32
	SiteObjGuid      [16]byte
	Pid              uint32
	ReplicationEpoch uint32
	FlagsExt         uint32
	ConfigObjGuid    [16]byte
}

// Marshal serializes DRS_EXTENSIONS_INT as the opaque blob payload carried
// inside DRS_EXTENSIONS.rgb. Hand-coded because the wire format is variable-
// length and not strictly NDR (cb governs which trailing fields are present).
func (e *DRSExtensionsInt) Marshal() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 52))
	binary.Write(w, le, e.Flags)
	w.Write(e.SiteObjGuid[:])
	binary.Write(w, le, e.Pid)
	binary.Write(w, le, e.ReplicationEpoch)
	binary.Write(w, le, e.FlagsExt)
	w.Write(e.ConfigObjGuid[:])
	return w.Bytes(), nil
}

func (e *DRSExtensionsInt) Unmarshal(data []byte) error {
	r := bytes.NewReader(data)
	// DRS_EXTENSIONS_INT is variable-length: cb governs which trailing fields are
	// present, so a short blob legitimately omits later fields (they stay zero).
	// Each read is gated by a cumulative length check, so the reads below cannot
	// short-read; the error checks are defensive against future reordering.
	if len(data) >= 4 {
		if err := binary.Read(r, le, &e.Flags); err != nil {
			return err
		}
	}
	if len(data) >= 20 {
		if _, err := io.ReadFull(r, e.SiteObjGuid[:]); err != nil {
			return err
		}
	}
	if len(data) >= 24 {
		if err := binary.Read(r, le, &e.Pid); err != nil {
			return err
		}
	}
	if len(data) >= 28 {
		if err := binary.Read(r, le, &e.ReplicationEpoch); err != nil {
			return err
		}
	}
	if len(data) >= 32 {
		if err := binary.Read(r, le, &e.FlagsExt); err != nil {
			return err
		}
	}
	if len(data) >= 48 {
		if _, err := io.ReadFull(r, e.ConfigObjGuid[:]); err != nil {
			return err
		}
	}
	return nil
}

// DSNAME represents a directory object name (MS-DRSR 4.1.10.2.9).
//
// IDL: struct { ULONG StructLen; ULONG SidLen; GUID Guid; NT4SID Sid;
//
//	ULONG NameLen; [size_is(NameLen+1)] WCHAR StringName[]; }
//
// StringName is a conformant-ONLY (not varying) WCHAR array: the NDR wire
// format places the hoisted max_count at the struct head and then writes the
// UTF-16 code units directly, with no offset/actual_count header. To achieve
// this, StringName is stored as []uint16 (a conformant primitive slice) —
// using a `string` field would trigger ndr's conformant-varying string path
// and emit an extra 8-byte offset/count header that the IDL does not allow.
// Use Name()/SetName() for Go string interop.
type DSNAME struct {
	StructLen  uint32
	SidLen     uint32
	Guid       [16]byte
	Sid        [28]byte // Fixed 28-byte buffer, zero-padded
	NameLen    uint32   // Character count NOT including null terminator
	StringName []uint16 `ndr:"conformant"`
}

// Name returns StringName as a Go string, stripping any trailing null.
func (d *DSNAME) Name() string {
	if len(d.StringName) == 0 {
		return ""
	}
	end := len(d.StringName)
	if d.StringName[end-1] == 0 {
		end--
	}
	return string(utf16.Decode(d.StringName[:end]))
}

// SetName sets StringName from a Go string (adding a trailing null terminator)
// and recomputes NameLen and StructLen so they are consistent for marshaling.
func (d *DSNAME) SetName(name string) {
	d.StringName = append(utf16.Encode([]rune(name)), 0)
	d.NameLen = uint32(len(name))
	d.StructLen = 56 + 2*uint32(len(d.StringName))
}

// ATTRVAL represents a single attribute value (MS-DRSR 4.1.10.2.2).
// IDL: struct { ULONG valLen; [size_is(valLen)] BYTE* pVal; }
type ATTRVAL struct {
	ValLen uint32
	PVal   []byte `ndr:"pointer,conformant,maxcount:ValLen"`
}

// ATTRVALBLOCK represents a block of attribute values (MS-DRSR 4.1.10.2.3).
// IDL: struct { ULONG valCount; [size_is(valCount)] ATTRVAL* pAVal; }
type ATTRVALBLOCK struct {
	ValCount uint32
	PVal     []ATTRVAL `ndr:"pointer,conformant,maxcount:ValCount"`
}

// ATTR represents a single attribute with its type and values (MS-DRSR 4.1.10.2.4).
type ATTR struct {
	AttrTyp ATTRTYP
	AttrVal ATTRVALBLOCK
}

// ATTRBLOCK represents a block of attributes (MS-DRSR 4.1.10.2.5).
// IDL: struct { ULONG attrCount; [size_is(attrCount)] ATTR* pAttr; }
type ATTRBLOCK struct {
	AttrCount uint32
	PAttr     []ATTR `ndr:"pointer,fullpointer,conformant,maxcount:AttrCount"`
}

// ENTINF represents a replicated directory entry with its attributes (MS-DRSR 4.1.10.2.10).
type ENTINF struct {
	PName     *DSNAME `ndr:"pointer"`
	UlFlags   uint32
	AttrBlock ATTRBLOCK
}

// USNVector represents a replication cursor (MS-DRSR 4.1.10.2.18).
// All-int64 struct: ndr's structAlignment=8 handles the 8-byte alignment.
type USNVector struct {
	UsnHighObjUpdate  int64
	UsnReserved       int64
	UsnHighPropUpdate int64
}

// UPTODATEVectorV1 — MS-DRSR 4.1.10.2.19 UPTODATE_VECTOR_V1_EXT.
// Returned by DRS_MSG_GETCHGREPLY_V1.
type UPTODATEVectorV1 struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	Cursors  []UPTODATECursorV1 `ndr:"conformant,maxcount:Count"`
}

// UPTODATECursorV1 — MS-DRSR 4.1.10.2.20 UPTODATE_CURSOR_V1.
type UPTODATECursorV1 struct {
	UuidDsa           [16]byte
	UsnHighPropUpdate int64
}

// UPTODATEVectorV2 represents the up-to-date vector for replication cursors.
// IDL: conformant struct with [size_is(cNumCursors)] rgCursors[]
type UPTODATEVectorV2 struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	Cursors  []UPTODATECursorV2 `ndr:"conformant,maxcount:Count"`
}

// UPTODATECursorV2 represents a single replication cursor entry.
type UPTODATECursorV2 struct {
	UuidDsa             [16]byte
	UsnHighPropUpdate   int64
	TimeLastSyncSuccess int64
}

// OIDPrefix represents a single entry in the prefix table (MS-DRSR 4.1.10.2.13).
// IDL: struct { DWORD ndxVal; [range(0,10000)] DWORD length;
//
//	[size_is(length)] BYTE* element; }
type OIDPrefix struct {
	NdxVal    uint32
	PrefixLen uint32
	Prefix    []byte `ndr:"pointer,conformant,maxcount:PrefixLen"`
}

// SchemaPrefixTable maps server-local ATTRTYP values to OID-based attribute IDs (MS-DRSR 4.1.10.2.14).
// IDL: struct { DWORD PrefixCount; [size_is(PrefixCount)] PrefixTableEntry* pPrefixEntry; }
type SchemaPrefixTable struct {
	PrefixCount uint32
	Entries     []OIDPrefix `ndr:"pointer,fullpointer,conformant,maxcount:PrefixCount"`
}

// PropertyMetaDataExt — MS-DRSR 4.1.10.2.16 PROPERTY_META_DATA_EXT.
type PropertyMetaDataExt struct {
	DwVersion          uint32
	FTimeChanged       int64 // FILETIME (8-byte aligned)
	UuidDsaOriginating [16]byte
	UsnOriginating     int64 // USN (8-byte aligned)
}

// PropertyMetaDataExtVector — MS-DRSR 4.1.10.2.17 PROPERTY_META_DATA_EXT_VECTOR.
// IDL: conformant struct with [size_is(cNumProps)] rgMetaData[]
type PropertyMetaDataExtVector struct {
	CNumProps  uint32
	RgMetaData []PropertyMetaDataExt `ndr:"conformant,maxcount:CNumProps"`
}

// AttIdFromPrefixTable resolves a server-local ATTRTYP to a well-known ATTRTYP
// using the prefix table. If the attribute is not found in the prefix table,
// the original value is returned unchanged.
func (pt *SchemaPrefixTable) AttIdFromPrefixTable(attTyp ATTRTYP) ATTRTYP {
	// The ATTRTYP encodes the prefix table index in the upper 16 bits
	// and the last OID component in the lower 16 bits.
	prefixIdx := uint32(attTyp) / 65536
	lastValue := uint32(attTyp) % 65536

	for i := range pt.Entries {
		if pt.Entries[i].NdxVal == prefixIdx {
			// Reconstruct the full OID and compute the well-known ATTRTYP
			oid := oidFromPrefix(pt.Entries[i].Prefix, lastValue)
			return attTypFromOid(oid)
		}
	}

	// If not found in prefix table, return as-is (may already be well-known)
	return attTyp
}

// MakeAttId creates a server-local ATTRTYP for a given well-known ATTRTYP
// using this prefix table. Returns 0 if the prefix is not in the table.
func (pt *SchemaPrefixTable) MakeAttId(wellKnown ATTRTYP) (ATTRTYP, bool) {
	oid := oidForAttTyp(wellKnown)
	if oid == nil {
		return 0, false
	}

	// Split OID: prefix is all but last component
	if len(oid) < 2 {
		return 0, false
	}
	lastValue := oid[len(oid)-1]
	prefixOid := oid[:len(oid)-1]
	prefixBytes := encodeOIDPrefix(prefixOid)

	for i := range pt.Entries {
		if bytes.Equal(pt.Entries[i].Prefix, prefixBytes) {
			return ATTRTYP(pt.Entries[i].NdxVal*65536 + lastValue), true
		}
	}

	return 0, false
}

// oidFromPrefix reconstructs an OID uint32 slice from a BER-encoded prefix
// and the last value component.
func oidFromPrefix(prefix []byte, lastValue uint32) []uint32 {
	if len(prefix) == 0 {
		return nil
	}

	var oid []uint32
	// First byte encodes first two components: val = c1*40 + c2
	first := uint32(prefix[0])
	oid = append(oid, first/40, first%40)

	var val uint32
	for i := 1; i < len(prefix); i++ {
		b := prefix[i]
		if b&0x80 != 0 {
			val = (val << 7) | uint32(b&0x7f)
		} else {
			val = (val << 7) | uint32(b)
			oid = append(oid, val)
			val = 0
		}
	}

	oid = append(oid, lastValue)
	return oid
}

// encodeOIDPrefix BER-encodes an OID component slice (without the last component).
func encodeOIDPrefix(components []uint32) []byte {
	if len(components) < 2 {
		return nil
	}

	var buf []byte
	buf = append(buf, byte(components[0]*40+components[1]))

	for i := 2; i < len(components); i++ {
		buf = appendBERComponent(buf, components[i])
	}

	return buf
}

func appendBERComponent(buf []byte, val uint32) []byte {
	if val < 0x80 {
		return append(buf, byte(val))
	}

	// Count number of 7-bit groups needed
	var groups []byte
	for v := val; v > 0; v >>= 7 {
		groups = append(groups, byte(v&0x7f))
	}

	// Reverse and set high bits
	for i := len(groups) - 1; i >= 0; i-- {
		b := groups[i]
		if i > 0 {
			b |= 0x80
		}
		buf = append(buf, b)
	}

	return buf
}

// Well-known OIDs for common AD attributes.
// These are under 2.5.4.* and 1.2.840.113556.1.4.*
var wellKnownAttrs = map[ATTRTYP][]uint32{
	AttUserAccountControl:      {1, 2, 840, 113556, 1, 4, 8},
	AttDBCSPwd:                 {1, 2, 840, 113556, 1, 4, 55},
	AttUnicodePwd:              {1, 2, 840, 113556, 1, 4, 90},
	AttNTPwdHistory:            {1, 2, 840, 113556, 1, 4, 94},
	AttPwdLastSet:              {1, 2, 840, 113556, 1, 4, 96},
	AttSupplementalCredentials: {1, 2, 840, 113556, 1, 4, 125},
	AttObjectSid:               {1, 2, 840, 113556, 1, 4, 146},
	AttAccountExpires:          {1, 2, 840, 113556, 1, 4, 159},
	AttLMPwdHistory:            {1, 2, 840, 113556, 1, 4, 160},
	AttSAMAccountName:          {1, 2, 840, 113556, 1, 4, 221},
	AttSAMAccountType:          {1, 2, 840, 113556, 1, 4, 302},
	AttSidHistory:              {1, 2, 840, 113556, 1, 4, 609},
	AttUserPrincipalName:       {1, 2, 840, 113556, 1, 4, 656},
}

func oidForAttTyp(att ATTRTYP) []uint32 {
	return wellKnownAttrs[att]
}

func attTypFromOid(oid []uint32) ATTRTYP {
	for att, knownOid := range wellKnownAttrs {
		if oidEqual(oid, knownOid) {
			return att
		}
	}
	// If not recognized, compute a synthetic ATTRTYP
	// Use the last component directly
	if len(oid) > 0 {
		return ATTRTYP(oid[len(oid)-1])
	}
	return 0
}

func oidEqual(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PartialAttrSet represents PARTIAL_ATTR_VECTOR_V1_EXT (MS-DRSR 4.1.10.2.12).
// PartialAttrSet — MS-DRSR 4.1.10.2.12 PARTIAL_ATTR_VECTOR_V1_EXT.
// IDL: conformant struct with [size_is(cAttrs)] rgPartialAttr[]
type PartialAttrSet struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	Attrs    []ATTRTYP `ndr:"conformant,maxcount:Count"`
}

func (p *PartialAttrSet) MarshalBinary() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 12+4*len(p.Attrs)))
	binary.Write(w, le, p.Version)
	binary.Write(w, le, p.Reserved)
	binary.Write(w, le, uint32(len(p.Attrs)))
	for _, a := range p.Attrs {
		binary.Write(w, le, uint32(a))
	}
	return w.Bytes(), nil
}

// buildPrefixTableAndConvertAttrs creates a SCHEMA_PREFIX_TABLE from the given
// well-known ATTRTYPs, assigning contiguous indices starting from 0.
// Returns the prefix table and the converted ATTRTYPs that use the table's indices.
// The server uses this table to interpret the ATTRTYPs in the partial attr set.
func buildPrefixTableAndConvertAttrs(attrs []ATTRTYP) (SchemaPrefixTable, []ATTRTYP) {
	prefixMap := make(map[string]uint32) // BER prefix bytes (as string key) → ndxVal
	var entries []OIDPrefix
	var nextIdx uint32

	convertedAttrs := make([]ATTRTYP, len(attrs))

	for i, att := range attrs {
		oid := oidForAttTyp(att)
		if len(oid) < 2 {
			// Unknown ATTRTYP — pass through unchanged
			convertedAttrs[i] = att
			continue
		}

		lastValue := oid[len(oid)-1]
		prefixOid := oid[:len(oid)-1]
		prefixBytes := encodeOIDPrefix(prefixOid)
		key := string(prefixBytes)

		ndx, ok := prefixMap[key]
		if !ok {
			ndx = nextIdx
			prefixMap[key] = ndx
			entries = append(entries, OIDPrefix{
				NdxVal:    ndx,
				PrefixLen: uint32(len(prefixBytes)),
				Prefix:    prefixBytes,
			})
			nextIdx++
		}

		convertedAttrs[i] = ATTRTYP(ndx*65536 + lastValue)
	}

	return SchemaPrefixTable{
		PrefixCount: uint32(len(entries)),
		Entries:     entries,
	}, convertedAttrs
}

func partialAttrSetForAttrs(flags DCSyncAttrs) *PartialAttrSet {
	attrList := []ATTRTYP{AttSAMAccountName, AttObjectSid}

	if flags.Has(AttrNTLM) {
		attrList = append(attrList, AttUnicodePwd, AttDBCSPwd)
	}
	if flags.Has(AttrHistory) {
		attrList = append(attrList, AttNTPwdHistory, AttLMPwdHistory, AttSidHistory)
	}
	if flags.Has(AttrMetadata) {
		attrList = append(attrList, AttUserAccountControl, AttSAMAccountType,
			AttUserPrincipalName, AttPwdLastSet, AttAccountExpires)
	}
	if flags.Has(AttrKerberos) {
		attrList = append(attrList, AttSupplementalCredentials)
	}
	return &PartialAttrSet{Version: 1, Count: uint32(len(attrList)), Attrs: attrList}
}

// buildGetNCChangesReqV8 assembles a DRSGetNCChangesReq with Version=8 and
// all V8 sub-structures populated: DSNAME for the NC, a prefix table keyed
// on the requested attributes, and a PartialAttrSet whose ATTRTYPs have
// been rewritten to use the prefix table indices.
func buildGetNCChangesReqV8(handle [20]byte, ncDN string, objectGuid [16]byte, dsaObjGuid [16]byte, extendedOp uint32, usnFrom USNVector, uptodateVec *UPTODATEVectorV2, attrs DCSyncAttrs) (*DRSGetNCChangesReq, error) {
	dsname := &DSNAME{Guid: objectGuid}
	dsname.SetName(ncDN)

	partialAttrs := partialAttrSetForAttrs(attrs)
	prefixTable, convertedAttrs := buildPrefixTableAndConvertAttrs(partialAttrs.Attrs)
	partialAttrs.Attrs = convertedAttrs
	partialAttrs.Count = uint32(len(convertedAttrs))

	var flags, cMaxObjects, cMaxBytes uint32
	if extendedOp == ExopReplObj {
		flags = DrsInitSync | DrsWritRep
		cMaxObjects = 1
		cMaxBytes = 0
	} else {
		flags = DrsInitSync | DrsWritRep | DrsNeverSynced | DrsFullSyncNow | DrsFullSyncInProgress
		cMaxObjects = 1000
		cMaxBytes = 0x00a00000
	}

	return &DRSGetNCChangesReq{
		HDrs:    handle,
		Version: 8,
		V8: DRSMsgGetChgReqV8{
			UuidDsaObjDest:    dsaObjGuid,
			UuidInvocIdSrc:    dsaObjGuid,
			PNC:               dsname,
			UsnvecFrom:        usnFrom,
			PUpToDateVecDest:  uptodateVec,
			UlFlags:           flags,
			CMaxObjects:       cMaxObjects,
			CMaxBytes:         cMaxBytes,
			UlExtendedOp:      extendedOp,
			LiFsmoInfo:        0,
			PPartialAttrSet:   partialAttrs,
			PPartialAttrSetEx: nil,
			PrefixTableDest:   prefixTable,
		},
	}, nil
}

// parseGuidString parses a GUID string like "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}"
// or "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" into a 16-byte array in mixed-endian format.
func parseGuidString(s string) ([16]byte, error) {
	var guid [16]byte

	s = strings.Trim(s, "{}")
	s = strings.ReplaceAll(s, "-", "")

	if len(s) != 32 {
		return guid, fmt.Errorf("invalid GUID string length: %d", len(s))
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return guid, fmt.Errorf("invalid GUID hex: %w", err)
	}

	// GUID is mixed-endian: first 3 groups are LE, last 2 are BE
	// Data1 (4 bytes LE)
	guid[0] = b[3]
	guid[1] = b[2]
	guid[2] = b[1]
	guid[3] = b[0]
	// Data2 (2 bytes LE)
	guid[4] = b[5]
	guid[5] = b[4]
	// Data3 (2 bytes LE)
	guid[6] = b[7]
	guid[7] = b[6]
	// Data4 (8 bytes, as-is)
	copy(guid[8:], b[8:])

	return guid, nil
}

// --- NDR-tagged wire types (ndr encoder migration) ---

// DRSExtensionsBlob mirrors DRS_EXTENSIONS (MS-DRSR 5.39): a conformant struct
// wrapping the opaque DRS_EXTENSIONS_INT capability blob. Callers must set Cb
// to len(Rgb) before encoding; the ndr library hoists the conformant max_count
// from Rgb automatically.
type DRSExtensionsBlob struct {
	Cb  uint32
	Rgb []byte `ndr:"conformant"`
}

// DRSBindReq — IDL_DRSBind request (opnum 0).
//
//	[in] UUID *puuidClientDsa,
//	[in] DRS_EXTENSIONS *pextClient
type DRSBindReq struct {
	PuuidClientDsa *[16]byte          `ndr:"toplevel,fullpointer"`
	PextClient     *DRSExtensionsBlob `ndr:"toplevel,fullpointer"`
}

// DRSBindRes — IDL_DRSBind response.
//
//	[out] DRS_EXTENSIONS **ppextServer,
//	[out, ref] DRS_HANDLE *phDrs
type DRSBindRes struct {
	PpextServer *DRSExtensionsBlob `ndr:"toplevel,fullpointer"`
	PhDrs       [20]byte
	ReturnCode  uint32
}

// DRSUnbindReq — IDL_DRSUnbind request (opnum 1): [in, out, ref] DRS_HANDLE *phDrs.
type DRSUnbindReq struct {
	PhDrs [20]byte
}

// DRSUnbindRes — IDL_DRSUnbind response.
type DRSUnbindRes struct {
	PhDrs      [20]byte
	ReturnCode uint32
}

// LPWSTR wraps a unique [string] WCHAR* pointer so arrays of string pointers
// (e.g. DRS_MSG_CRACKREQ_V1.rpNames) can be expressed as a slice of structs,
// each contributing one inline referent ID followed by a deferred conformant
// varying string. MS-RPC WCHAR** convention.
type LPWSTR struct {
	Value string `ndr:"pointer,conformant,varying"`
}

// DRSCrackNamesReq — IDL_DRSCrackNames request (opnum 12).
//
//	[in] DRS_HANDLE hDrs,
//	[in] DWORD dwInVersion,
//	[in, ref, switch_is(dwInVersion)] DRS_MSG_CRACKREQ *pmsgIn
//
// The non-encapsulated DRSMsgCrackReqUnion serializes its Level tag twice on
// the wire (once as dwInVersion, once as the union switch prefix), matching
// MS-RPCE 2.2.5.2.
type DRSCrackNamesReq struct {
	HDrs   [20]byte
	PmsgIn DRSMsgCrackReqUnion `ndr:"toplevel"`
}

type DRSMsgCrackReqUnion struct {
	Level  uint32           `ndr:"unionTag"`
	Level1 DRSMsgCrackReqV1 `ndr:"unionField"`
}

func (u DRSMsgCrackReqUnion) SwitchFunc(tag any) string {
	if tag.(uint32) == 1 {
		return "Level1"
	}
	return ""
}

// DRSMsgCrackReqV1 — MS-DRSR 4.1.4.1.1.
type DRSMsgCrackReqV1 struct {
	CodePage      uint32
	LocaleId      uint32
	DwFlags       uint32
	FormatOffered uint32
	FormatDesired uint32
	CNames        uint32
	RpNames       []LPWSTR `ndr:"pointer,conformant,maxcount:CNames"`
}

// DRSCrackNamesRes — IDL_DRSCrackNames response.
//
//	[out] DWORD *pdwOutVersion,
//	[out, ref, switch_is(*pdwOutVersion)] DRS_MSG_CRACKREPLY *pmsgOut
type DRSCrackNamesRes struct {
	PmsgOut    DRSMsgCrackReplyUnion `ndr:"toplevel"`
	ReturnCode uint32
}

type DRSMsgCrackReplyUnion struct {
	Level  uint32             `ndr:"unionTag"`
	Level1 DRSMsgCrackReplyV1 `ndr:"unionField"`
}

func (u DRSMsgCrackReplyUnion) SwitchFunc(tag any) string {
	if tag.(uint32) == 1 {
		return "Level1"
	}
	return ""
}

type DRSMsgCrackReplyV1 struct {
	PResult *DSNameResultW `ndr:"pointer"`
}

// DSNameResultW — MS-DRSR 4.1.4.1.9 DS_NAME_RESULTW.
type DSNameResultW struct {
	CItems uint32
	RItems []DSNameResultItemW `ndr:"pointer,conformant,maxcount:CItems"`
}

// DSNameResultItemW — MS-DRSR 4.1.4.1.8 DS_NAME_RESULT_ITEMW.
type DSNameResultItemW struct {
	Status  uint32
	PDomain string `ndr:"pointer,conformant,varying"`
	PName   string `ndr:"pointer,conformant,varying"`
}

// DRSDCInfoReq — IDL_DRSDomainControllerInfo request (opnum 16).
//
//	[in] DRS_HANDLE hDrs,
//	[in] DWORD dwInVersion,
//	[in, ref, switch_is(dwInVersion)] DRS_MSG_DCINFOREQ *pmsgIn
type DRSDCInfoReq struct {
	HDrs   [20]byte
	PmsgIn DRSMsgDCInfoReqUnion `ndr:"toplevel"`
}

type DRSMsgDCInfoReqUnion struct {
	Level  uint32            `ndr:"unionTag"`
	Level1 DRSMsgDCInfoReqV1 `ndr:"unionField"`
}

func (u DRSMsgDCInfoReqUnion) SwitchFunc(tag any) string {
	if tag.(uint32) == 1 {
		return "Level1"
	}
	return ""
}

type DRSMsgDCInfoReqV1 struct {
	Domain    string `ndr:"pointer,conformant,varying"`
	InfoLevel uint32
}

// DRSDCInfoRes — IDL_DRSDomainControllerInfo response.
type DRSDCInfoRes struct {
	PmsgOut    DRSMsgDCInfoReplyUnion `ndr:"toplevel"`
	ReturnCode uint32
}

// DRSMsgDCInfoReplyUnion contains V1/V2/V3 arms. Only V2 is populated today —
// the other arms exist so the decoder can dispatch to them if a server returns
// a different level without forcing a struct redesign.
type DRSMsgDCInfoReplyUnion struct {
	Level  uint32              `ndr:"unionTag"`
	Level1 DRSMsgDCInfoReplyV1 `ndr:"unionField"`
	Level2 DRSMsgDCInfoReplyV2 `ndr:"unionField"`
	Level3 DRSMsgDCInfoReplyV3 `ndr:"unionField"`
}

func (u DRSMsgDCInfoReplyUnion) SwitchFunc(tag any) string {
	switch tag.(uint32) {
	case 1:
		return "Level1"
	case 2:
		return "Level2"
	case 3:
		return "Level3"
	}
	return ""
}

type DRSMsgDCInfoReplyV1 struct {
	CItems uint32
	RItems []DSDomainControllerInfo1W `ndr:"pointer,conformant,maxcount:CItems"`
}

type DRSMsgDCInfoReplyV2 struct {
	CItems uint32
	RItems []DSDomainControllerInfo2W `ndr:"pointer,conformant,maxcount:CItems"`
}

type DRSMsgDCInfoReplyV3 struct {
	CItems uint32
	RItems []DSDomainControllerInfo3W `ndr:"pointer,conformant,maxcount:CItems"`
}

// DSDomainControllerInfo1W — MS-DRSR 5.40.
type DSDomainControllerInfo1W struct {
	NetbiosName        string `ndr:"pointer,conformant,varying"`
	DnsHostName        string `ndr:"pointer,conformant,varying"`
	SiteName           string `ndr:"pointer,conformant,varying"`
	ComputerObjectName string `ndr:"pointer,conformant,varying"`
	ServerObjectName   string `ndr:"pointer,conformant,varying"`
	FIsPdc             uint32
	FDsEnabled         uint32
}

// DSDomainControllerInfo2W — MS-DRSR 5.41.
type DSDomainControllerInfo2W struct {
	NetbiosName        string `ndr:"pointer,conformant,varying"`
	DnsHostName        string `ndr:"pointer,conformant,varying"`
	SiteName           string `ndr:"pointer,conformant,varying"`
	SiteObjectName     string `ndr:"pointer,conformant,varying"`
	ComputerObjectName string `ndr:"pointer,conformant,varying"`
	ServerObjectName   string `ndr:"pointer,conformant,varying"`
	NtdsDsaObjectName  string `ndr:"pointer,conformant,varying"`
	FIsPdc             uint32
	FDsEnabled         uint32
	FIsGc              uint32
	SiteObjectGuid     [16]byte
	ComputerObjectGuid [16]byte
	ServerObjectGuid   [16]byte
	NtdsDsaObjectGuid  [16]byte
}

// DSDomainControllerInfo3W — MS-DRSR 5.42.
type DSDomainControllerInfo3W struct {
	NetbiosName        string `ndr:"pointer,conformant,varying"`
	DnsHostName        string `ndr:"pointer,conformant,varying"`
	SiteName           string `ndr:"pointer,conformant,varying"`
	SiteObjectName     string `ndr:"pointer,conformant,varying"`
	ComputerObjectName string `ndr:"pointer,conformant,varying"`
	ServerObjectName   string `ndr:"pointer,conformant,varying"`
	NtdsDsaObjectName  string `ndr:"pointer,conformant,varying"`
	FIsPdc             uint32
	FDsEnabled         uint32
	FIsGc              uint32
	FIsRodc            uint32
	SiteObjectGuid     [16]byte
	ComputerObjectGuid [16]byte
	ServerObjectGuid   [16]byte
	NtdsDsaObjectGuid  [16]byte
}

// --- DRSGetNCChanges request/response ---
//
// DRSGetNCChangesReq — IDL_DRSGetNCChanges opnum 3.
//
//	[in] DRS_HANDLE hDrs,
//	[in] DWORD dwInVersion,
//	[in, ref, switch_is(dwInVersion)] DRS_MSG_GETCHGREQ *pmsgIn
//
// DRS_MSG_GETCHGREQ is a non-encapsulated IDL union. Per C706 §14.3.9 its
// wire layout is `[disc][disc_again][pad to arm align][arm]` — the ndr
// library writes the discriminator twice (once as the switch_is field, once
// as the union body's first word) via the `unionTag` tag convention.
type DRSGetNCChangesReq struct {
	HDrs    [20]byte
	Version uint32             `ndr:"unionTag"` // switch_is(dwInVersion) and internal disc
	V8      DRSMsgGetChgReqV8  `ndr:"unionField"`
	V10     DRSMsgGetChgReqV10 `ndr:"unionField"`
}

// SwitchFunc implements ndr.Union; selects the arm based on Version.
func (r DRSGetNCChangesReq) SwitchFunc(tag any) string {
	switch tag.(uint32) {
	case 8:
		return "V8"
	case 10:
		return "V10"
	}
	return ""
}

// DRSMsgGetChgReqV8 — MS-DRSR 4.1.10.2.21 DRS_MSG_GETCHGREQ_V8.
// USN_VECTOR and liFsmoInfo contain HYPER fields, giving the struct
// 8-byte alignment; ndr applies the pad automatically via structAlignment.
type DRSMsgGetChgReqV8 struct {
	UuidDsaObjDest    [16]byte
	UuidInvocIdSrc    [16]byte
	PNC               *DSNAME `ndr:"pointer"`
	UsnvecFrom        USNVector
	PUpToDateVecDest  *UPTODATEVectorV2 `ndr:"pointer,fullpointer"`
	UlFlags           uint32
	CMaxObjects       uint32
	CMaxBytes         uint32
	UlExtendedOp      uint32
	LiFsmoInfo        uint64
	PPartialAttrSet   *PartialAttrSet `ndr:"pointer,fullpointer"`
	PPartialAttrSetEx *PartialAttrSet `ndr:"pointer,fullpointer"`
	PrefixTableDest   SchemaPrefixTable
}

// DRSMsgGetChgReqV10 — MS-DRSR 4.1.10.2.22. V10 layout is V8 plus one extra
// ulMoreFlags field at the end (embedded V8 preserves declared field order).
type DRSMsgGetChgReqV10 struct {
	DRSMsgGetChgReqV8
	UlMoreFlags uint32
}

// --- Marshal / Unmarshal methods (ndr encoder) ---

func (s *DRSBindReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DRSBindReq: %w", err)
	}
	return b, nil
}

func (s *DRSBindRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	dec.SetEndianness(binary.LittleEndian)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling DRSBindRes: %w", err)
	}
	return nil
}

func (s *DRSUnbindReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DRSUnbindReq: %w", err)
	}
	return b, nil
}

func (s *DRSUnbindRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	dec.SetEndianness(binary.LittleEndian)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling DRSUnbindRes: %w", err)
	}
	return nil
}

func (s *DRSCrackNamesReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DRSCrackNamesReq: %w", err)
	}
	return b, nil
}

func (s *DRSCrackNamesRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	dec.SetEndianness(binary.LittleEndian)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling DRSCrackNamesRes: %w", err)
	}
	return nil
}

func (s *DRSDCInfoReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DRSDCInfoReq: %w", err)
	}
	return b, nil
}

func (s *DRSDCInfoRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	dec.SetEndianness(binary.LittleEndian)
	if err := dec.Decode(s); err != nil {
		return fmt.Errorf("error unmarshaling DRSDCInfoRes: %w", err)
	}
	return nil
}

// Marshal serializes a DSNAME via the ndr encoder, including the hoisted
// conformant max_count for StringName. Callers must have populated StringName
// (including the null terminator), NameLen, and StructLen via SetName before
// calling this.
func (d *DSNAME) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(d)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DSNAME: %w", err)
	}
	return b, nil
}

func (s *DRSGetNCChangesReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling DRSGetNCChangesReq: %w", err)
	}
	return b, nil
}

// Unmarshal decodes a DSNAME from its ndr-encoded bytes (with hoisted
// max_count at the head).
func (d *DSNAME) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	dec.SetEndianness(binary.LittleEndian)
	if err := dec.Decode(d); err != nil {
		return fmt.Errorf("error unmarshaling DSNAME: %w", err)
	}
	return nil
}

// --- DRSGetNCChanges response ---
//
// DRS_MSG_GETCHGREPLY is a non-encapsulated IDL union whose arms contain
// nested pointers; the trickiest field is pObjects, a pointer to the head of a
// self-referential REPLENTINFLIST chain. Windows emits the chain in per-entry
// order (entry_0 inline + entry_0 deferreds, entry_1 inline + entry_1
// deferreds, ...) rather than the depth-first unwind produced by ndr's default
// self-ref handling. To match the wire format, pNextEntInfRef is declared as
// an inline uint32 (not an ndr pointer) so each REPLENTINFLIST entry is
// decoded as a self-contained unit; the chain is walked manually in Unmarshal.

// REPLENTINFLIST — MS-DRSR 4.1.10.2.11.
// PNextEntInfRef is the raw pointer referent ID (nonzero → more entries follow
// in the wire stream, to be decoded by the next Decode loop iteration).
type REPLENTINFLIST struct {
	PNextEntInfRef uint32
	Entinf         ENTINF
	FIsNCPrefix    uint32
	PParentGuid    *[16]byte                  `ndr:"pointer,fullpointer"`
	PMetaDataExt   *PropertyMetaDataExtVector `ndr:"pointer,fullpointer"`
}

// DRSMsgGetChgReplyV1 — MS-DRSR 4.1.10.2.9 DRS_MSG_GETCHGREPLY_V1.
type DRSMsgGetChgReplyV1 struct {
	UuidDsaObjSrc     [16]byte
	UuidInvocIdSrc    [16]byte
	PNC               *DSNAME `ndr:"pointer"`
	UsnvecFrom        USNVector
	UsnvecTo          USNVector
	PUpToDateVecSrcV1 *UPTODATEVectorV1 `ndr:"pointer"`
	PrefixTableSrc    SchemaPrefixTable
	UlExtendedRet     uint32
	CNumObjects       uint32
	CNumBytes         uint32
	PObjects          *REPLENTINFLIST `ndr:"pointer"`
	FMoreData         uint32
}

// DRSMsgGetChgReplyV6 — MS-DRSR 4.1.10.2.11 DRS_MSG_GETCHGREPLY_V6 and V9.
// V9 (4.1.10.2.13) is structurally identical and shares this definition.
// RgValuesRef holds the [unique] referent ID for the rgValues array; the
// deferred payload (REPLVALINF_V1 for V6 / REPLVALINF_V3 for V9) is decoded
// after the REPLENTINFLIST chain in Unmarshal and surfaced on
// DRSGetNCChangesRes.LinkedValues.
type DRSMsgGetChgReplyV6 struct {
	UuidDsaObjSrc     [16]byte
	UuidInvocIdSrc    [16]byte
	PNC               *DSNAME `ndr:"pointer"`
	UsnvecFrom        USNVector
	UsnvecTo          USNVector
	PUpToDateVecSrc   *UPTODATEVectorV2 `ndr:"pointer,fullpointer"`
	PrefixTableSrc    SchemaPrefixTable
	UlExtendedRet     uint32
	CNumObjects       uint32
	CNumBytes         uint32
	PObjects          *REPLENTINFLIST `ndr:"pointer"`
	FMoreData         uint32
	CNumNcSizeObjects uint32
	CNumNcSizeValues  uint32
	CNumValues        uint32
	RgValuesRef       uint32 // Actually a pointer for REPLVALINF_V1 or REPLVALINF_V3 which we ignore
	DwDRSError        uint32
}

// DRSMsgGetChgReplyUnion — discriminated union of V1, V6, V9 reply bodies.
// V9 uses the same Go type as V6.
type DRSMsgGetChgReplyUnion struct {
	Level  uint32              `ndr:"unionTag"`
	Level1 DRSMsgGetChgReplyV1 `ndr:"unionField"`
	Level6 DRSMsgGetChgReplyV6 `ndr:"unionField"`
}

func (u DRSMsgGetChgReplyUnion) SwitchFunc(tag any) string {
	switch tag.(uint32) {
	case 1:
		return "Level1"
	case 6, 9:
		return "Level6"
	}
	return ""
}

// drsGetNCChangesResWrap holds the ndr-decodable portion of the reply:
// dwOutVersion (via union Level, duplicated on wire by the non-encapsulated
// union machinery) plus the selected arm body. pObjects → REPLENTINFLIST_0 is
// decoded as the last deferred of the arm scope; subsequent entries are walked
// manually via DRSGetNCChangesRes.Unmarshal.
type drsGetNCChangesResWrap struct {
	PmsgOut DRSMsgGetChgReplyUnion `ndr:"toplevel"`
}

// ReplValInfV1 — MS-DRSR 4.1.10.2.15 REPLVALINF_V1. One replicated link value.
// Aval is inline (not a pointer): the ATTRVAL carries the attribute bytes.
// MetaData holds the per-value replication metadata (version, timestamps,
// originating DSA/USN).
type ReplValInfV1 struct {
	PObject     *DSNAME `ndr:"pointer"`
	AttrTyp     ATTRTYP
	Aval        ATTRVAL
	FIsPresent  uint32 // BOOL
	TimeCreated int64  // DSTIME, 8-byte aligned
	MetaData    PropertyMetaDataExt
}

// ValueMetaDataExtV3 — MS-DRSR 4.1.10.2.44 VALUE_META_DATA_EXT_V3.
// Defined for completeness; no decoding path populates this today.
type ValueMetaDataExtV3 struct {
	TimeCreated int64
	MetaData    PropertyMetaDataExt
	TimeExpired int64
}

// ReplValInfV3 — MS-DRSR 4.1.10.2.15 REPLVALINF_V3 (V9 reply arm).
// Declared but not decoded: DRSBind does not advertise DrsExtGetchgReplyV9, so
// Windows DCs reply with V6 (REPLVALINF_V1). If a server returns V9 anyway,
// Unmarshal logs a warning and leaves LinkedValues empty.
type ReplValInfV3 struct {
	PObject    *DSNAME `ndr:"pointer"`
	AttrTyp    ATTRTYP
	Aval       ATTRVAL
	FIsPresent uint32
	MetaData   ValueMetaDataExtV3
}

// replValInfV1Array decodes the deferred payload of [unique, size_is(cNumValues)]
// REPLVALINF_V1 *rgValues. A single conformant slice at top level consumes
// max_count + elements from the stream (see ndr arrays_test.go TestRead*ConformantArray).
type replValInfV1Array struct {
	Values []ReplValInfV1 `ndr:"conformant"`
}

// DRSGetNCChangesRes holds the parsed DRS_MSG_GETCHGREPLY, with the
// REPLENTINFLIST chain flattened into Entries. MsgV1 xor MsgV6 is populated
// based on the server-chosen dwOutVersion. LinkedValues carries the parsed
// rgValues link-value array (V6 only; empty for V1 and unsupported V9).
// ReturnCode is the RPC HRESULT.
type DRSGetNCChangesRes struct {
	DwOutVersion uint32
	MsgV1        *DRSMsgGetChgReplyV1
	MsgV6        *DRSMsgGetChgReplyV6
	Entries      []REPLENTINFLIST
	LinkedValues []ReplValInfV1
	ReturnCode   uint32
}

// FMoreData returns whether the server has more data available (paging flag).
func (r *DRSGetNCChangesRes) FMoreData() bool {
	switch {
	case r.MsgV6 != nil:
		return r.MsgV6.FMoreData != 0
	case r.MsgV1 != nil:
		return r.MsgV1.FMoreData != 0
	}
	return false
}

// UsnvecTo returns the usnvecTo cursor from the selected reply arm, used to
// resume paging on subsequent DRSGetNCChanges calls.
func (r *DRSGetNCChangesRes) UsnvecTo() USNVector {
	switch {
	case r.MsgV6 != nil:
		return r.MsgV6.UsnvecTo
	case r.MsgV1 != nil:
		return r.MsgV1.UsnvecTo
	}
	return USNVector{}
}

// PrefixTableSrc returns the prefix table from the selected reply arm.
func (r *DRSGetNCChangesRes) PrefixTableSrc() SchemaPrefixTable {
	switch {
	case r.MsgV6 != nil:
		return r.MsgV6.PrefixTableSrc
	case r.MsgV1 != nil:
		return r.MsgV1.PrefixTableSrc
	}
	return SchemaPrefixTable{}
}

// UpToDateVec returns the UP-TO-DATE vector from the selected reply arm,
// normalizing V1 cursors into V2 cursors (with TimeLastSyncSuccess=0).
func (r *DRSGetNCChangesRes) UpToDateVec() *UPTODATEVectorV2 {
	if r.MsgV6 != nil {
		return r.MsgV6.PUpToDateVecSrc
	}
	if r.MsgV1 != nil && r.MsgV1.PUpToDateVecSrcV1 != nil {
		src := r.MsgV1.PUpToDateVecSrcV1
		v2 := &UPTODATEVectorV2{
			Version:  src.Version,
			Reserved: src.Reserved,
			Count:    src.Count,
			Cursors:  make([]UPTODATECursorV2, len(src.Cursors)),
		}
		for i, c := range src.Cursors {
			v2.Cursors[i] = UPTODATECursorV2{
				UuidDsa:           c.UuidDsa,
				UsnHighPropUpdate: c.UsnHighPropUpdate,
			}
		}
		return v2
	}
	return nil
}

// Unmarshal decodes the DRS_MSG_GETCHGREPLY response. The ndr library handles
// the top-level union and all deferred pointers in the selected arm, including
// the first REPLENTINFLIST entry (via pObjects). Remaining chain entries are
// decoded in a loop on the same Decoder, then the trailing RPC ReturnCode is
// read last.
func (r *DRSGetNCChangesRes) Unmarshal(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("GetNCChanges response too short: %d bytes", len(data))
	}
	dec := ndr.NewDecoder(bytes.NewReader(data), false)
	dec.SetEndianness(binary.LittleEndian)

	var wrap drsGetNCChangesResWrap
	if err := dec.Decode(&wrap); err != nil {
		return fmt.Errorf("error unmarshaling DRSGetNCChangesRes: %w", err)
	}
	r.DwOutVersion = wrap.PmsgOut.Level

	var head *REPLENTINFLIST
	switch wrap.PmsgOut.Level {
	case 1:
		r.MsgV1 = &wrap.PmsgOut.Level1
		head = r.MsgV1.PObjects
	case 6, 9:
		r.MsgV6 = &wrap.PmsgOut.Level6
		head = r.MsgV6.PObjects
	default:
		return fmt.Errorf("unexpected DRSGetNCChanges outVersion: %d", wrap.PmsgOut.Level)
	}

	if head != nil {
		r.Entries = append(r.Entries, *head)
		next := head.PNextEntInfRef
		for next != 0 {
			var entry REPLENTINFLIST
			if err := dec.Decode(&entry); err != nil {
				return fmt.Errorf("error unmarshaling REPLENTINFLIST entry %d: %v", len(r.Entries), err)
			}
			r.Entries = append(r.Entries, entry)
			next = entry.PNextEntInfRef
		}
	}

	if r.MsgV6 != nil && r.MsgV6.RgValuesRef != 0 && r.MsgV6.CNumValues > 0 {
		switch wrap.PmsgOut.Level {
		case 6:
			var arr replValInfV1Array
			if err := dec.Decode(&arr); err != nil {
				return fmt.Errorf("error unmarshaling rgValues (REPLVALINF_V1): %w", err)
			}
			r.LinkedValues = arr.Values
		case 9:
			// REPLVALINF_V3 decode is not implemented. Without consuming the
			// rgValues bytes we cannot locate ReturnCode; return early and let
			// the caller see ReturnCode == 0. We only reach this branch if a
			// server returns V9 despite us not advertising DrsExtGetchgReplyV9.
			log.Warningf("DRSGetNCChanges V9 rgValues (REPLVALINF_V3) decoding is not implemented; %d linked values dropped, ReturnCode unread", r.MsgV6.CNumValues)
			return nil
		}
	}

	var trailer struct{ ReturnCode uint32 }
	if err := dec.Decode(&trailer); err != nil {
		return fmt.Errorf("error unmarshaling DRSGetNCChanges returnCode: %w", err)
	}
	r.ReturnCode = trailer.ReturnCode
	return nil
}
