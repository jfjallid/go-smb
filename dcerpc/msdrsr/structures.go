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

	"github.com/jfjallid/go-smb/msdtyp"
)

// ndrAlign pads the write buffer to the given alignment boundary.
func ndrAlign(w *bytes.Buffer, alignment int) {
	if pad := (alignment - (w.Len() % alignment)) % alignment; pad > 0 {
		w.Write(make([]byte, pad))
	}
}

// ndrAlignReader skips padding bytes in the reader to reach the given alignment.
func ndrAlignReader(r *bytes.Reader, alignment int64) {
	pos, _ := r.Seek(0, io.SeekCurrent)
	if pad := (alignment - (pos % alignment)) % alignment; pad > 0 {
		r.Seek(pad, io.SeekCurrent)
	}
}

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

func (e *DRSExtensionsInt) MarshalBinary() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 52))
	binary.Write(w, le, e.Flags)
	w.Write(e.SiteObjGuid[:])
	binary.Write(w, le, e.Pid)
	binary.Write(w, le, e.ReplicationEpoch)
	binary.Write(w, le, e.FlagsExt)
	w.Write(e.ConfigObjGuid[:])
	return w.Bytes(), nil
}

func (e *DRSExtensionsInt) UnmarshalBinary(data []byte) error {
	r := bytes.NewReader(data)
	if len(data) >= 4 {
		binary.Read(r, le, &e.Flags)
	}
	if len(data) >= 20 {
		r.Read(e.SiteObjGuid[:])
	}
	if len(data) >= 24 {
		binary.Read(r, le, &e.Pid)
	}
	if len(data) >= 28 {
		binary.Read(r, le, &e.ReplicationEpoch)
	}
	if len(data) >= 32 {
		binary.Read(r, le, &e.FlagsExt)
	}
	if len(data) >= 48 {
		r.Read(e.ConfigObjGuid[:])
	}
	return nil
}

// DSNAME represents a directory object name (MS-DRSR 4.1.10.2.9).
type DSNAME struct {
	StructLen  uint32
	SidLen     uint32
	Guid       [16]byte
	Sid        [28]byte // Fixed 28-byte buffer, zero-padded
	NameLen    uint32   // Character count including null terminator
	StringName string
}

func (d *DSNAME) MarshalBinary() ([]byte, error) {
	nameUtf16 := msdtyp.ToUnicode(d.StringName)
	// Add null terminator
	nameUtf16 = append(nameUtf16, 0, 0)
	nameLen := uint32(len(d.StringName)) // chars NOT including null (MS-DRSR 4.1.10.2.9)

	// StructLen = fixed fields (4+4+16+28+4) + name bytes
	structLen := uint32(56 + len(nameUtf16))

	w := bytes.NewBuffer(make([]byte, 0, structLen))
	binary.Write(w, le, structLen)
	binary.Write(w, le, d.SidLen)
	w.Write(d.Guid[:])
	w.Write(d.Sid[:])
	binary.Write(w, le, nameLen)
	w.Write(nameUtf16)

	return w.Bytes(), nil
}

func unmarshalDSNAME(r io.Reader) (*DSNAME, error) {
	d := &DSNAME{}
	if err := binary.Read(r, le, &d.StructLen); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.StructLen: %w", err)
	}
	if err := binary.Read(r, le, &d.SidLen); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.SidLen: %w", err)
	}
	if _, err := io.ReadFull(r, d.Guid[:]); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.Guid: %w", err)
	}
	if _, err := io.ReadFull(r, d.Sid[:]); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.Sid: %w", err)
	}
	if err := binary.Read(r, le, &d.NameLen); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.NameLen: %w", err)
	}

	// StringName is [size_is(NameLen+1)] WCHAR — always at least 1 WCHAR
	// (the null terminator), even when NameLen == 0.
	nameWchars := d.NameLen + 1
	nameBytes := make([]byte, nameWchars*2)
	if _, err := io.ReadFull(r, nameBytes); err != nil {
		return nil, fmt.Errorf("failed to read DSNAME.StringName: %w", err)
	}
	if d.NameLen > 0 {
		d.StringName, _ = msdtyp.FromUnicodeString(nameBytes[:d.NameLen*2])
	}

	return d, nil
}

// ATTRVAL represents a single attribute value (MS-DRSR 4.1.10.2.2).
type ATTRVAL struct {
	ValLen uint32
	PVal   []byte
}

// ATTRVALBLOCK represents a block of attribute values (MS-DRSR 4.1.10.2.3).
type ATTRVALBLOCK struct {
	ValCount uint32
	PVal     []ATTRVAL
}

// ATTR represents a single attribute with its type and values (MS-DRSR 4.1.10.2.4).
type ATTR struct {
	AttrTyp ATTRTYP
	AttrVal ATTRVALBLOCK
}

// ATTRBLOCK represents a block of attributes (MS-DRSR 4.1.10.2.5).
type ATTRBLOCK struct {
	AttrCount uint32
	PAttr     []ATTR
}

// ENTINF represents a replicated directory entry with its attributes (MS-DRSR 4.1.10.2.10).
type ENTINF struct {
	PName    *DSNAME
	UlFlags  uint32
	AttrBlock ATTRBLOCK
}

// USNVector represents a replication cursor (MS-DRSR 4.1.10.2.18).
type USNVector struct {
	UsnHighObjUpdate  int64
	UsnReserved       int64
	UsnHighPropUpdate int64
}

// UPTODATEVectorV2 represents the up-to-date vector for replication cursors.
type UPTODATEVectorV2 struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	Cursors  []UPTODATECursorV2
}

// UPTODATECursorV2 represents a single replication cursor entry.
type UPTODATECursorV2 struct {
	UuidDsa            [16]byte
	UsnHighPropUpdate  int64
	TimeLastSyncSuccess int64
}

// OIDPrefix represents a single entry in the prefix table (MS-DRSR 4.1.10.2.13).
type OIDPrefix struct {
	NdxVal uint32
	Prefix []byte
}

// SchemaPrefixTable maps server-local ATTRTYP values to OID-based attribute IDs (MS-DRSR 4.1.10.2.14).
type SchemaPrefixTable struct {
	PrefixCount uint32
	Entries     []OIDPrefix
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

// GetNCChangesResponse holds the parsed response from DRSGetNCChanges.
type GetNCChangesResponse struct {
	Entries        []ENTINF
	FMoreData      bool
	UsnvecTo       USNVector
	PrefixTableSrc SchemaPrefixTable
	UpToDateVec    *UPTODATEVectorV2
}

// PartialAttrSet represents PARTIAL_ATTR_VECTOR_V1_EXT (MS-DRSR 4.1.10.2.12).
type PartialAttrSet struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	Attrs    []ATTRTYP
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

// marshalCrackNamesReq creates the request buffer for IDL_DRSCrackNames.
// Request structure (manual NDR):
//   [20 bytes] DRS_HANDLE
//   [4 bytes]  dwInVersion (1)
//   [4 bytes]  dwInVersion union switch
//   -- DRS_MSG_CRACKREQ_V1:
//   [4 bytes]  CodePage (0)
//   [4 bytes]  LocaleId (0)
//   [4 bytes]  dwFlags
//   [4 bytes]  formatOffered
//   [4 bytes]  formatDesired
//   [4 bytes]  cNames
//   [4 bytes]  rpNames referent ID
//   -- deferred rpNames:
//   [4 bytes]  conformant max_count
//   [N * 4 bytes] referent IDs for each string
//   -- deferred strings
func marshalCrackNamesReq(handle []byte, formatOffered, formatDesired uint32, names []string) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 256))

	// DRS_HANDLE
	w.Write(handle)

	// dwInVersion = 1
	binary.Write(w, le, uint32(1))
	// Union switch = 1
	binary.Write(w, le, uint32(1))

	// DRS_MSG_CRACKREQ_V1
	binary.Write(w, le, uint32(0)) // CodePage
	binary.Write(w, le, uint32(0)) // LocaleId
	binary.Write(w, le, uint32(DsNameNoFlags)) // dwFlags
	binary.Write(w, le, formatOffered)
	binary.Write(w, le, formatDesired)
	binary.Write(w, le, uint32(len(names))) // cNames

	// rpNames referent ID
	var refId uint32 = 1
	binary.Write(w, le, refId)

	// Conformant array max_count
	binary.Write(w, le, uint32(len(names)))

	// Referent IDs for each string pointer
	for range names {
		refId++
		binary.Write(w, le, refId)
	}

	// Deferred strings (conformant varying strings)
	for _, name := range names {
		msdtyp.WriteConformantVaryingString(w, name, true)
	}

	return w.Bytes(), nil
}

// unmarshalCrackNamesResp parses the response from IDL_DRSCrackNames.
// Response structure:
//   [4 bytes]  dwOutVersion (must be 1)
//   [4 bytes]  union switch (1)
//   -- DRS_MSG_CRACKREPLY_V1:
//   [4 bytes]  pResult referent ID
//   -- deferred pResult (DS_NAME_RESULTW):
//   [4 bytes]  cItems
//   [4 bytes]  rItems referent ID
//   -- deferred rItems (conformant array of DS_NAME_RESULT_ITEMW):
//   [4 bytes]  max_count
//   [N * (4+4+4) bytes] items: status, pDomain refId, pName refId
//   -- deferred strings for each item
//   [4 bytes]  return code (at end)
func unmarshalCrackNamesResp(data []byte) ([]CrackedName, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("DRSCrackNames response too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	var outVersion uint32
	binary.Read(r, le, &outVersion)
	if outVersion != 1 {
		return nil, fmt.Errorf("unexpected DRSCrackNames outVersion: %d", outVersion)
	}

	var unionSwitch uint32
	binary.Read(r, le, &unionSwitch)

	// pResult referent ID
	var pResultRef uint32
	binary.Read(r, le, &pResultRef)

	if pResultRef == 0 {
		// Check return code at end
		return nil, fmt.Errorf("DRSCrackNames returned null result")
	}

	// DS_NAME_RESULTW
	var cItems uint32
	binary.Read(r, le, &cItems)

	var rItemsRef uint32
	binary.Read(r, le, &rItemsRef)

	if rItemsRef == 0 || cItems == 0 {
		return nil, nil
	}

	// Conformant array max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	type itemEntry struct {
		Status     uint32
		DomainRef  uint32
		NameRef    uint32
	}

	items := make([]itemEntry, cItems)
	for i := uint32(0); i < cItems; i++ {
		binary.Read(r, le, &items[i].Status)
		binary.Read(r, le, &items[i].DomainRef)
		binary.Read(r, le, &items[i].NameRef)
	}

	// Read deferred strings
	results := make([]CrackedName, cItems)
	for i := uint32(0); i < cItems; i++ {
		results[i].Status = items[i].Status
		if items[i].DomainRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read domain string %d: %w", i, err)
			}
			results[i].Domain = s
		}
		if items[i].NameRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read name string %d: %w", i, err)
			}
			results[i].Name = s
		}
	}

	return results, nil
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
		if oid == nil || len(oid) < 2 {
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
				NdxVal: ndx,
				Prefix: prefixBytes,
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

// marshalPrefixTableDeferred writes the deferred portion of a SCHEMA_PREFIX_TABLE.
func marshalPrefixTableDeferred(w *bytes.Buffer, pt *SchemaPrefixTable) {
	if pt.PrefixCount == 0 {
		return
	}

	// Conformant array max_count
	binary.Write(w, le, pt.PrefixCount)

	// Per entry inline: NdxVal(4) + PrefixLen(4) + PrefixRef(4)
	for i, entry := range pt.Entries {
		binary.Write(w, le, entry.NdxVal)
		binary.Write(w, le, uint32(len(entry.Prefix)))
		binary.Write(w, le, uint32(i+1)) // non-zero referent ID for the byte array
	}

	// Per entry deferred: conformant byte array + padding
	for _, entry := range pt.Entries {
		binary.Write(w, le, uint32(len(entry.Prefix))) // max_count
		w.Write(entry.Prefix)
		// Pad to 4-byte alignment
		if pad := (4 - (len(entry.Prefix) % 4)) % 4; pad > 0 {
			w.Write(make([]byte, pad))
		}
	}
}

// marshalGetNCChangesReq creates the request buffer for IDL_DRSGetNCChanges.
func marshalGetNCChangesReq(handle []byte, ncDN string, objectGuid [16]byte, dsaObjGuid [16]byte, extendedOp uint32, usnFrom USNVector, uptodateVec *UPTODATEVectorV2, useV10 bool, attrs DCSyncAttrs) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 512))

	// DRS_HANDLE
	w.Write(handle)

	// dwInVersion
	var version uint32 = 8
	if useV10 {
		version = 10
	}
	binary.Write(w, le, version)
	// Union switch
	binary.Write(w, le, version)

	// Build the DSNAME for the NC
	dsname := &DSNAME{
		Guid:       objectGuid,
		StringName: ncDN,
	}
	dsnameBytes, err := dsname.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DSNAME: %w", err)
	}

	// DRS_MSG_GETCHGREQ_V8 arm
	// 64-bit fields (USN_VECTOR, liFsmoInfo) require 8-byte alignment.
	// The V8 struct alignment is 8 (max of member alignments),
	// so the arm body is also padded to 8 after the union discriminant.
	ndrAlign(w, 8) // align V8 arm body after union discriminant

	// [16 bytes] uuidDsaObjDest - NTDS DSA object GUID of target DC
	w.Write(dsaObjGuid[:])

	// [16 bytes] uuidInvocIdSrc - invocation ID (same as DSA GUID)
	w.Write(dsaObjGuid[:])

	// pNC referent ID
	var refId uint32 = 1
	binary.Write(w, le, refId)

	// usnvecFrom (USN_VECTOR) — 3 × int64, alignment 8
	ndrAlign(w, 8)
	binary.Write(w, le, usnFrom.UsnHighObjUpdate)
	binary.Write(w, le, usnFrom.UsnReserved)
	binary.Write(w, le, usnFrom.UsnHighPropUpdate)

	// pUpToDateVecDest referent ID (NULL for first request)
	if uptodateVec != nil {
		refId++
		binary.Write(w, le, refId)
	} else {
		binary.Write(w, le, uint32(0))
	}

	// ulFlags — for EXOP_REPL_OBJ (single user)
	// DRS_INIT_SYNC | DRS_WRIT_REP; for full NC sync add more flags.
	var flags uint32
	var cMaxObjects uint32
	var cMaxBytes uint32
	if extendedOp == ExopReplObj {
		flags = DrsInitSync | DrsWritRep
		cMaxObjects = 1
		cMaxBytes = 0
	} else {
		flags = DrsInitSync | DrsWritRep | DrsNeverSynced | DrsFullSyncNow | DrsFullSyncInProgress
		cMaxObjects = 1000
		cMaxBytes = 0x00a00000
	}
	binary.Write(w, le, flags)

	// cMaxObjects
	binary.Write(w, le, cMaxObjects)
	// cMaxBytes
	binary.Write(w, le, cMaxBytes)
	// ulExtendedOp
	binary.Write(w, le, extendedOp)

	// liFsmoInfo (ULARGE_INTEGER / NDRUHYPER, alignment 8)
	ndrAlign(w, 8)
	binary.Write(w, le, uint64(0)) // liFsmoInfo

	// Build prefix table and convert ATTRTYPs to use it
	partialAttrs := partialAttrSetForAttrs(attrs)
	prefixTable, convertedAttrs := buildPrefixTableAndConvertAttrs(partialAttrs.Attrs)
	partialAttrs.Attrs = convertedAttrs
	partialBytes, err := partialAttrs.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PartialAttrSet: %w", err)
	}

	// pPartialAttrSet referent ID
	refId++
	binary.Write(w, le, refId)

	// pPartialAttrSetEx referent ID (NULL)
	binary.Write(w, le, uint32(0))

	// PrefixTableDest (inline: PrefixCount + pPrefixEntry pointer)
	binary.Write(w, le, prefixTable.PrefixCount)
	if prefixTable.PrefixCount > 0 {
		refId++
		binary.Write(w, le, refId)
	} else {
		binary.Write(w, le, uint32(0))
	}

	if useV10 {
		// ulMoreFlags (DRS_MSG_GETCHGREQ_V10 additional field)
		binary.Write(w, le, uint32(0))
	}

	// -- Deferred data --

	// pNC (DSNAME) - preceded by conformant max_count for the StringName array
	// The DSNAME is embedded as a conformant structure with max_count = NameLen
	nameLen := uint32(len(ncDN) + 1)
	binary.Write(w, le, nameLen) // conformant max_count
	w.Write(dsnameBytes)

	// NDR alignment: pad to 4-byte boundary after DSNAME deferred data.
	// DSNAME length depends on the DN string and may not end 4-byte aligned.
	if pad := (4 - (w.Len() % 4)) % 4; pad > 0 {
		w.Write(make([]byte, pad))
	}

	// pUpToDateVecDest deferred data
	if uptodateVec != nil {
		binary.Write(w, le, uptodateVec.Version)
		binary.Write(w, le, uptodateVec.Reserved)
		binary.Write(w, le, uptodateVec.Count)
		for _, cursor := range uptodateVec.Cursors {
			w.Write(cursor.UuidDsa[:])
			binary.Write(w, le, cursor.UsnHighPropUpdate)
			binary.Write(w, le, cursor.TimeLastSyncSuccess)
		}

		// NDR alignment: pad to 4-byte boundary after uptodateVec deferred data
		if pad := (4 - (w.Len() % 4)) % 4; pad > 0 {
			w.Write(make([]byte, pad))
		}
	}

	// pPartialAttrSet deferred data (conformant max_count for Attrs array)
	binary.Write(w, le, uint32(len(partialAttrs.Attrs)))
	w.Write(partialBytes)

	// PrefixTableDest deferred data
	marshalPrefixTableDeferred(w, &prefixTable)

	return w.Bytes(), nil
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
	return &PartialAttrSet{Version: 1, Attrs: attrList}
}

// unmarshalGetNCChangesResp parses the response from IDL_DRSGetNCChanges.
// This is the most complex unmarshaling in the package due to the linked-list
// REPLENTINFLIST structure and nested NDR pointers.
//
// Supports DRS_MSG_GETCHGREPLY versions:
//   - V1: Basic reply (dwInVersion 4/5/7 or server fallback)
//   - V6: Extended reply with compression blob (dwInVersion 8/10)
//   - V9: V6 + dwDRSError (dwInVersion 11)
func unmarshalGetNCChangesResp(data []byte) (*GetNCChangesResponse, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("GetNCChanges response too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	var outVersion uint32
	binary.Read(r, le, &outVersion)
	if outVersion != 1 && outVersion != 6 && outVersion != 9 {
		return nil, fmt.Errorf("unexpected GetNCChanges outVersion: %d", outVersion)
	}

	var unionSwitch uint32
	binary.Read(r, le, &unionSwitch)

	resp := &GetNCChangesResponse{}

	// DRS_MSG_GETCHGREPLY_V1/V6 share the same initial layout:
	// [16 bytes] uuidDsaObjSrc
	var uuidDsaObjSrc [16]byte
	r.Read(uuidDsaObjSrc[:])

	// [16 bytes] uuidInvocIdSrc
	var uuidInvocIdSrc [16]byte
	r.Read(uuidInvocIdSrc[:])

	// pNC referent ID
	var pNCRef uint32
	binary.Read(r, le, &pNCRef)

	// NDR alignment: USN_VECTOR contains HYPER fields (alignment 8)
	ndrAlignReader(r, 8)

	// usnvecFrom (read and discard; we only need usnvecTo for paging)
	var usnvecFrom USNVector
	binary.Read(r, le, &usnvecFrom.UsnHighObjUpdate)
	binary.Read(r, le, &usnvecFrom.UsnReserved)
	binary.Read(r, le, &usnvecFrom.UsnHighPropUpdate)

	// usnvecTo
	binary.Read(r, le, &resp.UsnvecTo.UsnHighObjUpdate)
	binary.Read(r, le, &resp.UsnvecTo.UsnReserved)
	binary.Read(r, le, &resp.UsnvecTo.UsnHighPropUpdate)

	// pUpToDateVecSrc referent ID
	var uptodateVecRef uint32
	binary.Read(r, le, &uptodateVecRef)

	// PrefixTableSrc
	err := unmarshalPrefixTable(r, &resp.PrefixTableSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PrefixTableSrc: %w", err)
	}

	// ulExtendedRet
	var ulExtendedRet uint32
	binary.Read(r, le, &ulExtendedRet)

	// cNumObjects
	var cNumObjects uint32
	binary.Read(r, le, &cNumObjects)

	// cNumBytes
	var cNumBytes uint32
	binary.Read(r, le, &cNumBytes)

	// pObjects referent ID (pointer to first REPLENTINFLIST)
	var pObjectsRef uint32
	binary.Read(r, le, &pObjectsRef)

	// fMoreData
	var fMoreData uint32
	binary.Read(r, le, &fMoreData)
	resp.FMoreData = fMoreData != 0

	log.Debugf("GetNCChanges response: ulExtendedRet=%d cNumObjects=%d cNumBytes=%d pObjectsRef=0x%x fMoreData=%v",
		ulExtendedRet, cNumObjects, cNumBytes, pObjectsRef, resp.FMoreData)

	// V6/V9 have extra inline fields after fMoreData
	if outVersion == 6 || outVersion == 9 {
		// cbReplicationDataGranularity
		var cbRepGranularity uint32
		binary.Read(r, le, &cbRepGranularity)

		// DRS_COMPRESSED_BLOB inline part:
		// cbUncompressedSize (4) + cbCompressedSize (4) + pbCompressedData ref (4)
		var cbUncompressedSize, cbCompressedSize, compressedRef uint32
		binary.Read(r, le, &cbUncompressedSize)
		binary.Read(r, le, &cbCompressedSize)
		binary.Read(r, le, &compressedRef)

		if outVersion == 9 {
			// dwDRSError (V9 only)
			var dwDRSError uint32
			binary.Read(r, le, &dwDRSError)
		}
	}

	// In NDR, the function return value is serialized as the last inline
	// field (after all [out] parameters) before deferred pointer data.
	var returnCode uint32
	binary.Read(r, le, &returnCode)

	// -- Deferred data --

	// pNC deferred (DSNAME — conformant struct, max_count hoisted)
	if pNCRef != 0 {
		// Conformant max_count for DSNAME StringName
		var dsnameMaxCount uint32
		binary.Read(r, le, &dsnameMaxCount)

		_, err := unmarshalDSNAME(r)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal pNC DSNAME: %w", err)
		}
		// Pad to 4-byte alignment after variable-length DSNAME
		ndrAlignReader(r, 4)
	}

	// pUpToDateVecSrc deferred — UPTODATE_VECTOR_V1/V2_EXT is a conformant
	// struct (rgCursors is [size_is(cNumCursors)]), so the hoisted max_count
	// comes first.
	if uptodateVecRef != 0 {
		// Conformant max_count (hoisted from rgCursors[])
		var utdvMaxCount uint32
		binary.Read(r, le, &utdvMaxCount)

		utdv := &UPTODATEVectorV2{}
		binary.Read(r, le, &utdv.Version)
		binary.Read(r, le, &utdv.Reserved)

		var cNumCursors uint32
		binary.Read(r, le, &cNumCursors)
		utdv.Count = cNumCursors

		_ = utdvMaxCount // conformance max_count consumed; actual count read below

		// NDR alignment: UPTODATE_CURSOR_V2 contains int64 fields (alignment 8)
		ndrAlignReader(r, 8)

		utdv.Cursors = make([]UPTODATECursorV2, cNumCursors)
		for i := uint32(0); i < cNumCursors; i++ {
			r.Read(utdv.Cursors[i].UuidDsa[:])
			binary.Read(r, le, &utdv.Cursors[i].UsnHighPropUpdate)
			if outVersion != 1 {
				// V6/V9: UPTODATE_CURSOR_V2 has TimeLastSyncSuccess
				binary.Read(r, le, &utdv.Cursors[i].TimeLastSyncSuccess)
			}
			// V1: UPTODATE_CURSOR_V1 has no TimeLastSyncSuccess
		}
		resp.UpToDateVec = utdv
	}

	// PrefixTableSrc deferred (prefix entries)
	err = unmarshalPrefixTableDeferred(r, &resp.PrefixTableSrc)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PrefixTableSrc entries: %w", err)
	}

	// pObjects deferred - linked list of REPLENTINFLIST
	if pObjectsRef != 0 {
		entries, err := unmarshalREPLENTINFLIST(r, cNumObjects)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal REPLENTINFLIST: %w", err)
		}
		resp.Entries = entries
	}

	return resp, nil
}

// unmarshalPrefixTable reads the inline (non-deferred) part of the prefix table.
func unmarshalPrefixTable(r *bytes.Reader, pt *SchemaPrefixTable) error {
	binary.Read(r, le, &pt.PrefixCount)

	// pPrefixEntry referent ID
	var prefixEntryRef uint32
	binary.Read(r, le, &prefixEntryRef)

	// Actual entries are deferred
	return nil
}

// unmarshalPrefixTableDeferred reads the deferred prefix table entries.
func unmarshalPrefixTableDeferred(r *bytes.Reader, pt *SchemaPrefixTable) error {
	if pt.PrefixCount == 0 {
		return nil
	}

	// Conformant array max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	pt.Entries = make([]OIDPrefix, pt.PrefixCount)

	// Read all entries inline: NdxVal + prefix length + referent ID
	type prefixHdr struct {
		NdxVal    uint32
		PrefixLen uint32
		PrefixRef uint32
	}

	hdrs := make([]prefixHdr, pt.PrefixCount)
	for i := uint32(0); i < pt.PrefixCount; i++ {
		binary.Read(r, le, &hdrs[i].NdxVal)
		binary.Read(r, le, &hdrs[i].PrefixLen)
		binary.Read(r, le, &hdrs[i].PrefixRef)
		pt.Entries[i].NdxVal = hdrs[i].NdxVal
	}

	// Read deferred prefix byte arrays
	for i := uint32(0); i < pt.PrefixCount; i++ {
		if hdrs[i].PrefixRef == 0 {
			continue
		}
		// Conformant array: max_count + data
		var arrMaxCount uint32
		binary.Read(r, le, &arrMaxCount)

		prefixData := make([]byte, hdrs[i].PrefixLen)
		r.Read(prefixData)
		pt.Entries[i].Prefix = prefixData

		// Pad to 4-byte alignment
		if pad := (4 - (hdrs[i].PrefixLen % 4)) % 4; pad > 0 {
			r.Seek(int64(pad), io.SeekCurrent)
		}
	}

	return nil
}

// unmarshalREPLENTINFLIST walks the linked list of replicated entries.
func unmarshalREPLENTINFLIST(r *bytes.Reader, expectedCount uint32) ([]ENTINF, error) {
	var entries []ENTINF

	for i := uint32(0); i < expectedCount; i++ {
		entry, hasNext, err := unmarshalOneReplEntInf(r)
		if err != nil {
			return entries, fmt.Errorf("failed to unmarshal entry %d: %w", i, err)
		}
		if entry != nil {
			entries = append(entries, *entry)
		}
		if !hasNext {
			break
		}
	}

	return entries, nil
}

// unmarshalOneReplEntInf reads a single REPLENTINFLIST entry from the stream.
func unmarshalOneReplEntInf(r *bytes.Reader) (*ENTINF, bool, error) {
	// pNextEntInf referent ID (pointer to next entry, or 0 for end of list)
	var nextRef uint32
	if err := binary.Read(r, le, &nextRef); err != nil {
		return nil, false, fmt.Errorf("failed to read pNextEntInf: %w", err)
	}

	entry := &ENTINF{}

	// ENTINF.pName referent ID
	var pNameRef uint32
	binary.Read(r, le, &pNameRef)

	// ENTINF.ulFlags
	binary.Read(r, le, &entry.UlFlags)

	// ENTINF.AttrBlock
	binary.Read(r, le, &entry.AttrBlock.AttrCount)

	// pAttr referent ID
	var pAttrRef uint32
	binary.Read(r, le, &pAttrRef)

	// fIsNCPrefix
	var fIsNCPrefix uint32
	binary.Read(r, le, &fIsNCPrefix)

	// pParentGuid referent ID (MS-DRSR 4.1.10.2.11)
	var pParentGuidRef uint32
	binary.Read(r, le, &pParentGuidRef)

	// pMetaDataExt referent ID (PROPERTY_META_DATA_EXT_VECTOR*)
	var pMetaDataExtRef uint32
	binary.Read(r, le, &pMetaDataExtRef)

	// -- Deferred data for this entry --
	// NDR deferred pointer order: pNextEntInf, pName, pAttr, pParentGuid, pMetaDataExt

	// pName (DSNAME — conformant struct, max_count hoisted)
	if pNameRef != 0 {
		var maxCount uint32
		binary.Read(r, le, &maxCount)
		dsname, err := unmarshalDSNAME(r)
		if err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal ENTINF DSNAME: %w", err)
		}
		entry.PName = dsname
		ndrAlignReader(r, 4)
	}

	// ATTRBLOCK (array of ATTRs)
	if pAttrRef != 0 && entry.AttrBlock.AttrCount > 0 {
		err := unmarshalATTRBLOCK(r, &entry.AttrBlock)
		if err != nil {
			return nil, false, fmt.Errorf("failed to unmarshal ATTRBLOCK: %w", err)
		}
	}

	// pParentGuid deferred (16-byte GUID)
	if pParentGuidRef != 0 {
		var guid [16]byte
		io.ReadFull(r, guid[:])
	}

	// pMetaDataExt deferred (PROPERTY_META_DATA_EXT_VECTOR — conformant struct)
	if pMetaDataExtRef != 0 {
		if err := skipPropertyMetaDataExtVector(r); err != nil {
			return nil, false, fmt.Errorf("failed to skip pMetaDataExt: %w", err)
		}
	}

	return entry, nextRef != 0, nil
}

// skipPropertyMetaDataExtVector consumes a PROPERTY_META_DATA_EXT_VECTOR from
// the NDR stream. Each entry is PROPERTY_META_DATA_EXT:
//
//	DWORD dwVersion (4) + FILETIME timeChanged (8) + UUID uuidDsaOriginating (16) + USN usnOriginating (8) = 36 bytes
//
// The struct is conformant (rgMetaData is [size_is(cNumProps)]).
func skipPropertyMetaDataExtVector(r *bytes.Reader) error {
	// Hoisted conformant max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	// cNumProps
	var cNumProps uint32
	binary.Read(r, le, &cNumProps)

	// Each PROPERTY_META_DATA_EXT: dwVersion(4) + timeChanged(8) + uuid(16) + usn(8)
	// USN is UHYPER (8-byte aligned), so pad after uuid: offset 28 → aligned to 32
	// Entry size = 4 + 8 + 16 + 4(pad) + 8 = 40? No...
	// Actually: dwVersion at 0, timeChanged at 4, uuid at 12, usn at 28.
	// 28 is not 8-aligned, so pad 4 → usn at 32. Total per entry = 40.
	// But array elements are tightly packed after the first, with stride = struct size.
	// Let's align before the array for the first entry's UHYPER.
	ndrAlignReader(r, 8)

	// Each entry is 40 bytes (with 4 bytes padding before USN)
	const entrySize = 40
	skip := int64(cNumProps) * entrySize
	_, err := r.Seek(skip, io.SeekCurrent)
	return err
}

// unmarshalATTRBLOCK reads the attribute block for a replicated entry.
func unmarshalATTRBLOCK(r *bytes.Reader, ab *ATTRBLOCK) error {
	// Conformant array max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	ab.PAttr = make([]ATTR, ab.AttrCount)

	// Read inline ATTR headers: AttrTyp + ValCount + pVal referent ID
	type attrHdr struct {
		AttrTyp  uint32
		ValCount uint32
		PValRef  uint32
	}

	hdrs := make([]attrHdr, ab.AttrCount)
	for i := uint32(0); i < ab.AttrCount; i++ {
		binary.Read(r, le, &hdrs[i].AttrTyp)
		binary.Read(r, le, &hdrs[i].ValCount)
		binary.Read(r, le, &hdrs[i].PValRef)
		ab.PAttr[i].AttrTyp = ATTRTYP(hdrs[i].AttrTyp)
		ab.PAttr[i].AttrVal.ValCount = hdrs[i].ValCount
	}

	// Read deferred ATTRVALBLOCK data
	for i := uint32(0); i < ab.AttrCount; i++ {
		if hdrs[i].PValRef == 0 || hdrs[i].ValCount == 0 {
			continue
		}
		err := unmarshalATTRVALBLOCK(r, &ab.PAttr[i].AttrVal)
		if err != nil {
			return fmt.Errorf("failed to unmarshal ATTRVALBLOCK for attr %d: %w", i, err)
		}
	}

	return nil
}

// unmarshalATTRVALBLOCK reads the value block for a single attribute.
func unmarshalATTRVALBLOCK(r *bytes.Reader, avb *ATTRVALBLOCK) error {
	// Conformant array max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	avb.PVal = make([]ATTRVAL, avb.ValCount)

	// Read inline ATTRVAL headers: ValLen + pVal referent ID
	type valHdr struct {
		ValLen uint32
		PRef   uint32
	}

	hdrs := make([]valHdr, avb.ValCount)
	for i := uint32(0); i < avb.ValCount; i++ {
		binary.Read(r, le, &hdrs[i].ValLen)
		binary.Read(r, le, &hdrs[i].PRef)
		avb.PVal[i].ValLen = hdrs[i].ValLen
	}

	// Read deferred value data
	for i := uint32(0); i < avb.ValCount; i++ {
		if hdrs[i].PRef == 0 {
			continue
		}
		// Conformant array max_count
		var arrMaxCount uint32
		binary.Read(r, le, &arrMaxCount)

		valData := make([]byte, hdrs[i].ValLen)
		r.Read(valData)
		avb.PVal[i].PVal = valData

		// Pad to 4-byte alignment
		if pad := (4 - (hdrs[i].ValLen % 4)) % 4; pad > 0 {
			r.Seek(int64(pad), io.SeekCurrent)
		}
	}

	return nil
}

// marshalDCInfoReq creates the request buffer for IDL_DRSDomainControllerInfo.
func marshalDCInfoReq(handle []byte, domain string, infoLevel uint32) ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 128))

	// DRS_HANDLE
	w.Write(handle)

	// dwInVersion = 1
	binary.Write(w, le, uint32(1))
	// Union switch = 1
	binary.Write(w, le, uint32(1))

	// DRS_MSG_DCINFOREQ_V1:
	// Domain referent ID
	var refId uint32 = 1
	binary.Write(w, le, refId)

	// InfoLevel
	binary.Write(w, le, infoLevel)

	// Deferred domain string
	msdtyp.WriteConformantVaryingString(w, domain, true)

	return w.Bytes(), nil
}

// unmarshalDCInfoResp parses the response from IDL_DRSDomainControllerInfo.
func unmarshalDCInfoResp(data []byte, infoLevel uint32) ([]DCInfo, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("DCInfo response too short: %d bytes", len(data))
	}

	r := bytes.NewReader(data)

	var outVersion uint32
	binary.Read(r, le, &outVersion)

	var unionSwitch uint32
	binary.Read(r, le, &unionSwitch)

	// cItems
	var cItems uint32
	binary.Read(r, le, &cItems)

	// rItems referent ID
	var rItemsRef uint32
	binary.Read(r, le, &rItemsRef)

	if rItemsRef == 0 || cItems == 0 {
		return nil, nil
	}

	// Conformant array max_count
	var maxCount uint32
	binary.Read(r, le, &maxCount)

	if outVersion == 2 || outVersion == 3 {
		return unmarshalDCInfoV2Items(r, cItems)
	}

	return nil, fmt.Errorf("unsupported DCInfo response version: %d", outVersion)
}

// unmarshalDCInfoV2Items parses DS_DOMAIN_CONTROLLER_INFO_2W items.
// Wire layout per item (MS-DRSR 4.1.10.2.6):
//   7 string pointers + 3 BOOLs + 4 GUIDs (SiteObj, Computer, Server, NtdsDsa)
func unmarshalDCInfoV2Items(r *bytes.Reader, count uint32) ([]DCInfo, error) {
	type dcInfoHdr struct {
		NetbiosNameRef     uint32
		DnsHostNameRef     uint32
		SiteNameRef        uint32
		SiteObjectRef      uint32
		ComputerObjDNRef   uint32
		ServerObjDNRef     uint32
		NtdsDsaObjDNRef    uint32
		FIsPDC             uint32
		FDsEnabled         uint32
		FIsGC              uint32
		SiteObjectGuid     [16]byte
		ComputerObjectGuid [16]byte
		ServerObjectGuid   [16]byte
		NtdsDsaObjectGuid  [16]byte
	}

	hdrs := make([]dcInfoHdr, count)
	for i := uint32(0); i < count; i++ {
		binary.Read(r, le, &hdrs[i].NetbiosNameRef)
		binary.Read(r, le, &hdrs[i].DnsHostNameRef)
		binary.Read(r, le, &hdrs[i].SiteNameRef)
		binary.Read(r, le, &hdrs[i].SiteObjectRef)
		binary.Read(r, le, &hdrs[i].ComputerObjDNRef)
		binary.Read(r, le, &hdrs[i].ServerObjDNRef)
		binary.Read(r, le, &hdrs[i].NtdsDsaObjDNRef)
		binary.Read(r, le, &hdrs[i].FIsPDC)
		binary.Read(r, le, &hdrs[i].FDsEnabled)
		binary.Read(r, le, &hdrs[i].FIsGC)
		r.Read(hdrs[i].SiteObjectGuid[:])
		r.Read(hdrs[i].ComputerObjectGuid[:])
		r.Read(hdrs[i].ServerObjectGuid[:])
		r.Read(hdrs[i].NtdsDsaObjectGuid[:])
	}

	results := make([]DCInfo, count)
	for i := uint32(0); i < count; i++ {
		results[i].SiteObjectGuid = hdrs[i].SiteObjectGuid
		results[i].ComputerObjectGuid = hdrs[i].ComputerObjectGuid
		results[i].ServerObjectGuid = hdrs[i].ServerObjectGuid
		results[i].NtdsDsaObjectGuid = hdrs[i].NtdsDsaObjectGuid
		results[i].IsPDC = hdrs[i].FIsPDC != 0
		results[i].IsGC = hdrs[i].FIsGC != 0

		if hdrs[i].NetbiosNameRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read NetbiosName: %w", err)
			}
			results[i].NetbiosName = s
		}
		if hdrs[i].DnsHostNameRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read DnsHostName: %w", err)
			}
			results[i].DnsHostName = s
		}
		if hdrs[i].SiteNameRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read SiteName: %w", err)
			}
			results[i].SiteName = s
		}
		if hdrs[i].SiteObjectRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read SiteObjectName: %w", err)
			}
			results[i].SiteObjectName = s
		}
		if hdrs[i].ComputerObjDNRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read ComputerObjectDN: %w", err)
			}
			results[i].ComputerObjectDN = s
		}
		if hdrs[i].ServerObjDNRef != 0 {
			s, err := msdtyp.ReadConformantVaryingString(r, true)
			if err != nil {
				return nil, fmt.Errorf("failed to read ServerObjectDN: %w", err)
			}
			results[i].ServerObjectDN = s
		}
		if hdrs[i].NtdsDsaObjDNRef != 0 {
			// Read but discard (not in our output struct)
			msdtyp.ReadConformantVaryingString(r, true)
		}
	}

	return results, nil
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

