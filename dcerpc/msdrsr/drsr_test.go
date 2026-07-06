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
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/ndr"
)

// TestMarshalGetNCChangesReqHexDump generates and prints the exact bytes of a
// GetNCChanges request for manual inspection and comparison. Only V8 is
// exercised; V10 is not used by the DCSync code path and would require a
// separate flat request type.
func TestMarshalGetNCChangesReqHexDump(t *testing.T) {
	var handle [20]byte // zero handle for testing
	ncDN := "CN=Administrator,CN=Users,DC=test,DC=com"
	objectGuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	usnFrom := USNVector{}
	mode := DCSyncNTLMOnly

	for _, useV10 := range []bool{false} {
		label := "V8"
		if useV10 {
			label = "V10"
		}
		t.Run(label, func(t *testing.T) {
			dsaGuid := [16]byte{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
				0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}
			req, err := buildGetNCChangesReqV8(handle, ncDN, objectGuid, dsaGuid, ExopReplObj, usnFrom, nil, mode)
			if err != nil {
				t.Fatalf("buildGetNCChangesReqV8 failed: %v", err)
			}
			buf, err := req.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			t.Logf("Total buffer length: %d bytes", len(buf))
			t.Logf("Full hex dump:")
			for i := 0; i < len(buf); i += 16 {
				end := i + 16
				if end > len(buf) {
					end = len(buf)
				}
				hexStr := hex.EncodeToString(buf[i:end])
				// Add spaces between bytes
				spaced := ""
				for j := 0; j < len(hexStr); j += 2 {
					if j > 0 {
						spaced += " "
					}
					spaced += hexStr[j : j+2]
				}
				t.Logf("  %04x: %s", i, spaced)
			}

			// Annotate key offsets
			off := 0
			t.Logf("\nAnnotated layout:")
			t.Logf("  [%04x] DRS_HANDLE (20 bytes)", off)
			off += 20
			t.Logf("  [%04x] dwInVersion: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] union tag: %d", off, le.Uint32(buf[off:]))
			off += 4
			// NDR alignment: V8 arm has alignment 8 (contains HYPER fields)
			if pad := (8 - (off % 8)) % 8; pad > 0 {
				t.Logf("  [%04x] arm alignment pad (%d bytes)", off, pad)
				off += pad
			}
			t.Logf("  [%04x] uuidDsaObjDest (16 bytes): %x", off, buf[off:off+16])
			off += 16
			t.Logf("  [%04x] uuidInvocIdSrc (16 bytes): %x", off, buf[off:off+16])
			off += 16
			t.Logf("  [%04x] pNC referent ID: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			// NDR alignment: USN_VECTOR first field is HYPER (alignment 8)
			if pad := (8 - (off % 8)) % 8; pad > 0 {
				t.Logf("  [%04x] USN_VECTOR alignment pad (%d bytes)", off, pad)
				off += pad
			}
			t.Logf("  [%04x] usnvecFrom.UsnHighObjUpdate: %d", off, int64(le.Uint64(buf[off:])))
			off += 8
			t.Logf("  [%04x] usnvecFrom.UsnReserved: %d", off, int64(le.Uint64(buf[off:])))
			off += 8
			t.Logf("  [%04x] usnvecFrom.UsnHighPropUpdate: %d", off, int64(le.Uint64(buf[off:])))
			off += 8
			t.Logf("  [%04x] pUpToDateVecDest referent: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] ulFlags: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] cMaxObjects: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] cMaxBytes: 0x%x", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] ulExtendedOp: %d", off, le.Uint32(buf[off:]))
			off += 4
			// NDR alignment: liFsmoInfo is NDRUHYPER (alignment 8)
			if pad := (8 - (off % 8)) % 8; pad > 0 {
				t.Logf("  [%04x] liFsmoInfo alignment pad (%d bytes)", off, pad)
				off += pad
			}
			t.Logf("  [%04x] liFsmoInfo: %d", off, le.Uint64(buf[off:]))
			off += 8
			t.Logf("  [%04x] pPartialAttrSet referent: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] pPartialAttrSetEx referent: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] PrefixTableDest.PrefixCount: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] PrefixTableDest.pPrefixEntry: 0x%08x", off, le.Uint32(buf[off:]))
			off += 4
			if useV10 {
				t.Logf("  [%04x] ulMoreFlags: 0x%08x", off, le.Uint32(buf[off:]))
				off += 4
			}
			t.Logf("  --- Deferred data ---")
			t.Logf("  [%04x] DSNAME max_count: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] DSNAME.structLen: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] DSNAME.SidLen: %d", off, le.Uint32(buf[off:]))
			off += 4
			t.Logf("  [%04x] DSNAME.Guid: %x", off, buf[off:off+16])
			off += 16
			t.Logf("  [%04x] DSNAME.Sid: %x", off, buf[off:off+28])
			off += 28
			nameLen := le.Uint32(buf[off:])
			t.Logf("  [%04x] DSNAME.NameLen: %d", off, nameLen)
			off += 4
			nameBytes := int(nameLen+1) * 2 // NameLen chars + null terminator
			t.Logf("  [%04x] DSNAME.StringName (%d bytes UTF-16LE, %d chars + null)", off, nameBytes, nameLen)
			off += nameBytes

			// Check for padding
			if off < len(buf) {
				remaining := len(buf) - off
				t.Logf("  [%04x] Remaining %d bytes (padding + PartialAttrSet):", off, remaining)
				// Check alignment
				if off%4 != 0 {
					pad := (4 - (off % 4)) % 4
					t.Logf("  [%04x] alignment padding: %d bytes", off, pad)
					off += pad
				}
				t.Logf("  [%04x] PartialAttrSet max_count: %d", off, le.Uint32(buf[off:]))
				off += 4
				t.Logf("  [%04x] PartialAttrSet.Version: %d", off, le.Uint32(buf[off:]))
				off += 4
				t.Logf("  [%04x] PartialAttrSet.Reserved: %d", off, le.Uint32(buf[off:]))
				off += 4
				attrCount := le.Uint32(buf[off:])
				t.Logf("  [%04x] PartialAttrSet.Count: %d", off, attrCount)
				off += 4
				for i := uint32(0); i < attrCount && off+4 <= len(buf); i++ {
					t.Logf("  [%04x] Attr[%d]: 0x%08x", off, i, le.Uint32(buf[off:]))
					off += 4
				}

				// PrefixTableDest deferred data
				if off+4 <= len(buf) {
					prefixMaxCount := le.Uint32(buf[off:])
					t.Logf("  [%04x] PrefixTable max_count: %d", off, prefixMaxCount)
					off += 4
					type ptHdr struct {
						ndx     uint32
						prefLen uint32
						prefRef uint32
					}
					hdrs := make([]ptHdr, prefixMaxCount)
					for i := uint32(0); i < prefixMaxCount && off+12 <= len(buf); i++ {
						hdrs[i].ndx = le.Uint32(buf[off:])
						hdrs[i].prefLen = le.Uint32(buf[off+4:])
						hdrs[i].prefRef = le.Uint32(buf[off+8:])
						t.Logf("  [%04x] PrefixEntry[%d]: ndx=%d prefixLen=%d ref=0x%08x",
							off, i, hdrs[i].ndx, hdrs[i].prefLen, hdrs[i].prefRef)
						off += 12
					}
					for i := uint32(0); i < prefixMaxCount && off+4 <= len(buf); i++ {
						arrMaxCount := le.Uint32(buf[off:])
						t.Logf("  [%04x] PrefixData[%d] max_count: %d", off, i, arrMaxCount)
						off += 4
						if off+int(hdrs[i].prefLen) <= len(buf) {
							t.Logf("  [%04x] PrefixData[%d] bytes: %x", off, i, buf[off:off+int(hdrs[i].prefLen)])
							off += int(hdrs[i].prefLen)
							if pad := (4 - (int(hdrs[i].prefLen) % 4)) % 4; pad > 0 {
								off += pad
							}
						}
					}
				}
			}
			t.Logf("  [%04x] END (total %d)", off, off)
			if off != len(buf) {
				t.Errorf("Buffer length mismatch: annotated %d bytes but buffer has %d", off, len(buf))
			}
		})
	}
}

func TestDRSExtensionsIntRoundTrip(t *testing.T) {
	ext := DRSExtensionsInt{
		Flags:            DrsExtBase | DrsExtGetchgReqV8 | DrsExtGetchgReqV10,
		SiteObjGuid:      [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Pid:              1234,
		ReplicationEpoch: 0,
		FlagsExt:         0x04000000,
		ConfigObjGuid:    [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	data, err := ext.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	if len(data) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(data))
	}

	var ext2 DRSExtensionsInt
	err = ext2.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if ext2.Flags != ext.Flags {
		t.Errorf("Flags mismatch: got 0x%08x, want 0x%08x", ext2.Flags, ext.Flags)
	}
	if ext2.SiteObjGuid != ext.SiteObjGuid {
		t.Errorf("SiteObjGuid mismatch")
	}
	if ext2.Pid != ext.Pid {
		t.Errorf("Pid mismatch: got %d, want %d", ext2.Pid, ext.Pid)
	}
	if ext2.ReplicationEpoch != ext.ReplicationEpoch {
		t.Errorf("ReplicationEpoch mismatch")
	}
	if ext2.FlagsExt != ext.FlagsExt {
		t.Errorf("FlagsExt mismatch: got 0x%08x, want 0x%08x", ext2.FlagsExt, ext.FlagsExt)
	}
	if ext2.ConfigObjGuid != ext.ConfigObjGuid {
		t.Errorf("ConfigObjGuid mismatch")
	}
}

func TestDRSExtensionsIntPartialUnmarshal(t *testing.T) {
	data := []byte{0x01, 0x0A, 0x00, 0x00}
	var ext DRSExtensionsInt
	err := ext.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed for partial data: %v", err)
	}
	if ext.Flags != 0x00000A01 {
		t.Errorf("Flags mismatch: got 0x%08x, want 0x00000A01", ext.Flags)
	}
	if ext.Pid != 0 || ext.ReplicationEpoch != 0 {
		t.Errorf("Expected zero fields for partial unmarshal")
	}
}

// TestSharedWireTypeRoundTrip exercises ndr encode/decode for the wire types
// that GetNCChanges request/response builds on, so format mistakes surface here
// rather than buried in a complex composite struct.
func TestSharedWireTypeRoundTrip(t *testing.T) {
	t.Run("UPTODATEVectorV2", func(t *testing.T) {
		v := UPTODATEVectorV2{
			Version:  2,
			Reserved: 0,
			Count:    2,
			Cursors: []UPTODATECursorV2{
				{
					UuidDsa:             [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99},
					UsnHighPropUpdate:   12345,
					TimeLastSyncSuccess: 0x1d2c1b1a19181716,
				},
				{
					UuidDsa:             [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					UsnHighPropUpdate:   67890,
					TimeLastSyncSuccess: 0x0807060504030201,
				},
			},
		}
		enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
		enc.SetEndianness(binary.LittleEndian)
		buf, err := enc.Encode(&v)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var got UPTODATEVectorV2
		dec := ndr.NewDecoder(bytes.NewReader(buf), false)
		dec.SetEndianness(binary.LittleEndian)
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Count != v.Count || len(got.Cursors) != len(v.Cursors) {
			t.Fatalf("count mismatch: got %d cursors, want %d", len(got.Cursors), v.Count)
		}
		for i := range v.Cursors {
			if got.Cursors[i] != v.Cursors[i] {
				t.Errorf("cursor[%d] mismatch:\n  got:  %+v\n  want: %+v", i, got.Cursors[i], v.Cursors[i])
			}
		}
	})

	t.Run("PartialAttrSet", func(t *testing.T) {
		p := PartialAttrSet{
			Version:  1,
			Reserved: 0,
			Count:    3,
			Attrs:    []ATTRTYP{AttUnicodePwd, AttDBCSPwd, AttSAMAccountName},
		}
		enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
		enc.SetEndianness(binary.LittleEndian)
		buf, err := enc.Encode(&p)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var got PartialAttrSet
		dec := ndr.NewDecoder(bytes.NewReader(buf), false)
		dec.SetEndianness(binary.LittleEndian)
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.Count != p.Count || len(got.Attrs) != len(p.Attrs) {
			t.Fatalf("attr count mismatch: got %d, want %d", len(got.Attrs), p.Count)
		}
		for i := range p.Attrs {
			if got.Attrs[i] != p.Attrs[i] {
				t.Errorf("attr[%d]: got %d, want %d", i, got.Attrs[i], p.Attrs[i])
			}
		}
	})

	t.Run("SchemaPrefixTable", func(t *testing.T) {
		pt := SchemaPrefixTable{
			PrefixCount: 2,
			Entries: []OIDPrefix{
				{NdxVal: 0, PrefixLen: 8, Prefix: []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04}},
				{NdxVal: 1, PrefixLen: 3, Prefix: []byte{0x55, 0x04, 0x06}},
			},
		}
		enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
		enc.SetEndianness(binary.LittleEndian)
		buf, err := enc.Encode(&pt)
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		var got SchemaPrefixTable
		dec := ndr.NewDecoder(bytes.NewReader(buf), false)
		dec.SetEndianness(binary.LittleEndian)
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got.PrefixCount != pt.PrefixCount || len(got.Entries) != len(pt.Entries) {
			t.Fatalf("entry count mismatch: got %d, want %d", len(got.Entries), pt.PrefixCount)
		}
		for i := range pt.Entries {
			if got.Entries[i].NdxVal != pt.Entries[i].NdxVal {
				t.Errorf("entry[%d].NdxVal: got %d, want %d", i, got.Entries[i].NdxVal, pt.Entries[i].NdxVal)
			}
			if got.Entries[i].PrefixLen != pt.Entries[i].PrefixLen {
				t.Errorf("entry[%d].PrefixLen: got %d, want %d", i, got.Entries[i].PrefixLen, pt.Entries[i].PrefixLen)
			}
			if !bytes.Equal(got.Entries[i].Prefix, pt.Entries[i].Prefix) {
				t.Errorf("entry[%d].Prefix: got %x, want %x", i, got.Entries[i].Prefix, pt.Entries[i].Prefix)
			}
		}
	})
}

// TestDRSGetNCChangesResRoundTrip encodes a V6 reply with one REPLENTINFLIST
// entry containing DSNAME, ATTRBLOCK, pParentGuid, and pMetaDataExt, then
// decodes it back via DRSGetNCChangesRes.Unmarshal. The encoded wire bytes
// are produced by ndr.Encode so this test verifies self-consistency of the
// new response types (not wire compatibility with a live DC — that requires
// the live test).
func TestDRSGetNCChangesResRoundTrip(t *testing.T) {
	// Build a synthetic V6 reply: one entry, no chain tail.
	pNC := &DSNAME{Guid: [16]byte{0xAA, 0xBB, 0xCC, 0xDD}}
	pNC.SetName("DC=contoso,DC=com")

	entryName := &DSNAME{Guid: [16]byte{0x01, 0x02, 0x03, 0x04}}
	entryName.SetName("CN=Administrator,CN=Users,DC=contoso,DC=com")

	guid := [16]byte{0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00}

	v6 := DRSMsgGetChgReplyV6{
		UuidDsaObjSrc:  [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		UuidInvocIdSrc: [16]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		PNC:            pNC,
		UsnvecFrom:     USNVector{1, 2, 3},
		UsnvecTo:       USNVector{10, 20, 30},
		PUpToDateVecSrc: &UPTODATEVectorV2{
			Version: 2, Count: 1,
			Cursors: []UPTODATECursorV2{{UuidDsa: guid, UsnHighPropUpdate: 100, TimeLastSyncSuccess: 200}},
		},
		PrefixTableSrc: SchemaPrefixTable{
			PrefixCount: 1,
			Entries:     []OIDPrefix{{NdxVal: 0, PrefixLen: 3, Prefix: []byte{0x55, 0x04, 0x06}}},
		},
		UlExtendedRet: 0,
		CNumObjects:   1,
		CNumBytes:     0,
		PObjects: &REPLENTINFLIST{
			PNextEntInfRef: 0,
			Entinf: ENTINF{
				PName:   entryName,
				UlFlags: 0,
				AttrBlock: ATTRBLOCK{
					AttrCount: 1,
					PAttr: []ATTR{{
						AttrTyp: ATTRTYP(AttUnicodePwd),
						AttrVal: ATTRVALBLOCK{
							ValCount: 1,
							PVal:     []ATTRVAL{{ValLen: 4, PVal: []byte{0xDE, 0xAD, 0xBE, 0xEF}}},
						},
					}},
				},
			},
			FIsNCPrefix:  0,
			PParentGuid:  &guid,
			PMetaDataExt: &PropertyMetaDataExtVector{CNumProps: 0, RgMetaData: nil},
		},
		FMoreData: 0,
	}

	wrap := drsGetNCChangesResWrap{
		PmsgOut: DRSMsgGetChgReplyUnion{
			Level:  6,
			Level6: v6,
		},
	}

	// dwOutVersion is sourced from the union Level field (duplicated on wire
	// by the non-encapsulated union machinery).
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	body, err := enc.Encode(&wrap)
	if err != nil {
		t.Fatalf("encode wrap: %v", err)
	}

	// Append the trailing RPC ReturnCode.
	trailer := []byte{0x00, 0x00, 0x00, 0x00}
	wire := append(body, trailer...)

	var got DRSGetNCChangesRes
	if err := got.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.DwOutVersion != 6 {
		t.Errorf("DwOutVersion: got %d want 6", got.DwOutVersion)
	}
	if got.MsgV6 == nil {
		t.Fatalf("MsgV6 is nil")
	}
	if got.MsgV6.PNC == nil || got.MsgV6.PNC.Name() != "DC=contoso,DC=com" {
		t.Errorf("PNC.Name mismatch: got %+v", got.MsgV6.PNC)
	}
	if got.UsnvecTo() != (USNVector{10, 20, 30}) {
		t.Errorf("UsnvecTo mismatch: got %+v", got.UsnvecTo())
	}
	if got.PrefixTableSrc().PrefixCount != 1 || len(got.PrefixTableSrc().Entries) != 1 {
		t.Errorf("PrefixTableSrc mismatch: got %+v", got.PrefixTableSrc())
	}
	if !bytes.Equal(got.PrefixTableSrc().Entries[0].Prefix, []byte{0x55, 0x04, 0x06}) {
		t.Errorf("Prefix bytes mismatch: got %x", got.PrefixTableSrc().Entries[0].Prefix)
	}
	if utdv := got.UpToDateVec(); utdv == nil || utdv.Count != 1 || utdv.Cursors[0].UsnHighPropUpdate != 100 {
		t.Errorf("UpToDateVec mismatch: got %+v", utdv)
	}
	if len(got.Entries) != 1 {
		t.Fatalf("Entries count: got %d want 1", len(got.Entries))
	}
	entry := got.Entries[0]
	if entry.Entinf.PName == nil || entry.Entinf.PName.Name() != "CN=Administrator,CN=Users,DC=contoso,DC=com" {
		t.Errorf("entry PName mismatch: got %+v", entry.Entinf.PName)
	}
	if entry.Entinf.AttrBlock.AttrCount != 1 || len(entry.Entinf.AttrBlock.PAttr) != 1 {
		t.Fatalf("entry AttrBlock mismatch: got %+v", entry.Entinf.AttrBlock)
	}
	attr := entry.Entinf.AttrBlock.PAttr[0]
	if attr.AttrTyp != ATTRTYP(AttUnicodePwd) || attr.AttrVal.ValCount != 1 {
		t.Errorf("attr mismatch: got %+v", attr)
	}
	if !bytes.Equal(attr.AttrVal.PVal[0].PVal, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Errorf("attr value mismatch: got %x", attr.AttrVal.PVal[0].PVal)
	}
	if entry.PParentGuid == nil || *entry.PParentGuid != guid {
		t.Errorf("PParentGuid mismatch: got %+v", entry.PParentGuid)
	}
	if got.ReturnCode != 0 {
		t.Errorf("ReturnCode: got %d want 0", got.ReturnCode)
	}
}

// TestDRSGetNCChangesResRgValuesRoundTrip verifies that a V6 reply carrying a
// non-empty rgValues (REPLVALINF_V1) array decodes correctly. The wire layout
// is: wrap(union+arm inlines+deferreds) | REPLVALINF_V1 array deferred body
// | ReturnCode. The arm's RgValuesRef and CNumValues fields drive the decode
// branch in DRSGetNCChangesRes.Unmarshal.
func TestDRSGetNCChangesResRgValuesRoundTrip(t *testing.T) {
	pNC := &DSNAME{Guid: [16]byte{0xAA}}
	pNC.SetName("DC=contoso,DC=com")
	entryName := &DSNAME{Guid: [16]byte{0x01}}
	entryName.SetName("CN=Group,DC=contoso,DC=com")

	memberDN1 := &DSNAME{Guid: [16]byte{0xA1}}
	memberDN1.SetName("CN=Alice,CN=Users,DC=contoso,DC=com")
	memberDN2 := &DSNAME{Guid: [16]byte{0xB2}}
	memberDN2.SetName("CN=Bob,CN=Users,DC=contoso,DC=com")

	linked := []ReplValInfV1{
		{
			PObject:     memberDN1,
			AttrTyp:     ATTRTYP(0x1F01),
			Aval:        ATTRVAL{ValLen: 4, PVal: []byte{0x11, 0x22, 0x33, 0x44}},
			FIsPresent:  1,
			TimeCreated: 0x01020304_05060708,
			MetaData: PropertyMetaDataExt{
				DwVersion:          1,
				FTimeChanged:       0x1122334455667788,
				UuidDsaOriginating: [16]byte{0xDE, 0xAD},
				UsnOriginating:     42,
			},
		},
		{
			PObject:     memberDN2,
			AttrTyp:     ATTRTYP(0x1F01),
			Aval:        ATTRVAL{ValLen: 2, PVal: []byte{0xFE, 0xED}},
			FIsPresent:  0,
			TimeCreated: 0x0A0B0C0D_0E0F1011,
			MetaData: PropertyMetaDataExt{
				DwVersion:          2,
				FTimeChanged:       0x2233445566778899,
				UuidDsaOriginating: [16]byte{0xBE, 0xEF},
				UsnOriginating:     43,
			},
		},
	}

	v6 := DRSMsgGetChgReplyV6{
		UuidDsaObjSrc:   [16]byte{1},
		UuidInvocIdSrc:  [16]byte{2},
		PNC:             pNC,
		UsnvecFrom:      USNVector{},
		UsnvecTo:        USNVector{5, 6, 7},
		PUpToDateVecSrc: nil,
		PrefixTableSrc:  SchemaPrefixTable{PrefixCount: 0, Entries: nil},
		UlExtendedRet:   0,
		CNumObjects:     1,
		CNumBytes:       0,
		PObjects: &REPLENTINFLIST{
			PNextEntInfRef: 0,
			Entinf: ENTINF{
				PName:     entryName,
				UlFlags:   0,
				AttrBlock: ATTRBLOCK{AttrCount: 0, PAttr: nil},
			},
			FIsNCPrefix:  0,
			PParentGuid:  nil,
			PMetaDataExt: nil,
		},
		FMoreData:         0,
		CNumNcSizeObjects: 0,
		CNumNcSizeValues:  0,
		CNumValues:        uint32(len(linked)),
		RgValuesRef:       0x00030000,
		DwDRSError:        0,
	}

	wrap := drsGetNCChangesResWrap{
		PmsgOut: DRSMsgGetChgReplyUnion{Level: 6, Level6: v6},
	}

	// Encode each top-level struct with its own Encoder so alignment
	// tracking resets between structs, matching the Unmarshal decoder's
	// per-Decode pos reset. The decoder does NOT skip padding between
	// top-level Decode calls, so the encoder must also emit each struct
	// starting from its own pos=0.
	buf := bytes.NewBuffer([]byte{})
	for _, item := range []any{&wrap, &replValInfV1Array{Values: linked}, &struct{ ReturnCode uint32 }{ReturnCode: 0}} {
		sub := bytes.NewBuffer([]byte{})
		enc := ndr.NewEncoder(sub, false)
		enc.SetEndianness(binary.LittleEndian)
		if _, err := enc.Encode(item); err != nil {
			t.Fatalf("encode %T: %v", item, err)
		}
		buf.Write(sub.Bytes())
	}
	wire := buf.Bytes()

	var got DRSGetNCChangesRes
	if err := got.Unmarshal(wire); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if got.ReturnCode != 0 {
		t.Errorf("ReturnCode: got 0x%x want 0", got.ReturnCode)
	}
	if len(got.LinkedValues) != len(linked) {
		t.Fatalf("LinkedValues count: got %d want %d", len(got.LinkedValues), len(linked))
	}
	for i, want := range linked {
		lv := got.LinkedValues[i]
		if lv.PObject == nil || lv.PObject.Name() != want.PObject.Name() {
			t.Errorf("linked[%d] pObject: got %+v want name %q", i, lv.PObject, want.PObject.Name())
		}
		if lv.AttrTyp != want.AttrTyp {
			t.Errorf("linked[%d] AttrTyp: got %d want %d", i, lv.AttrTyp, want.AttrTyp)
		}
		if lv.Aval.ValLen != want.Aval.ValLen || !bytes.Equal(lv.Aval.PVal, want.Aval.PVal) {
			t.Errorf("linked[%d] Aval: got {%d,%x} want {%d,%x}", i, lv.Aval.ValLen, lv.Aval.PVal, want.Aval.ValLen, want.Aval.PVal)
		}
		if lv.FIsPresent != want.FIsPresent {
			t.Errorf("linked[%d] FIsPresent: got %d want %d", i, lv.FIsPresent, want.FIsPresent)
		}
		if lv.TimeCreated != want.TimeCreated {
			t.Errorf("linked[%d] TimeCreated: got 0x%x want 0x%x", i, lv.TimeCreated, want.TimeCreated)
		}
		if lv.MetaData != want.MetaData {
			t.Errorf("linked[%d] MetaData: got %+v want %+v", i, lv.MetaData, want.MetaData)
		}
	}
}

// TestREPLENTINFLISTChainRoundTrip verifies that multi-entry chains decode in
// per-entry wire order: [entry_0 inline + deferreds, entry_1 inline +
// deferreds, ...]. The PNextEntInfRef uint32 is a plain referent ID rather
// than an ndr pointer so each entry's Decode call consumes exactly one entry
// worth of bytes.
func TestREPLENTINFLISTChainRoundTrip(t *testing.T) {
	makeEntry := func(name string, nextRef uint32) REPLENTINFLIST {
		dn := &DSNAME{Guid: [16]byte{}}
		dn.SetName(name)
		return REPLENTINFLIST{
			PNextEntInfRef: nextRef,
			Entinf: ENTINF{
				PName:   dn,
				UlFlags: 0,
				AttrBlock: ATTRBLOCK{
					AttrCount: 0,
					PAttr:     nil,
				},
			},
			FIsNCPrefix:  0,
			PParentGuid:  nil,
			PMetaDataExt: nil,
		}
	}

	entries := []REPLENTINFLIST{
		makeEntry("CN=Alice,DC=test", 0x00020100),
		makeEntry("CN=Bob,DC=test", 0x00020200),
		makeEntry("CN=Carol,DC=test", 0),
	}

	// Encode the chain as a single stream — each entry uses its own
	// Encoder so alignment tracking resets between entries and bytes flow
	// seamlessly (matching Windows wire format where each REPLENTINFLIST
	// entry is a self-contained unit).
	wire := bytes.NewBuffer([]byte{})
	for i := range entries {
		entryBuf := bytes.NewBuffer([]byte{})
		enc := ndr.NewEncoder(entryBuf, false)
		enc.SetEndianness(binary.LittleEndian)
		if _, err := enc.Encode(&entries[i]); err != nil {
			t.Fatalf("encode entry %d: %v", i, err)
		}
		wire.Write(entryBuf.Bytes())
	}

	// Decode via a single Decoder, mirroring DRSGetNCChangesRes.Unmarshal.
	dec := ndr.NewDecoder(bytes.NewReader(wire.Bytes()), false)
	dec.SetEndianness(binary.LittleEndian)
	for i := range entries {
		var got REPLENTINFLIST
		if err := dec.Decode(&got); err != nil {
			t.Fatalf("decode entry %d: %v", i, err)
		}
		if got.PNextEntInfRef != entries[i].PNextEntInfRef {
			t.Errorf("entry[%d] PNextEntInfRef: got 0x%x want 0x%x",
				i, got.PNextEntInfRef, entries[i].PNextEntInfRef)
		}
		wantName := entries[i].Entinf.PName.Name()
		if got.Entinf.PName == nil || got.Entinf.PName.Name() != wantName {
			t.Errorf("entry[%d] PName: got %q want %q", i, got.Entinf.PName, wantName)
		}
	}
}

func TestDSNAMERoundTrip(t *testing.T) {
	dsname := &DSNAME{
		Guid: [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB},
	}
	dsname.SetName("DC=contoso,DC=com")

	data, err := dsname.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	dsname2 := &DSNAME{}
	if err := dsname2.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if dsname2.Guid != dsname.Guid {
		t.Errorf("Guid mismatch")
	}
	if dsname2.Name() != dsname.Name() {
		t.Errorf("StringName mismatch: got %q, want %q", dsname2.Name(), dsname.Name())
	}
}

func TestStrToKey(t *testing.T) {
	rid := uint32(500)
	key1, key2 := ridToDesKeys(rid)

	if len(key1) != 8 {
		t.Fatalf("key1 length: got %d, want 8", len(key1))
	}
	if len(key2) != 8 {
		t.Fatalf("key2 length: got %d, want 8", len(key2))
	}

	if bytes.Equal(key1, key2) {
		t.Error("key1 and key2 should be different")
	}

	// Verify parity bits are set correctly (odd parity)
	for i, b := range key1 {
		bits := 0
		for j := 0; j < 8; j++ {
			if b&(1<<uint(j)) != 0 {
				bits++
			}
		}
		if bits%2 == 0 {
			t.Errorf("key1[%d] = 0x%02x has even parity", i, b)
		}
	}
}

func TestRemoveRIDEncryption(t *testing.T) {
	rid := uint32(500)
	input := make([]byte, 16)
	for i := range input {
		input[i] = byte(i)
	}

	result := RemoveRIDEncryption(input, rid, false)
	if len(result) != 16 {
		t.Fatalf("result length: got %d, want 16", len(result))
	}

	// Result should differ from input (DES decryption changes the data)
	if bytes.Equal(result, input) {
		t.Error("RemoveRIDEncryption should change the data")
	}

	// Non-16-byte input should be returned unchanged
	short := []byte{1, 2, 3}
	shortResult := RemoveRIDEncryption(short, rid, false)
	if !bytes.Equal(shortResult, short) {
		t.Error("RemoveRIDEncryption should return non-16-byte input unchanged")
	}
}

func TestDecryptSecretRC4(t *testing.T) {
	sessionKey := []byte("0123456789abcdef")
	plaintext := []byte("test secret data")

	// Build RC4 encrypted payload: Salt(16) + RC4(Checksum(4) + Data)
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 0xA0)
	}

	// Use arbitrary 4-byte checksum (algorithm is undocumented, not verified)
	checksum := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// Derive key: MD5(sessionKey + salt)
	h := md5.New()
	h.Write(sessionKey)
	h.Write(salt)
	derivedKey := h.Sum(nil)

	// RC4 encrypt checksum + plaintext together
	rc4c, err := rc4.NewCipher(derivedKey)
	if err != nil {
		t.Fatalf("rc4.NewCipher failed: %v", err)
	}
	body := append(checksum, plaintext...)
	encryptedBody := make([]byte, len(body))
	rc4c.XORKeyStream(encryptedBody, body)

	// Build payload: salt + encrypted(checksum + data)
	payload := make([]byte, 0, 16+len(encryptedBody))
	payload = append(payload, salt...)
	payload = append(payload, encryptedBody...)

	// Decrypt
	result, err := DecryptSecret(sessionKey, payload)
	if err != nil {
		t.Fatalf("DecryptSecret failed: %v", err)
	}

	if !bytes.Equal(result, plaintext) {
		t.Errorf("Decrypted data mismatch:\n  got:  %x\n  want: %x", result, plaintext)
	}
}

func TestParseGuidString(t *testing.T) {
	tests := []struct {
		input string
		want  [16]byte
	}{
		{
			input: "{12345678-abcd-ef01-2345-6789abcdef01}",
			want: [16]byte{
				0x78, 0x56, 0x34, 0x12,
				0xcd, 0xab,
				0x01, 0xef,
				0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
			},
		},
		{
			input: "00000000-0000-0000-0000-000000000000",
			want:  [16]byte{},
		},
	}

	for _, tt := range tests {
		got, err := parseGuidString(tt.input)
		if err != nil {
			t.Errorf("parseGuidString(%q) failed: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseGuidString(%q):\n  got:  %x\n  want: %x", tt.input, got, tt.want)
		}
	}
}

func TestParseGuidStringInvalid(t *testing.T) {
	_, err := parseGuidString("not-a-guid")
	if err == nil {
		t.Error("expected error for invalid GUID string")
	}
}

func TestOidFromPrefix(t *testing.T) {
	// BER encoding of 1.2.840.113556.1.4
	prefix := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04}
	lastValue := uint32(90) // unicodePwd

	oid := oidFromPrefix(prefix, lastValue)

	expected := []uint32{1, 2, 840, 113556, 1, 4, 90}
	if !oidEqual(oid, expected) {
		t.Errorf("oidFromPrefix got %v, want %v", oid, expected)
	}
}

func TestEncodeOIDPrefix(t *testing.T) {
	components := []uint32{1, 2, 840, 113556, 1, 4}
	prefix := encodeOIDPrefix(components)

	expected := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04}
	if !bytes.Equal(prefix, expected) {
		t.Errorf("encodeOIDPrefix:\n  got:  %x\n  want: %x", prefix, expected)
	}
}

func TestOidPrefixRoundTrip(t *testing.T) {
	components := []uint32{1, 2, 840, 113556, 1, 4}
	prefix := encodeOIDPrefix(components)

	// Decode back with a last value
	oid := oidFromPrefix(prefix, 42)
	expected := append(components, 42)
	if !oidEqual(oid, expected) {
		t.Errorf("Round trip mismatch: got %v, want %v", oid, expected)
	}
}

func TestSchemaPrefixTableLookup(t *testing.T) {
	prefix := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04}
	pt := SchemaPrefixTable{
		PrefixCount: 1,
		Entries: []OIDPrefix{
			{NdxVal: 0, Prefix: prefix},
		},
	}

	// unicodePwd OID = 1.2.840.113556.1.4.90 -> server-local = 0*65536 + 90 = 90
	serverAttId := ATTRTYP(90)
	resolved := pt.AttIdFromPrefixTable(serverAttId)
	if resolved != AttUnicodePwd {
		t.Errorf("AttIdFromPrefixTable(%d) = %d, want %d (AttUnicodePwd)", serverAttId, resolved, AttUnicodePwd)
	}
}

func TestSchemaPrefixTableMakeAttId(t *testing.T) {
	prefix := []byte{0x2A, 0x86, 0x48, 0x86, 0xF7, 0x14, 0x01, 0x04}
	pt := SchemaPrefixTable{
		PrefixCount: 1,
		Entries: []OIDPrefix{
			{NdxVal: 0, Prefix: prefix},
		},
	}

	attId, ok := pt.MakeAttId(AttUnicodePwd)
	if !ok {
		t.Fatal("MakeAttId failed for AttUnicodePwd")
	}
	if attId != 90 {
		t.Errorf("MakeAttId(AttUnicodePwd) = %d, want 90", attId)
	}
}

func TestPartialAttrSetMarshalNTLMOnly(t *testing.T) {
	pas := partialAttrSetForAttrs(DCSyncNTLMOnly)
	data, err := pas.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 2 identity + 2 NTLM = 4
	expectedLen := 12 + 4*4
	if len(data) != expectedLen {
		t.Errorf("PartialAttrSet marshal length: got %d, want %d", len(data), expectedLen)
	}

	version := le.Uint32(data[0:4])
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}

	count := le.Uint32(data[8:12])
	if count != 4 {
		t.Errorf("count: got %d, want 4", count)
	}
}

func TestPartialAttrSetMarshalAll(t *testing.T) {
	pas := partialAttrSetForAttrs(DCSyncAll)
	data, err := pas.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 2 identity + 2 NTLM + 3 history + 5 metadata + 1 supplementalCredentials = 13
	expectedLen := 12 + 4*13
	if len(data) != expectedLen {
		t.Errorf("PartialAttrSet marshal length: got %d, want %d", len(data), expectedLen)
	}

	version := le.Uint32(data[0:4])
	if version != 1 {
		t.Errorf("version: got %d, want 1", version)
	}

	count := le.Uint32(data[8:12])
	if count != 13 {
		t.Errorf("count: got %d, want 13", count)
	}
}

func TestPartialAttrSetMarshalKerberosOnly(t *testing.T) {
	pas := partialAttrSetForAttrs(AttrKerberos)
	data, err := pas.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 2 identity + 1 supplementalCredentials = 3
	count := le.Uint32(data[8:12])
	if count != 3 {
		t.Errorf("count: got %d, want 3", count)
	}
}

func TestPartialAttrSetMarshalNTLMAndKerberos(t *testing.T) {
	pas := partialAttrSetForAttrs(AttrNTLM | AttrKerberos)
	data, err := pas.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 2 identity + 2 NTLM + 1 supplementalCredentials = 5
	count := le.Uint32(data[8:12])
	if count != 5 {
		t.Errorf("count: got %d, want 5", count)
	}
}

func TestPartialAttrSetMarshalIdentityOnly(t *testing.T) {
	pas := partialAttrSetForAttrs(0)
	data, err := pas.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// 2 identity only
	count := le.Uint32(data[8:12])
	if count != 2 {
		t.Errorf("count: got %d, want 2", count)
	}
}

func TestDCSyncAttrsHas(t *testing.T) {
	all := DCSyncAll
	if !all.Has(AttrNTLM) {
		t.Error("DCSyncAll should have AttrNTLM")
	}
	if !all.Has(AttrKerberos) {
		t.Error("DCSyncAll should have AttrKerberos")
	}
	if !all.Has(AttrHistory) {
		t.Error("DCSyncAll should have AttrHistory")
	}
	if !all.Has(AttrMetadata) {
		t.Error("DCSyncAll should have AttrMetadata")
	}

	ntlmOnly := DCSyncNTLMOnly
	if !ntlmOnly.Has(AttrNTLM) {
		t.Error("DCSyncNTLMOnly should have AttrNTLM")
	}
	if ntlmOnly.Has(AttrKerberos) {
		t.Error("DCSyncNTLMOnly should not have AttrKerberos")
	}

	var zero DCSyncAttrs
	if zero.Has(AttrNTLM) {
		t.Error("zero flags should not have AttrNTLM")
	}
}

func TestParseSupplementalCredentials(t *testing.T) {
	var buf bytes.Buffer

	binary.Write(&buf, le, uint32(0))    // Reserved1
	binary.Write(&buf, le, uint32(0))    // Length
	binary.Write(&buf, le, uint16(0))    // Reserved2
	binary.Write(&buf, le, uint16(0))    // Reserved3
	buf.Write(make([]byte, 96))          // Reserved4
	binary.Write(&buf, le, uint16(0x50)) // PropertySignature
	binary.Write(&buf, le, uint16(1))    // PropertyCount

	propName := msdtyp.ToUnicode("Primary:CLEARTEXT")
	clearText := msdtyp.ToUnicode("password123")
	hexValue := []byte(hex.EncodeToString(clearText))

	binary.Write(&buf, le, uint16(len(propName)))
	binary.Write(&buf, le, uint16(len(hexValue)))
	binary.Write(&buf, le, uint16(0))
	buf.Write(propName)
	buf.Write(hexValue)

	sc, err := ParseSupplementalCredentials(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseSupplementalCredentials failed: %v", err)
	}

	if sc.ClearTextPassword != "password123" {
		t.Errorf("ClearTextPassword: got %q, want %q", sc.ClearTextPassword, "password123")
	}
}

func TestParseSupplementalCredentialsBadSignature(t *testing.T) {
	var buf bytes.Buffer

	binary.Write(&buf, le, uint32(0))
	binary.Write(&buf, le, uint32(0))
	binary.Write(&buf, le, uint16(0))
	binary.Write(&buf, le, uint16(0))
	buf.Write(make([]byte, 96))
	binary.Write(&buf, le, uint16(0x99)) // Wrong signature
	binary.Write(&buf, le, uint16(0))

	_, err := ParseSupplementalCredentials(buf.Bytes())
	if err == nil {
		t.Error("expected error for bad PropertySignature")
	}
}

func TestParseWDigest(t *testing.T) {
	var buf bytes.Buffer

	buf.WriteByte(0x31)         // Reserved1
	buf.WriteByte(0x00)         // Reserved2
	buf.WriteByte(0x01)         // Version
	buf.WriteByte(0x03)         // NumberOfHashes
	buf.Write(make([]byte, 12)) // Reserved3

	for i := 0; i < 3; i++ {
		hash := make([]byte, 16)
		for j := range hash {
			hash[j] = byte(i*16 + j)
		}
		buf.Write(hash)
	}

	hashes, err := parseWDigest(buf.Bytes())
	if err != nil {
		t.Fatalf("parseWDigest failed: %v", err)
	}

	if len(hashes) != 3 {
		t.Fatalf("expected 3 hashes, got %d", len(hashes))
	}

	for j := 0; j < 16; j++ {
		if hashes[0][j] != byte(j) {
			t.Errorf("hash[0][%d]: got %d, want %d", j, hashes[0][j], j)
		}
	}
}

func TestDecodeUTF16LE(t *testing.T) {
	input := []byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00}
	result := decodeUTF16LE(input)
	if result != "ABC" {
		t.Errorf("decodeUTF16LE: got %q, want %q", result, "ABC")
	}

	inputNull := []byte{0x41, 0x00, 0x42, 0x00, 0x00, 0x00}
	result2 := decodeUTF16LE(inputNull)
	if result2 != "AB" {
		t.Errorf("decodeUTF16LE with null: got %q, want %q", result2, "AB")
	}
}
