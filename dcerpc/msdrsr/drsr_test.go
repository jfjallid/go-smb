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
)

// TestMarshalGetNCChangesReqHexDump generates and prints the exact bytes of a
// GetNCChanges request for manual inspection and comparison.
func TestMarshalGetNCChangesReqHexDump(t *testing.T) {
	handle := make([]byte, 20) // zero handle for testing
	ncDN := "CN=Administrator,CN=Users,DC=test,DC=com"
	objectGuid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	usnFrom := USNVector{}
	mode := DCSyncNTLMOnly

	for _, useV10 := range []bool{false, true} {
		label := "V8"
		if useV10 {
			label = "V10"
		}
		t.Run(label, func(t *testing.T) {
			dsaGuid := [16]byte{0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
				0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF}
			buf, err := marshalGetNCChangesReq(handle, ncDN, objectGuid, dsaGuid, ExopReplObj, usnFrom, nil, useV10, mode)
			if err != nil {
				t.Fatalf("marshalGetNCChangesReq failed: %v", err)
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
		SiteObjGuid:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Pid:              1234,
		ReplicationEpoch: 0,
		FlagsExt:         0x04000000,
		ConfigObjGuid:    [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1},
	}

	data, err := ext.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	if len(data) != 48 {
		t.Fatalf("expected 48 bytes, got %d", len(data))
	}

	var ext2 DRSExtensionsInt
	err = ext2.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
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
	err := ext.UnmarshalBinary(data)
	if err != nil {
		t.Fatalf("UnmarshalBinary failed for partial data: %v", err)
	}
	if ext.Flags != 0x00000A01 {
		t.Errorf("Flags mismatch: got 0x%08x, want 0x00000A01", ext.Flags)
	}
	if ext.Pid != 0 || ext.ReplicationEpoch != 0 {
		t.Errorf("Expected zero fields for partial unmarshal")
	}
}

func TestDSNAMERoundTrip(t *testing.T) {
	dsname := &DSNAME{
		Guid:       [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAA, 0xBB},
		StringName: "DC=contoso,DC=com",
	}

	data, err := dsname.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	r := bytes.NewReader(data)
	dsname2, err := unmarshalDSNAME(r)
	if err != nil {
		t.Fatalf("unmarshalDSNAME failed: %v", err)
	}

	if dsname2.Guid != dsname.Guid {
		t.Errorf("Guid mismatch")
	}
	if dsname2.StringName != dsname.StringName {
		t.Errorf("StringName mismatch: got %q, want %q", dsname2.StringName, dsname.StringName)
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

	binary.Write(&buf, le, uint32(0))   // Reserved1
	binary.Write(&buf, le, uint32(0))   // Length
	binary.Write(&buf, le, uint16(0))   // Reserved2
	binary.Write(&buf, le, uint16(0))   // Reserved3
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

	buf.WriteByte(0x31) // Reserved1
	buf.WriteByte(0x00) // Reserved2
	buf.WriteByte(0x01) // Version
	buf.WriteByte(0x03) // NumberOfHashes
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

