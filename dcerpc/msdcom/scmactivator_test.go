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
package msdcom

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestBuildInstantiationInfo(t *testing.T) {
	clsid := mustGUID("49b2791a-b1ae-4c90-9b8e-e860ba07f889")
	iid := IID_IUnknown

	buf := buildInstantiationInfo(clsid, iid)

	// Expected: 16 (classId) + 4*6 (fixed fields) + 4 (COMVERSION) + 4 (maxCount) + 16 (IID) = 68
	if len(buf) != 68 {
		t.Fatalf("expected 68 bytes, got %d", len(buf))
	}

	// Check classId
	if !bytes.Equal(buf[0:16], clsid[:]) {
		t.Fatalf("classId mismatch")
	}

	// Check classCtx = CLSCTX_LOCAL_SERVER (0x4)
	if le.Uint32(buf[16:20]) != 0x04 {
		t.Fatalf("expected classCtx 0x4, got 0x%x", le.Uint32(buf[16:20]))
	}

	// Check cIID = 1
	if le.Uint32(buf[28:32]) != 1 {
		t.Fatalf("expected cIID 1, got %d", le.Uint32(buf[28:32]))
	}

	// Check pIID referent ID (non-zero)
	if le.Uint32(buf[36:40]) == 0 {
		t.Fatal("expected non-null pIID referent ID")
	}

	// Check COMVERSION {5, 7}
	if le.Uint16(buf[44:46]) != 5 || le.Uint16(buf[46:48]) != 7 {
		t.Fatalf("expected COMVERSION {5, 7}, got {%d, %d}", le.Uint16(buf[44:46]), le.Uint16(buf[46:48]))
	}

	// Check maxCount for IID array
	if le.Uint32(buf[48:52]) != 1 {
		t.Fatalf("expected maxCount 1, got %d", le.Uint32(buf[48:52]))
	}

	// Check IID
	if !bytes.Equal(buf[52:68], iid[:]) {
		t.Fatalf("IID mismatch")
	}
}

func TestBuildActivationContextInfo(t *testing.T) {
	buf := buildActivationContextInfo()
	if len(buf) != 24 {
		t.Fatalf("expected 24 bytes, got %d", len(buf))
	}
	// All zeros
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected zero at offset %d, got 0x%02x", i, b)
		}
	}
}

func TestBuildLocationInfo(t *testing.T) {
	buf := buildLocationInfo()
	if len(buf) != 16 {
		t.Fatalf("expected 16 bytes, got %d", len(buf))
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("expected zero at offset %d, got 0x%02x", i, b)
		}
	}
}

func TestBuildScmRequestInfo(t *testing.T) {
	buf := buildScmRequestInfo()

	// pdwReserved(4) + remoteRequest ptr(4) + ClientImpLevel(4) + cReqProtseqs(2) + pad(2) +
	// pReqProtseqs ptr(4) + maxCount(4) + protseq(2) = 26 bytes
	if len(buf) != 26 {
		t.Fatalf("expected 26 bytes, got %d", len(buf))
	}

	// Check pdwReserved = null
	if le.Uint32(buf[0:4]) != 0 {
		t.Fatal("expected pdwReserved NULL")
	}

	// Check remoteRequest ptr non-null
	if le.Uint32(buf[4:8]) == 0 {
		t.Fatal("expected non-null remoteRequest ptr")
	}

	// Check ClientImpLevel = 2
	if le.Uint32(buf[8:12]) != 2 {
		t.Fatalf("expected ClientImpLevel 2, got %d", le.Uint32(buf[8:12]))
	}

	// Check cRequestedProtseqs = 1
	if le.Uint16(buf[12:14]) != 1 {
		t.Fatalf("expected cRequestedProtseqs 1, got %d", le.Uint16(buf[12:14]))
	}

	// Check protseq = 7 (ncacn_ip_tcp)
	if le.Uint16(buf[24:26]) != 7 {
		t.Fatalf("expected protseq 7, got %d", le.Uint16(buf[24:26]))
	}
}

func TestBuildCustomHeader(t *testing.T) {
	clsids := [][16]byte{
		CLSID_InstantiationInfo,
		CLSID_ActivationContextInfo,
		CLSID_LocationInfo,
		CLSID_ScmRequestInfo,
	}
	sizes := []uint32{88, 40, 32, 48}
	totalSize := uint32(0) // placeholder

	buf := buildCustomHeader(totalSize, clsids, sizes)

	// destCtx at offset 12
	if le.Uint32(buf[12:16]) != 2 {
		t.Fatalf("expected destCtx 2, got %d", le.Uint32(buf[12:16]))
	}

	// cIfs at offset 16
	if le.Uint32(buf[16:20]) != 4 {
		t.Fatalf("expected cIfs 4, got %d", le.Uint32(buf[16:20]))
	}

	// classInfoClsid at offset 20 should be zeros
	for i := 20; i < 36; i++ {
		if buf[i] != 0 {
			t.Fatalf("expected zero at classInfoClsid offset %d", i-20)
		}
	}

	// pclsid ptr at offset 36 (non-null)
	if le.Uint32(buf[36:40]) == 0 {
		t.Fatal("expected non-null pclsid ptr")
	}

	// pSizes ptr at offset 40 (non-null)
	if le.Uint32(buf[40:44]) == 0 {
		t.Fatal("expected non-null pSizes ptr")
	}

	// NDR alignment padding at offset 44 (4 bytes to reach 48)
	if le.Uint32(buf[44:48]) != 0 {
		t.Fatalf("expected NDR alignment padding 0, got %d", le.Uint32(buf[44:48]))
	}

	// CLSID array starts at offset 48: maxCount(4) + 4 GUIDs
	if le.Uint32(buf[48:52]) != 4 {
		t.Fatalf("expected CLSID maxCount 4, got %d", le.Uint32(buf[48:52]))
	}

	// First CLSID at offset 52
	if !bytes.Equal(buf[52:68], CLSID_InstantiationInfo[:]) {
		t.Fatal("first CLSID mismatch")
	}

	// Sizes array starts after CLSIDs: offset 52 + 4*16 = 116
	// maxCount at offset 116
	if le.Uint32(buf[116:120]) != 4 {
		t.Fatalf("expected sizes maxCount 4, got %d", le.Uint32(buf[116:120]))
	}

	// First size at offset 120
	if le.Uint32(buf[120:124]) != 88 {
		t.Fatalf("expected first size 88, got %d", le.Uint32(buf[120:124]))
	}

	// Total raw size: 44 + 4(pad) + 4 + 64 + 4 + 16 = 136
	if len(buf) != 136 {
		t.Fatalf("expected 136 bytes, got %d", len(buf))
	}
}

func TestBuildActivationPropertiesIn(t *testing.T) {
	clsid := mustGUID("49b2791a-b1ae-4c90-9b8e-e860ba07f889")
	iid := IID_IUnknown

	blob := buildActivationPropertiesIn(clsid, iid)

	// Verify dwSize and dwReserved
	if len(blob) < 8 {
		t.Fatalf("blob too short: %d", len(blob))
	}

	dwSize := le.Uint32(blob[0:4])
	dwReserved := le.Uint32(blob[4:8])

	if dwReserved != 0 {
		t.Fatalf("expected dwReserved 0, got %d", dwReserved)
	}

	// dwSize should equal blob length minus 8 (dwSize + dwReserved)
	if dwSize != uint32(len(blob)-8) {
		t.Fatalf("expected dwSize %d, got %d", len(blob)-8, dwSize)
	}

	// TS1 header is 16 bytes, then CustomHeader data starts
	// headerSize at offset 8 + 16 + 4 = 28
	headerSize := le.Uint32(blob[8+ts1HeaderSize+4 : 8+ts1HeaderSize+8])
	if headerSize%8 != 0 {
		t.Fatalf("headerSize %d not 8-byte aligned", headerSize)
	}

	// CustomHeader: TS1(16) + raw(136) = 152
	if headerSize != 152 {
		t.Fatalf("expected headerSize 152, got %d", headerSize)
	}

	// totalSize at offset 8 + 16 = 24
	totalSize := le.Uint32(blob[8+ts1HeaderSize : 8+ts1HeaderSize+4])

	// totalSize == dwSize (both measure from CustomHeader to end of last property)
	if totalSize != dwSize {
		t.Fatalf("totalSize (%d) != dwSize (%d)", totalSize, dwSize)
	}

	// Verify TS1 CommonHeader signature at offset 8
	if blob[8] != 0x01 || blob[9] != 0x10 {
		t.Fatalf("expected TS1 CommonHeader at offset 8, got %02x %02x", blob[8], blob[9])
	}

	// Total blob: 8 + dwSize
	expectedLen := 8 + int(dwSize)
	if len(blob) != expectedLen {
		t.Fatalf("expected blob length %d, got %d", expectedLen, len(blob))
	}
}

func TestMarshalRemoteCreateInstanceRequest(t *testing.T) {
	cid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	clsid := mustGUID("49b2791a-b1ae-4c90-9b8e-e860ba07f889")
	iid := IID_IUnknown

	buf := marshalRemoteCreateInstanceRequest(cid, clsid, iid)

	// Check ORPCTHIS at offset 0
	if le.Uint16(buf[0:2]) != 5 || le.Uint16(buf[2:4]) != 7 {
		t.Fatalf("ORPCTHIS version mismatch")
	}

	// Causality ID at offset 12
	if !bytes.Equal(buf[12:28], cid[:]) {
		t.Fatalf("causality ID mismatch")
	}

	// Extensions ptr NULL at offset 28
	if le.Uint32(buf[28:32]) != 0 {
		t.Fatal("expected NULL extensions ptr")
	}

	// pUnkOuter at offset 32 = NULL
	if le.Uint32(buf[32:36]) != 0 {
		t.Fatal("expected NULL pUnkOuter")
	}

	// pActProperties at offset 36 = non-null referent ID
	if le.Uint32(buf[36:40]) == 0 {
		t.Fatal("expected non-null pActProperties referent ID")
	}

	// MInterfacePointer starts at offset 40
	// max_count at 40, ulCntData at 44
	maxCount := le.Uint32(buf[40:44])
	ulCntData := le.Uint32(buf[44:48])
	if maxCount != ulCntData {
		t.Fatalf("maxCount (%d) != ulCntData (%d)", maxCount, ulCntData)
	}

	// OBJREF signature at offset 48
	if le.Uint32(buf[48:52]) != OBJREFSignature {
		t.Fatalf("expected MEOW signature, got 0x%08x", le.Uint32(buf[48:52]))
	}

	// OBJREF flags = OBJREF_CUSTOM at offset 52
	if le.Uint32(buf[52:56]) != OBJREFCustom {
		t.Fatalf("expected OBJREF_CUSTOM, got 0x%08x", le.Uint32(buf[52:56]))
	}

	// IID at offset 56
	if !bytes.Equal(buf[56:72], IID_IActivationPropertiesIn[:]) {
		t.Fatal("IID mismatch")
	}

	// CLSID at offset 72
	if !bytes.Equal(buf[72:88], CLSID_ActivationPropertiesIn[:]) {
		t.Fatal("CLSID mismatch")
	}

	// TS1 header should appear after OBJREF_CUSTOM header (at offset 96 + 8 = 104)
	// Blob starts at 96 (48 OBJREF header + 4 cbExtension + 4 size + 4 dwSize + 4 dwReserved)
	// Actually: OBJREF(48) + cbExt(4) + size(4) = 56 OBJREF overhead, data at 48+8+16+16+4+4 = 96
	// Then dwSize(4) + dwReserved(4) = 8, then TS1 at offset 104
	if buf[104] != 0x01 || buf[105] != 0x10 {
		t.Fatalf("expected TS1 CommonHeader at blob start, got %02x %02x", buf[104], buf[105])
	}
}

func TestPadTo8(t *testing.T) {
	tests := []struct {
		inputLen  int
		expectLen int
	}{
		{0, 0},
		{1, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{16, 16},
		{26, 32},
		{132, 136},
	}

	for _, tc := range tests {
		input := make([]byte, tc.inputLen)
		result := padTo8(input)
		if len(result) != tc.expectLen {
			t.Errorf("padTo8(%d) = %d, want %d", tc.inputLen, len(result), tc.expectLen)
		}
	}
}

// TestUnmarshalRemoteCreateInstanceResponse builds a synthetic response
// and verifies the parser extracts the correct fields.
func TestUnmarshalRemoteCreateInstanceResponse(t *testing.T) {
	ipidRemUnknown := [16]byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0}
	interfaceIPID := [16]byte{0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0}
	oxid := uint64(0x1122334455667788)
	ifOxid := uint64(0xaabbccddeeff0011)
	ifOid := uint64(0x2233445566778899)

	// Build ScmReplyInfo property buffer
	scmReply := buildScmReplyInfoTestData(oxid, ipidRemUnknown)

	// Build PropsOutInfo property buffer
	propsOut := buildPropsOutInfoTestData(interfaceIPID, ifOxid, ifOid)

	// Wrap property buffers with TS1 headers (as Windows responses do)
	scmReplyWrapped := wrapTS1(scmReply)
	propsOutWrapped := wrapTS1(propsOut)

	// Build CustomHeader for 2 properties (sizes include TS1 wrapping)
	clsids := [][16]byte{CLSID_ScmReplyInfo, CLSID_PropsOutInfo}
	sizes := []uint32{uint32(len(scmReplyWrapped)), uint32(len(propsOutWrapped))}
	totalSize := sizes[0] + sizes[1]

	customHeaderRaw := buildCustomHeader(totalSize, clsids, sizes)
	customHeaderWrapped := wrapTS1(customHeaderRaw)
	headerSize := uint32(len(customHeaderWrapped))
	// Patch headerSize in the CustomHeader data (at offset ts1HeaderSize+4)
	le.PutUint32(customHeaderWrapped[ts1HeaderSize+4:ts1HeaderSize+8], headerSize)

	// Build ActivationPropertiesBlob
	dwSize := headerSize + totalSize
	actProps := make([]byte, 0, 8+int(dwSize))
	actProps = binary.LittleEndian.AppendUint32(actProps, dwSize)
	actProps = binary.LittleEndian.AppendUint32(actProps, 0)
	actProps = append(actProps, customHeaderWrapped...)
	actProps = append(actProps, scmReplyWrapped...)
	actProps = append(actProps, propsOutWrapped...)

	// Wrap in OBJREF_CUSTOM
	objref := MarshalOBJREFCustom(IID_IActivationPropertiesOut, CLSID_ActivationPropertiesOut, actProps)

	// Wrap in MInterfacePointer
	mip := MarshalMInterfacePointer(objref)

	// Build full response stub
	resp := make([]byte, 0, 200+len(mip))

	// ORPCTHAT (null extensions)
	resp = binary.LittleEndian.AppendUint32(resp, 0) // flags
	resp = binary.LittleEndian.AppendUint32(resp, 0) // extensions = NULL

	// ppActProperties referent ID
	resp = binary.LittleEndian.AppendUint32(resp, 0x00020000)

	// MInterfacePointer (deferred)
	resp = append(resp, mip...)

	// ErrorCode = 0 (success)
	resp = binary.LittleEndian.AppendUint32(resp, 0)

	// Parse!
	result, err := unmarshalRemoteCreateInstanceResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	if result.OXID != oxid {
		t.Fatalf("OXID mismatch: 0x%x vs 0x%x", result.OXID, oxid)
	}
	if result.IpidRemUnknown != ipidRemUnknown {
		t.Fatalf("IpidRemUnknown mismatch")
	}
	if result.InterfaceIPID != interfaceIPID {
		t.Fatalf("InterfaceIPID mismatch")
	}
	if result.InterfaceOXID != ifOxid {
		t.Fatalf("InterfaceOXID mismatch: 0x%x vs 0x%x", result.InterfaceOXID, ifOxid)
	}
	if result.InterfaceOID != ifOid {
		t.Fatalf("InterfaceOID mismatch: 0x%x vs 0x%x", result.InterfaceOID, ifOid)
	}
	if result.ServerVersion.MajorVersion != 5 || result.ServerVersion.MinorVersion != 7 {
		t.Fatalf("ServerVersion mismatch: %d.%d", result.ServerVersion.MajorVersion, result.ServerVersion.MinorVersion)
	}
}

// --- Test data builders ---

// buildScmReplyInfoTestData builds a minimal ScmReplyInfoData buffer for testing.
func buildScmReplyInfoTestData(oxid uint64, ipidRemUnknown [16]byte) []byte {
	buf := make([]byte, 0, 80)

	// pdwReserved = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	// remoteReply referent ID
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)

	// customREMOTE_REPLY_SCM_INFO:
	// OXID
	buf = binary.LittleEndian.AppendUint64(buf, oxid)
	// pdsaOxidBindings referent ID
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)
	// ipidRemUnknown
	buf = append(buf, ipidRemUnknown[:]...)
	// authnHint
	buf = binary.LittleEndian.AppendUint32(buf, 10)
	// COMVERSION {5, 7}
	buf = binary.LittleEndian.AppendUint16(buf, 5)
	buf = binary.LittleEndian.AppendUint16(buf, 7)

	// Deferred DUALSTRINGARRAY: NDR conformant maxCount + structure
	dsa := DUALSTRINGARRAY{
		NumEntries:     2,
		SecurityOffset: 1,
		StringArray:    []uint16{0, 0},
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(dsa.NumEntries)) // NDR conformant maxCount
	buf = append(buf, dsa.MarshalBinary()...)

	return buf
}

// buildPropsOutInfoTestData builds a minimal PropsOutInfo buffer for testing.
func buildPropsOutInfoTestData(ipid [16]byte, oxid, oid uint64) []byte {
	buf := make([]byte, 0, 200)

	// cIfs = 1
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	// piid ptr
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	// phresults ptr
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)
	// ppIntfData ptr
	buf = binary.LittleEndian.AppendUint32(buf, 0x00060000)

	// Deferred piid: maxCount + IID
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = append(buf, IID_IUnknown[:]...)

	// Deferred phresults: maxCount + HRESULT
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint32(buf, 0) // S_OK

	// Deferred ppIntfData: maxCount + referent IDs
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00080000) // referent ID for MIP[0]

	// MInterfacePointer[0] containing OBJREF_STANDARD
	std := STDOBJREF{
		Flags:       0,
		CPublicRefs: 5,
		OXID:        oxid,
		OID:         oid,
		IPID:        ipid,
	}
	dsa := DUALSTRINGARRAY{
		NumEntries:     2,
		SecurityOffset: 1,
		StringArray:    []uint16{0, 0},
	}

	// Build OBJREF_STANDARD
	objref := make([]byte, 0, 100)
	objref = binary.LittleEndian.AppendUint32(objref, OBJREFSignature)
	objref = binary.LittleEndian.AppendUint32(objref, OBJREFStandard)
	objref = append(objref, IID_IUnknown[:]...)
	objref = append(objref, std.MarshalBinary()...)
	objref = append(objref, dsa.MarshalBinary()...)

	// Wrap in MInterfacePointer
	mip := MarshalMInterfacePointer(objref)
	buf = append(buf, mip...)

	return buf
}
