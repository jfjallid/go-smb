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

func TestMarshalNTLMLoginRequest(t *testing.T) {
	// Build the stub data matching wbemNTLMLogin's layout
	namespace := "//./root/cimv2"

	buf := make([]byte, 0, 96)

	// NDR top-level pointer: referent_id + LPWSTR body inline
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalLPWSTRBody(namespace)...)
	buf = padTo4(buf)
	buf = binary.LittleEndian.AppendUint32(buf, 0) // strPreferredLocale = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0) // lFlags = 0
	buf = binary.LittleEndian.AppendUint32(buf, 0) // pCtx = NULL

	// referent_id at offset 0
	if le.Uint32(buf[0:4]) != 0x00020000 {
		t.Fatal("strNetworkResource referent ID mismatch")
	}
	// LPWSTR maxCount = 15 (14 chars + null terminator)
	if le.Uint32(buf[4:8]) != 15 {
		t.Fatalf("LPWSTR maxCount: expected 15, got %d", le.Uint32(buf[4:8]))
	}
	// offset = 0
	if le.Uint32(buf[8:12]) != 0 {
		t.Fatalf("LPWSTR offset: expected 0, got %d", le.Uint32(buf[8:12]))
	}
	// actualCount = 15
	if le.Uint32(buf[12:16]) != 15 {
		t.Fatalf("LPWSTR actualCount: expected 15, got %d", le.Uint32(buf[12:16]))
	}

	// After LPWSTR data (30 bytes) + 2 bytes padding: locale, flags, ctx
	// offset = 4 (ref) + 12 (header) + 30 (data) = 46, padded to 48
	if le.Uint32(buf[48:52]) != 0 {
		t.Fatal("strPreferredLocale should be NULL")
	}
	if le.Uint32(buf[52:56]) != 0 {
		t.Fatal("lFlags should be 0")
	}
	if le.Uint32(buf[56:60]) != 0 {
		t.Fatal("pCtx should be NULL")
	}
}

func TestMarshalGetObjectRequest(t *testing.T) {
	objectPath := "Win32_Process"

	buf := make([]byte, 0, 96)

	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalBSTRBody(objectPath)...)
	buf = padTo4(buf)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // lFlags
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // pCtx
	buf = binary.LittleEndian.AppendUint32(buf, 0x00060000) // ppObject referent_id (non-null)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ppObject max_count
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ppObject ulCntData
	buf = binary.LittleEndian.AppendUint32(buf, 0x00080000) // ppCallResult referent_id (non-null)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ppCallResult max_count
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ppCallResult ulCntData

	if le.Uint32(buf[0:4]) != 0x00020000 {
		t.Fatal("strObjectPath referent ID mismatch")
	}
	// BSTR maxCount = len("Win32_Process") = 13 (no null terminator)
	if le.Uint32(buf[4:8]) != 13 {
		t.Fatalf("BSTR maxCount: expected 13, got %d", le.Uint32(buf[4:8]))
	}
	// cBytes = 13 * 2 = 26
	if le.Uint32(buf[8:12]) != 26 {
		t.Fatalf("BSTR cBytes: expected 26, got %d", le.Uint32(buf[8:12]))
	}

	// Verify ppObject at expected offset
	// ref(4) + header(12) + data(26) + pad(2) + lFlags(4) + pCtx(4) = 52
	if le.Uint32(buf[52:56]) != 0x00060000 {
		t.Fatal("ppObject referent ID mismatch")
	}
	// ppObject empty MInterfacePointer: max_count=0, ulCntData=0
	if le.Uint32(buf[56:60]) != 0 || le.Uint32(buf[60:64]) != 0 {
		t.Fatal("ppObject MInterfacePointer should be empty")
	}
	// ppCallResult at offset 64
	if le.Uint32(buf[64:68]) != 0x00080000 {
		t.Fatal("ppCallResult referent ID mismatch")
	}
}

func TestMarshalExecMethodRequest(t *testing.T) {
	objectPath := "Win32_Process"
	methodName := "Create"

	// Build a minimal CIM instance
	inParams := make([]byte, 12)
	le.PutUint32(inParams[0:4], cimSignature)
	le.PutUint32(inParams[4:8], 1)
	inParams[8] = cimFlagInstance

	objref := MarshalOBJREFCustom(IID_IWbemClassObject, CLSID_WbemClassObject, inParams)
	mip := MarshalMInterfacePointer(objref)

	buf := make([]byte, 0, 128+len(mip))

	// strObjectPath: referent_id + BSTR body (null-terminated)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalBSTRBody(objectPath+"\x00")...)
	buf = padTo4(buf)

	// strMethodName: referent_id + BSTR body (null-terminated)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)
	buf = append(buf, MarshalBSTRBody(methodName+"\x00")...)
	buf = padTo4(buf)

	// lFlags, pCtx, pInParams
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00060000)
	buf = append(buf, mip...)
	buf = padTo4(buf)

	// ppOutParams: non-null outer pointer with NULL inner data
	buf = binary.LittleEndian.AppendUint32(buf, 0x00080000)
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// ppCallResult: NULL pointer
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	if le.Uint32(buf[0:4]) != 0x00020000 {
		t.Fatal("strObjectPath referent ID mismatch")
	}
	// objectPath BSTR with MarshalBSTRBody: maxCount=14 (13+null), cBytes=28, clSize=14
	// 4 (ref) + 12 (header) + 28 (data) = 44
	// strMethodName referent_id at offset 44
	if le.Uint32(buf[44:48]) != 0x00040000 {
		t.Fatal("strMethodName referent ID mismatch")
	}
}

func TestUnmarshalWbemObjectResponse(t *testing.T) {
	// Build a synthetic response with OBJREF_CUSTOM containing test CIM data
	// Need at least 12 bytes of data to satisfy OBJREF_CUSTOM minimum size check
	cimData := []byte{
		0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	}

	objref := MarshalOBJREFCustom(IID_IWbemClassObject, CLSID_WbemClassObject, cimData)
	mip := MarshalMInterfacePointer(objref)

	resp := make([]byte, 0, 12+len(mip))
	resp = binary.LittleEndian.AppendUint32(resp, 0x00020000) // ppObject referent ID (non-null)
	resp = binary.LittleEndian.AppendUint32(resp, 0)          // ppCallResult = NULL
	resp = append(resp, mip...)                               // deferred MInterfacePointer
	resp = binary.LittleEndian.AppendUint32(resp, 0)          // HRESULT = S_OK

	result, err := unmarshalWbemObjectResponse(resp)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result, cimData) {
		t.Fatalf("CIM data mismatch\n got:  %x\n want: %x", result, cimData)
	}
}

func TestUnmarshalWbemObjectResponseNull(t *testing.T) {
	resp := make([]byte, 12)
	le.PutUint32(resp[0:4], 0)  // ppObject = NULL
	le.PutUint32(resp[4:8], 0)  // ppCallResult = NULL
	le.PutUint32(resp[8:12], 0) // HRESULT = S_OK

	_, err := unmarshalWbemObjectResponse(resp)
	if err == nil {
		t.Fatal("expected error for NULL object")
	}
}

func TestUnmarshalWbemObjectResponseError(t *testing.T) {
	cimData := []byte{0x01, 0x02, 0x03, 0x04}
	objref := MarshalOBJREFCustom(IID_IWbemClassObject, CLSID_WbemClassObject, cimData)
	mip := MarshalMInterfacePointer(objref)

	resp := make([]byte, 0, 12+len(mip))
	resp = binary.LittleEndian.AppendUint32(resp, 0x00020000)
	resp = binary.LittleEndian.AppendUint32(resp, 0)
	resp = append(resp, mip...)
	resp = binary.LittleEndian.AppendUint32(resp, 0x80041001) // WBEM_E_FAILED

	_, err := unmarshalWbemObjectResponse(resp)
	if err == nil {
		t.Fatal("expected error for non-zero HRESULT")
	}
}

func TestWMIGUIDs(t *testing.T) {
	// Verify well-known GUIDs are parsed correctly
	tests := []struct {
		name string
		guid [16]byte
		str  string
	}{
		{"CLSID_WbemLevel1Login", CLSID_WbemLevel1Login, "8BC3F05E-D86B-11D0-A075-00C04FB68820"},
		{"IID_IWbemLevel1Login", IID_IWbemLevel1Login, "F309AD18-D86A-11D0-A075-00C04FB68820"},
		{"IID_IWbemServices", IID_IWbemServices, "9556DC99-828C-11CF-A37E-00AA003240C7"},
	}

	for _, tc := range tests {
		expected, err := GUIDFromString(tc.str)
		if err != nil {
			t.Fatalf("%s: GUIDFromString failed: %v", tc.name, err)
		}
		if tc.guid != expected {
			t.Fatalf("%s: GUID mismatch\n got:  %x\n want: %x", tc.name, tc.guid, expected)
		}
	}
}
