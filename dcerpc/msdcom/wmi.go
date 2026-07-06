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
// WMI (Windows Management Instrumentation) DCOM client.
// Implements IWbemLevel1Login and IWbemServices for remote command execution
// via Win32_Process.Create.
// References: [MS-WMI], [MS-WMIO]

package msdcom

import (
	"encoding/binary"
	"fmt"
)

// Well-known CLSIDs and IIDs for WMI.
var (
	CLSID_WbemLevel1Login = mustGUID("8BC3F05E-D86B-11D0-A075-00C04FB68820")
	IID_IWbemLevel1Login  = mustGUID("F309AD18-D86A-11D0-A075-00C04FB68820")
	IID_IWbemServices     = mustGUID("9556DC99-828C-11CF-A37E-00AA003240C7")
	CLSID_WbemClassObject = mustGUID("4590F812-1D3A-11D0-891F-00AA004B2E24")
	IID_IWbemClassObject  = mustGUID("DC12A681-737F-11CF-884D-00AA004B2E24")
)

// IWbemLevel1Login opnums (MS-WMI 3.1.4.4)
const (
	OpWbemNTLMLogin uint16 = 6
)

// IWbemServices opnums (MS-WMI 3.1.4.3)
const (
	OpWbemGetObject  uint16 = 6
	OpWbemExecQuery  uint16 = 20
	OpWbemExecMethod uint16 = 24
)

// IEnumWbemClassObject opnums (MS-WMI 3.1.4.6)
const (
	OpEnumNext uint16 = 4
)

// IEnumWbemClassObject IID
var IID_IEnumWbemClassObject = mustGUID("027947e1-d731-11ce-a357-000000000001")

// ExecQuery flags
const (
	wbemFlagReturnImmediately uint32 = 0x10
	wbemFlagForwardOnly       uint32 = 0x20
)

// HRESULT values for IEnumWbemClassObject::Next
const (
	wbemSOK       uint32 = 0
	wbemSFalse    uint32 = 1
	wbemSTimedout uint32 = 0x00040004
)

// WMIClient provides access to a WMI namespace via DCOM. Create one with
// NewWMIClient and use its methods to query or invoke WMI operations.
type WMIClient struct {
	conn *DCOMConnection
	svc  *COMObject // IWbemServices
}

// NewWMIClient activates IWbemLevel1Login and performs NTLMLogin to the
// given namespace (e.g., "//./root/cimv2"), returning a connected client.
func NewWMIClient(conn *DCOMConnection, namespace string) (*WMIClient, error) {
	loginObj, err := conn.CreateInstance(CLSID_WbemLevel1Login, IID_IWbemLevel1Login)
	if err != nil {
		return nil, fmt.Errorf("create WbemLevel1Login: %w", err)
	}

	svcObj, err := wbemNTLMLogin(loginObj, namespace)
	if err != nil {
		return nil, fmt.Errorf("NTLMLogin: %w", err)
	}
	loginObj.Release()

	return &WMIClient{conn: conn, svc: svcObj}, nil
}

// Query executes a WQL query and returns all result rows as maps of
// property name to value.
func (w *WMIClient) Query(wql string) ([]map[string]any, error) {
	enumObj, err := wbemExecQuery(w.svc, wql)
	if err != nil {
		return nil, fmt.Errorf("ExecQuery: %w", err)
	}

	var results []map[string]any
	var enumErr error
	for {
		blobs, done, err := enumNext(enumObj, 10, -1)
		if err != nil {
			enumErr = fmt.Errorf("enumNext: %w", err)
			break
		}
		for _, blob := range blobs {
			row, err := ParseCIMInstanceAllValues(blob)
			if err != nil {
				log.Debugf("WMIClient.Query: failed to parse instance: %v", err)
				continue
			}
			results = append(results, row)
		}
		if done {
			break
		}
	}

	enumObj.Release()

	if enumErr != nil && len(results) == 0 {
		return nil, enumErr
	}
	return results, nil
}

// GetObject retrieves a CIM class definition by path (e.g., "Win32_Process").
// Returns the raw CIM-encoded EncodingUnit bytes.
func (w *WMIClient) GetObject(objectPath string) ([]byte, error) {
	return wbemGetObject(w.svc, objectPath)
}

// ExecMethod invokes a method on a CIM class. The inParams are CIM-encoded
// EncodingUnit bytes for the input parameters instance (see BuildMethodInput).
// Returns raw CIM-encoded bytes for the output parameters.
func (w *WMIClient) ExecMethod(objectPath, methodName string, inParams []byte) ([]byte, error) {
	return wbemExecMethod(w.svc, objectPath, methodName, inParams)
}

// Close releases the IWbemServices object.
func (w *WMIClient) Close() {
	if w.svc != nil {
		w.svc.Release()
		w.svc = nil
	}
}

// wbemNTLMLogin calls IWbemLevel1Login::NTLMLogin (Opnum 6) to connect
// to a WMI namespace and obtain an IWbemServices interface.
//
// # MS-WMI 3.1.4.4.8
//
// NDR top-level unique pointers serialize their referent_id followed
// immediately by the pointed-to data, before the next parameter.
func wbemNTLMLogin(login *COMObject, namespace string) (*COMObject, error) {
	buf := make([]byte, 0, 96)

	// strNetworkResource: referent_id + LPWSTR body (conformant varying string)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalLPWSTRBody(namespace)...)
	buf = padTo4(buf)

	// strPreferredLocale: NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// lFlags: 0
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// pCtx: NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	result, err := login.CallMethod(OpWbemNTLMLogin, buf)
	if err != nil {
		return nil, err
	}

	// Response: referent_id + MInterfacePointer + HRESULT
	return UnmarshalInterfacePointerResponse(login.conn, result)
}

// wbemGetObject calls IWbemServices::GetObject (Opnum 6) to retrieve
// a CIM class definition. Returns the raw CIM-encoded bytes (EncodingUnit).
//
// MS-WMI 3.1.4.3.6
func wbemGetObject(svc *COMObject, objectPath string) ([]byte, error) {
	buf := make([]byte, 0, 96)

	// strObjectPath: referent_id + BSTR body (inline per NDR top-level pointer rules)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalBSTRBody(objectPath)...)
	buf = padTo4(buf)

	// lFlags: 0
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// pCtx: NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// ppObject: [in,out] non-null referent + empty MInterfacePointer
	// For [in,out] interface pointer-to-pointer params, we must send a
	// non-null outer pointer with an empty MInterfacePointer body
	// (hoisted max_count=0, ulCntData=0) rather than a NULL pointer.
	buf = binary.LittleEndian.AppendUint32(buf, 0x00060000) // referent_id (non-null)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // max_count (hoisted conformant dim)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ulCntData = 0

	// ppCallResult: [in,out] non-null referent + empty MInterfacePointer
	buf = binary.LittleEndian.AppendUint32(buf, 0x00080000) // referent_id (non-null)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // max_count (hoisted conformant dim)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // ulCntData = 0

	result, err := svc.CallMethod(OpWbemGetObject, buf)
	if err != nil {
		return nil, err
	}

	// Response:
	//   ppObject referent_id (4)
	//   ppCallResult referent_id (4)
	//   [deferred: ppObject MInterfacePointer]
	//   HRESULT (4)
	return unmarshalWbemObjectResponse(result)
}

// wbemExecMethod calls IWbemServices::ExecMethod (Opnum 24) to invoke
// a method on a CIM class. The inParams are raw CIM-encoded EncodingUnit
// bytes for the input parameters instance. Returns raw CIM-encoded bytes
// for the output parameters.
//
// MS-WMI 3.1.4.3.22
func wbemExecMethod(svc *COMObject, objectPath, methodName string, inParams []byte) ([]byte, error) {
	// Wrap inParams as OBJREF_CUSTOM in MInterfacePointer
	objref := MarshalOBJREFCustom(IID_IWbemClassObject, CLSID_WbemClassObject, inParams)
	mip := MarshalMInterfacePointer(objref)

	buf := make([]byte, 0, 64+len(mip))

	// strObjectPath: referent_id + BSTR body.
	// The embedded null is required by the WMI server's checkNullString
	// validation, which expects a null terminator within the BSTR data
	// despite BSTR being length-prefixed (not null-terminated) per MS-OAUT.
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalBSTRBody(objectPath+"\x00")...)
	buf = padTo4(buf)

	// strMethodName: referent_id + BSTR body (embedded null for WMI validation)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)
	buf = append(buf, MarshalBSTRBody(methodName+"\x00")...)
	buf = padTo4(buf)

	// lFlags: 0
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// pCtx: NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// pInParams: referent_id + MInterfacePointer body
	buf = binary.LittleEndian.AppendUint32(buf, 0x00060000)
	buf = append(buf, mip...)
	buf = padTo4(buf) // NDR alignment before next parameter

	// ppOutParams: [in,out] non-null outer pointer with NULL inner data
	// PPMInterfacePointer is a double pointer; the outer pointer must be
	// non-null so the server knows where to write the output.
	buf = binary.LittleEndian.AppendUint32(buf, 0x00080000) // referent_id (non-null)
	buf = binary.LittleEndian.AppendUint32(buf, 0)          // inner pointer = NULL

	// ppCallResult: [in,out] NULL pointer
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	result, err := svc.CallMethod(OpWbemExecMethod, buf)
	if err != nil {
		return nil, err
	}

	// Response:
	//   ppOutParams referent_id (4)
	//   ppCallResult referent_id (4)
	//   [deferred: ppOutParams MInterfacePointer]
	//   HRESULT (4)
	return unmarshalWbemObjectResponse(result)
}

// wbemExecQuery calls IWbemServices::ExecQuery (Opnum 20) to execute a WQL
// query and return an IEnumWbemClassObject for enumerating results.
//
// MS-WMI 3.1.4.3.18
func wbemExecQuery(svc *COMObject, query string) (*COMObject, error) {
	buf := make([]byte, 0, 128)

	// strQueryLanguage: referent_id + BSTR body
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)
	buf = append(buf, MarshalBSTRBody("WQL")...)
	buf = padTo4(buf)

	// strQuery: referent_id + BSTR body
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)
	buf = append(buf, MarshalBSTRBody(query)...)
	buf = padTo4(buf)

	// lFlags: WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY
	buf = binary.LittleEndian.AppendUint32(buf, wbemFlagReturnImmediately|wbemFlagForwardOnly)

	// pCtx: NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// ppEnum is [out] only — not included in the request stub

	result, err := svc.CallMethod(OpWbemExecQuery, buf)
	if err != nil {
		return nil, err
	}

	// Response: referent_id + MInterfacePointer + HRESULT
	return UnmarshalInterfacePointerResponse(svc.conn, result)
}

// enumNext calls IEnumWbemClassObject::Next (Opnum 4) to fetch the next
// batch of WMI objects. Returns raw CIM blobs and whether enumeration is done.
//
// MS-WMI 3.1.4.6.4
func enumNext(enum *COMObject, count uint32, timeout int32) ([][]byte, bool, error) {
	buf := make([]byte, 0, 8)

	// lTimeout: int32 (milliseconds, -1 = WBEM_INFINITE)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(timeout))

	// uCount: uint32
	buf = binary.LittleEndian.AppendUint32(buf, count)

	result, err := enum.CallMethod(OpEnumNext, buf)
	if err != nil {
		return nil, true, err
	}

	// Response format:
	//   Conformant-varying array of [unique] PMInterfacePointer
	//   (size_is(uCount), length_is(*puReturned)):
	//     maxCount (4) — conformant dimension = uCount
	//     offset (4) — always 0
	//     actualCount (4) — = *puReturned
	//     referent_id[actualCount] (4 each)
	//     Deferred MInterfacePointer bodies (for non-null refs)
	//   puReturned (4)
	//   HRESULT (4)

	if len(result) < 12 {
		return nil, true, fmt.Errorf("enumNext response too short")
	}

	offset := 0
	_ = le.Uint32(result[offset:]) // maxCount (conformant dimension)
	offset += 4
	_ = le.Uint32(result[offset:]) // offset (always 0)
	offset += 4
	actualCount := le.Uint32(result[offset:])
	offset += 4

	// Read referent IDs
	if len(result) < offset+int(actualCount)*4 {
		return nil, true, fmt.Errorf("enumNext: response too short for referent IDs")
	}
	refIds := make([]uint32, actualCount)
	for i := uint32(0); i < actualCount; i++ {
		refIds[i] = le.Uint32(result[offset:])
		offset += 4
	}

	// Read deferred MInterfacePointer bodies and extract CIM data
	var blobs [][]byte
	for i := uint32(0); i < actualCount; i++ {
		if refIds[i] == 0 {
			continue
		}

		// NDR alignment: each deferred body starts at 4-byte boundary
		if pad := offset % 4; pad != 0 {
			offset += 4 - pad
		}

		mip, consumed, err := UnmarshalMInterfacePointer(result[offset:])
		if err != nil {
			return nil, true, fmt.Errorf("enumNext MInterfacePointer[%d]: %w", i, err)
		}
		offset += consumed

		objref, _, err := UnmarshalOBJREF(mip.Data)
		if err != nil {
			return nil, true, fmt.Errorf("enumNext OBJREF[%d]: %w", i, err)
		}
		if objref.Flags != OBJREFCustom {
			return nil, true, fmt.Errorf("enumNext[%d]: expected OBJREF_CUSTOM, got 0x%08x", i, objref.Flags)
		}
		blobs = append(blobs, objref.Custom.Data)
	}

	// puReturned and HRESULT at end
	if len(result) < offset+8 {
		return nil, true, fmt.Errorf("enumNext: response too short for puReturned+HRESULT")
	}
	puReturned := le.Uint32(result[offset:])
	offset += 4
	hresult := le.Uint32(result[offset:])

	done := hresult == wbemSFalse || puReturned == 0 || actualCount == 0
	if hresult != wbemSOK && hresult != wbemSFalse {
		if hresult == wbemSTimedout {
			log.Debugf("enumNext: timed out")
			return blobs, true, nil
		}
		return nil, true, fmt.Errorf("enumNext failed: HRESULT 0x%08x", hresult)
	}

	return blobs, done, nil
}

// unmarshalWbemObjectResponse parses a WMI method response that returns
// an IWbemClassObject. Used by both GetObject and ExecMethod responses.
//
// Wire format (after ORPCTHAT, already stripped by CallMethod):
//
//	ppObject referent_id (4)
//	ppCallResult referent_id (4)
//	[deferred: ppObject MInterfacePointer if non-null]
//	[deferred: ppCallResult MInterfacePointer if non-null]
//	HRESULT (4)
//
// Returns the raw CIM-encoded data from the OBJREF_CUSTOM.
func unmarshalWbemObjectResponse(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("WMI response too short (%d < 12)", len(data))
	}

	offset := 0

	// ppObject referent ID
	objRefId := le.Uint32(data[offset:])
	offset += 4

	// ppCallResult referent ID
	//_ = le.Uint32(data[offset:]) // callResultRefId - we don't use this
	offset += 4

	if objRefId == 0 {
		// No object returned, check HRESULT at end
		if len(data) < offset+4 {
			return nil, fmt.Errorf("WMI response too short for HRESULT")
		}
		hresult := le.Uint32(data[offset:])
		if hresult != 0 {
			return nil, fmt.Errorf("WMI method failed: HRESULT 0x%08x", hresult)
		}
		return nil, fmt.Errorf("WMI method returned NULL object")
	}

	// Deferred: ppObject MInterfacePointer
	mip, consumed, err := UnmarshalMInterfacePointer(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("WMI MInterfacePointer: %w", err)
	}
	offset += consumed

	// HRESULT is read from the last 4 bytes rather than the tracked offset because
	// ppCallResult may have deferred MInterfacePointer data (if its referent ID was
	// non-null) that we don't parse. In practice ppCallResult is always NULL, but
	// reading from the end is a safe fallback.
	if len(data) < offset+4 {
		return nil, fmt.Errorf("WMI response too short for HRESULT (at offset %d)", offset)
	}
	hresult := le.Uint32(data[len(data)-4:])
	if hresult != 0 {
		return nil, fmt.Errorf("WMI method failed: HRESULT 0x%08x", hresult)
	}

	// Parse OBJREF from MInterfacePointer
	objref, _, err := UnmarshalOBJREF(mip.Data)
	if err != nil {
		return nil, fmt.Errorf("WMI OBJREF: %w", err)
	}

	if objref.Flags != OBJREFCustom {
		return nil, fmt.Errorf("WMI: expected OBJREF_CUSTOM, got flags 0x%08x", objref.Flags)
	}

	return objref.Custom.Data, nil
}
