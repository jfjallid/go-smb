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
// IDispatch automation interface for DCOM method invocation.
// Reference: [MS-OAUT] Sections 3.1.4.2 (GetIDsOfNames) and 3.1.4.4 (Invoke)

package msdcom

import (
	"encoding/binary"
	"fmt"
)

const (
	MSRPCUuidIDispatch = "00020400-0000-0000-c000-000000000046"
)

// IDispatch opnums (IUnknown methods 0-2 are implicit)
const (
	OpGetIDsOfNames uint16 = 5
	OpInvoke        uint16 = 6
)

// Invoke dispatch flags
const (
	DispatchMethod      uint32 = 0x1
	DispatchPropertyGet uint32 = 0x2
	DispatchPropertyPut uint32 = 0x4
)

// VARIANT type constants
const (
	VtEmpty    uint16 = 0x0000
	VtI4       uint16 = 0x0003
	VtBstr     uint16 = 0x0008
	VtDispatch uint16 = 0x0009
	VtBool     uint16 = 0x000B
)

// DISPID for named args
const (
	DispidPropertyPut int32 = -3
)

var iidNull = [16]byte{}
var IID_IDispatch = mustGUID(MSRPCUuidIDispatch)

// GetIDsOfNames resolves a method/property name to a DISPID via
// IDispatch::GetIDsOfNames (opnum 5).
func (o *COMObject) GetIDsOfNames(name string) (int32, error) {
	stub := marshalGetIDsOfNamesStub(name)
	result, err := o.CallMethod(OpGetIDsOfNames, stub)
	if err != nil {
		return 0, err
	}
	return unmarshalGetIDsOfNamesResponse(result)
}

// InvokeGetProperty calls IDispatch::Invoke with DISPATCH_PROPERTYGET
// and parses the returned VT_DISPATCH VARIANT as a new COMObject.
func (o *COMObject) InvokeGetProperty(dispid int32) (*COMObject, error) {
	stub := marshalInvokeStub(dispid, DispatchPropertyGet, nil)
	result, err := o.CallMethod(OpInvoke, stub)
	if err != nil {
		return nil, err
	}
	return unmarshalInvokeDispatchResponse(o.conn, result)
}

// InvokeMethodBSTR calls IDispatch::Invoke with DISPATCH_METHOD,
// passing the given strings as VT_BSTR arguments.
func (o *COMObject) InvokeMethodBSTR(dispid int32, args []string) error {
	stub := marshalInvokeStub(dispid, DispatchMethod, args)
	result, err := o.CallMethod(OpInvoke, stub)
	if err != nil {
		return err
	}
	return unmarshalInvokeMethodResponse(result)
}

// TypedArg represents a typed argument for IDispatch::Invoke.
type TypedArg struct {
	VT    uint16
	BStr  string // VtBstr
	Int32 int32  // VtI4
	Bool  bool   // VtBool
}

// InvokeMethodTyped calls IDispatch::Invoke with DISPATCH_METHOD and typed args.
func (o *COMObject) InvokeMethodTyped(dispid int32, args []TypedArg) error {
	stub := marshalInvokeTypedStub(dispid, DispatchMethod, args)
	result, err := o.CallMethod(OpInvoke, stub)
	if err != nil {
		return err
	}
	return unmarshalInvokeMethodResponse(result)
}

// InvokePropertyPut calls IDispatch::Invoke with DISPATCH_PROPERTYPUT.
func (o *COMObject) InvokePropertyPut(dispid int32, args []TypedArg) error {
	stub := marshalInvokeTypedStub(dispid, DispatchPropertyPut, args)
	result, err := o.CallMethod(OpInvoke, stub)
	if err != nil {
		return err
	}
	return unmarshalInvokeMethodResponse(result)
}

// marshalGetIDsOfNamesStub builds stub data for GetIDsOfNames (after ORPCTHIS).
//
// Wire format:
//
//	REFIID riid (16 bytes, IID_NULL)
//	rgszNames conformant array:
//	  maxCount (4)
//	  [cNames] referent IDs (4 each)
//	  [cNames] deferred conformant-varying OLESTR bodies
//	cNames (4)
//	lcid (4)
func marshalGetIDsOfNamesStub(name string) []byte {
	buf := make([]byte, 0, 96)

	// riid = IID_NULL
	buf = append(buf, iidNull[:]...)

	// rgszNames conformant array
	buf = binary.LittleEndian.AppendUint32(buf, 1)          // maxCount = 1
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000) // referent ID for name[0]

	// deferred string body - conformant varying OLESTR
	buf = append(buf, MarshalLPWSTRBody(name)...)
	buf = padTo4(buf)

	// cNames
	buf = binary.LittleEndian.AppendUint32(buf, 1)

	// lcid
	buf = binary.LittleEndian.AppendUint32(buf, 0x0409)

	return buf
}

// unmarshalGetIDsOfNamesResponse parses the GetIDsOfNames response
// (after ORPCTHAT has been stripped by CallMethod).
//
// Wire format:
//
//	rgDispId conformant array: maxCount (4) + [cNames] DISPID (4 each)
//	HRESULT (4)
func unmarshalGetIDsOfNamesResponse(data []byte) (int32, error) {
	if len(data) < 12 {
		return 0, fmt.Errorf("GetIDsOfNames response too short (%d bytes)", len(data))
	}

	maxCount := le.Uint32(data[0:])
	if maxCount < 1 {
		return 0, fmt.Errorf("GetIDsOfNames: no DISPIDs returned")
	}

	dispid := int32(le.Uint32(data[4:]))

	hresultOffset := 4 + 4*int(maxCount)
	if len(data) < hresultOffset+4 {
		return 0, fmt.Errorf("GetIDsOfNames: response too short for HRESULT")
	}
	hresult := le.Uint32(data[hresultOffset:])
	if hresult != 0 {
		return 0, fmt.Errorf("GetIDsOfNames failed: HRESULT 0x%08x", hresult)
	}

	return dispid, nil
}

// marshalInvokeStub builds stub data for IDispatch::Invoke (after ORPCTHIS).
//
// Wire format per MS-OAUT 3.1.4.4:
//
//	DISPID dispIdMember (4)
//	REFIID riid (16, IID_NULL)
//	LCID lcid (4)
//	DWORD dwFlags (4)
//	DISPPARAMS:
//	  rgvarg referent ID (4, NULL if no args)
//	  rgdispidNamedArgs referent ID (4, always NULL)
//	  cArgs (4)
//	  cNamedArgs (4, always 0)
//	  [deferred rgvarg conformant array if non-null]
//	UINT cVarRef (4, always 0)
//	UINT* rgVarRefIdx (4, NULL)
//	VARIANT* rgVarRef (4, NULL)
func marshalInvokeStub(dispid int32, flags uint32, bstrArgs []string) []byte {
	buf := make([]byte, 0, 256)

	// DISPID
	buf = binary.LittleEndian.AppendUint32(buf, uint32(dispid))

	// REFIID riid = IID_NULL
	buf = append(buf, iidNull[:]...)

	// LCID
	buf = binary.LittleEndian.AppendUint32(buf, 0x0409)

	// dwFlags
	buf = binary.LittleEndian.AppendUint32(buf, flags)

	// DISPPARAMS
	cArgs := uint32(len(bstrArgs))
	if cArgs > 0 {
		buf = binary.LittleEndian.AppendUint32(buf, 0x00020000) // rgvarg referent ID (non-null)
	} else {
		buf = binary.LittleEndian.AppendUint32(buf, 0) // rgvarg = NULL
	}
	buf = binary.LittleEndian.AppendUint32(buf, 0)     // rgdispidNamedArgs = NULL
	buf = binary.LittleEndian.AppendUint32(buf, cArgs) // cArgs
	buf = binary.LittleEndian.AppendUint32(buf, 0)     // cNamedArgs

	// Deferred rgvarg conformant array of [unique] wireVARIANT.
	// VARIANT = typedef [unique] wireVARIANT, so each array element is
	// a unique pointer. Layout:
	//   maxCount + [cArgs] VARIANT referent IDs
	//   [cArgs] deferred wireVARIANT bodies (each followed by its BSTR body)
	if cArgs > 0 {
		buf = binary.LittleEndian.AppendUint32(buf, cArgs) // maxCount

		// IDispatch::Invoke passes args in REVERSE order in rgvarg.
		// Referent IDs just need to be unique within the parameter scope.
		nextRef := uint32(1)
		for i := int(cArgs) - 1; i >= 0; i-- {
			buf = binary.LittleEndian.AppendUint32(buf, nextRef)
			nextRef++
		}

		// Deferred wireVARIANT bodies, each followed by its deferred BSTR body.
		// wireVARIANT: clSize(4) + rpcReserved(4) + vt(2) + reserved(6)
		//   + union discriminant ULONG(4) + BSTR refID(4) = 24 bytes
		// Each wireVARIANT+BSTR unit must start at an 8-byte boundary.
		for i := int(cArgs) - 1; i >= 0; i-- {
			// Align to 8-byte boundary before each wireVARIANT
			for len(buf)%8 != 0 {
				buf = append(buf, 0)
			}

			buf = binary.LittleEndian.AppendUint32(buf, 5)      // clSize: body size in 32-bit words after this field (5 × 4 = 20 bytes)
			buf = binary.LittleEndian.AppendUint32(buf, 0)      // rpcReserved
			buf = binary.LittleEndian.AppendUint16(buf, VtBstr) // vt
			buf = binary.LittleEndian.AppendUint16(buf, 0)      // wReserved1
			buf = binary.LittleEndian.AppendUint16(buf, 0)      // wReserved2
			buf = binary.LittleEndian.AppendUint16(buf, 0)      // wReserved3
			// Union discriminant (switch_type ULONG)
			buf = binary.LittleEndian.AppendUint32(buf, uint32(VtBstr))
			// BSTR referent ID (unique pointer)
			buf = binary.LittleEndian.AppendUint32(buf, nextRef)
			nextRef++

			// Deferred BSTR body (FLAGGED_WORD_BLOB) right after its wireVARIANT
			buf = append(buf, MarshalBSTRBody(bstrArgs[i])...)
		}
	}

	// Align to 4-byte boundary (standard NDR) before trailing fields
	buf = padTo4(buf)

	// cVarRef = 0 (no by-reference arguments)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	// rgVarRefIdx = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	// rgVarRef = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	return buf
}

// marshalInvokeTypedStub builds stub data for IDispatch::Invoke with typed args.
// Supports VT_BSTR, VT_I4, and VT_BOOL argument types.
// For DISPATCH_PROPERTYPUT, automatically adds DISPID_PROPERTYPUT as a named arg.
func marshalInvokeTypedStub(dispid int32, flags uint32, args []TypedArg) []byte {
	buf := make([]byte, 0, 256)

	buf = binary.LittleEndian.AppendUint32(buf, uint32(dispid))
	buf = append(buf, iidNull[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, 0x0409) // LCID
	buf = binary.LittleEndian.AppendUint32(buf, flags)

	cArgs := uint32(len(args))
	isPut := flags&DispatchPropertyPut != 0

	// DISPPARAMS
	if cArgs > 0 {
		buf = binary.LittleEndian.AppendUint32(buf, 0x00020000) // rgvarg referent ID (non-null)
	} else {
		buf = binary.LittleEndian.AppendUint32(buf, 0) // rgvarg = NULL
	}

	if isPut {
		buf = binary.LittleEndian.AppendUint32(buf, 0x00030000) // rgdispidNamedArgs referent ID (non-null)
		buf = binary.LittleEndian.AppendUint32(buf, cArgs)      // cArgs
		buf = binary.LittleEndian.AppendUint32(buf, 1)          // cNamedArgs = 1 (DISPID_PROPERTYPUT)
	} else {
		buf = binary.LittleEndian.AppendUint32(buf, 0)     // rgdispidNamedArgs = NULL
		buf = binary.LittleEndian.AppendUint32(buf, cArgs) // cArgs
		buf = binary.LittleEndian.AppendUint32(buf, 0)     // cNamedArgs
	}

	// Deferred rgdispidNamedArgs array (for PROPERTYPUT)
	if isPut {
		dispidPut := DispidPropertyPut
		buf = binary.LittleEndian.AppendUint32(buf, 1) // maxCount = 1
		buf = binary.LittleEndian.AppendUint32(buf, uint32(dispidPut))
	}

	// Deferred rgvarg conformant array
	if cArgs > 0 {
		buf = binary.LittleEndian.AppendUint32(buf, cArgs) // maxCount
		nextRef := uint32(0x00040000)

		// Referent IDs in reverse order
		for i := int(cArgs) - 1; i >= 0; i-- {
			buf = binary.LittleEndian.AppendUint32(buf, nextRef)
			nextRef += 0x00010000
		}

		// Deferred wireVARIANT bodies in reverse order
		for i := int(cArgs) - 1; i >= 0; i-- {
			for len(buf)%8 != 0 {
				buf = append(buf, 0)
			}

			arg := args[i]
			switch arg.VT {
			case VtBstr:
				buf = binary.LittleEndian.AppendUint32(buf, 5)              // clSize
				buf = binary.LittleEndian.AppendUint32(buf, 0)              // rpcReserved
				buf = binary.LittleEndian.AppendUint16(buf, VtBstr)         // vt
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved1
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved2
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved3
				buf = binary.LittleEndian.AppendUint32(buf, uint32(VtBstr)) // union discriminant
				buf = binary.LittleEndian.AppendUint32(buf, nextRef)        // BSTR referent ID
				nextRef += 0x00010000
				buf = append(buf, MarshalBSTRBody(arg.BStr)...)

			case VtI4:
				buf = binary.LittleEndian.AppendUint32(buf, 5)                 // clSize
				buf = binary.LittleEndian.AppendUint32(buf, 0)                 // rpcReserved
				buf = binary.LittleEndian.AppendUint16(buf, VtI4)              // vt
				buf = binary.LittleEndian.AppendUint16(buf, 0)                 // wReserved1
				buf = binary.LittleEndian.AppendUint16(buf, 0)                 // wReserved2
				buf = binary.LittleEndian.AppendUint16(buf, 0)                 // wReserved3
				buf = binary.LittleEndian.AppendUint32(buf, uint32(VtI4))      // union discriminant
				buf = binary.LittleEndian.AppendUint32(buf, uint32(arg.Int32)) // lVal

			case VtBool:
				buf = binary.LittleEndian.AppendUint32(buf, 5)              // clSize
				buf = binary.LittleEndian.AppendUint32(buf, 0)              // rpcReserved
				buf = binary.LittleEndian.AppendUint16(buf, VtBool)         // vt
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved1
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved2
				buf = binary.LittleEndian.AppendUint16(buf, 0)              // wReserved3
				buf = binary.LittleEndian.AppendUint32(buf, uint32(VtBool)) // union discriminant
				boolVal := uint16(0x0000)
				if arg.Bool {
					boolVal = 0xFFFF
				}
				buf = binary.LittleEndian.AppendUint16(buf, boolVal)
				buf = binary.LittleEndian.AppendUint16(buf, 0) // padding to 4 bytes
			}
		}
	}

	buf = padTo4(buf)

	// cVarRef, rgVarRefIdx, rgVarRef
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	return buf
}

// unmarshalInvokeDispatchResponse parses an Invoke response that returns
// a VT_DISPATCH VARIANT (interface pointer).
//
// Wire format per MS-OAUT 3.1.4.4 (after ORPCTHAT, stripped by CallMethod):
//
//	pArgErr: UINT (4)
//	padding to 8-byte boundary (4)
//	pVarResult: wireVARIANT (embedded, 8-byte aligned)
//	  clSize (4) + rpcReserved (4) + vt (2) + reserved (6)
//	  union discriminant ULONG (4)  [switch_type(ULONG)]
//	  union arm: pdispVal referent_id (4)
//	  deferred: MInterfacePointer (maxCount + ulCntData + OBJREF)
//	pExcepInfo: EXCEPINFO (variable)
//	HRESULT (4)
//
// The wireVARIANT is embedded inline (not a [unique] pointer with a referent
// ID). Its union can hold 8-byte types (double, int64), so the struct requires
// 8-byte alignment. After the 4-byte pArgErr, 4 bytes of alignment padding
// precede the wireVARIANT body.
func unmarshalInvokeDispatchResponse(conn *DCOMConnection, data []byte) (*COMObject, error) {
	// Check HRESULT first (last 4 bytes). On error, pVarResult is VT_EMPTY
	// and pExcepInfo may contain variable-length deferred BSTR data, making
	// forward parsing of the middle section unreliable.
	if len(data) < 4 {
		return nil, fmt.Errorf("Invoke response too short")
	}
	hresult := le.Uint32(data[len(data)-4:])
	if hresult != 0 {
		return nil, fmt.Errorf("Invoke failed: HRESULT 0x%08x", hresult)
	}

	// pArgErr (UINT, 4 bytes) — only meaningful on error, skip it.
	// Then align to 8-byte boundary for the wireVARIANT body.
	offset := 4
	offset = (offset + 7) &^ 7 // align to 8

	// wireVARIANT header: clSize(4) + rpcReserved(4) + vt(2) + reserved(6)
	if len(data) < offset+16 {
		return nil, fmt.Errorf("Invoke response too short for wireVARIANT header")
	}
	_ = le.Uint32(data[offset:]) // clSize
	offset += 4
	offset += 4 // rpcReserved
	vt := le.Uint16(data[offset:])
	offset += 2
	offset += 6 // reserved1-3

	if vt != VtDispatch {
		return nil, fmt.Errorf("Invoke: expected VT_DISPATCH (0x%04x), got 0x%04x", VtDispatch, vt)
	}

	// Union discriminant (ULONG) - switch_type(ULONG) causes NDR to emit
	// the discriminant before the arm data
	if len(data) < offset+4 {
		return nil, fmt.Errorf("Invoke response too short for union discriminant")
	}
	offset += 4 // skip union discriminant (same value as vt)

	// VT_DISPATCH union arm: MInterfacePointer* pdispVal (unique pointer referent ID)
	if len(data) < offset+4 {
		return nil, fmt.Errorf("Invoke response too short for pdispVal pointer")
	}
	mipRefId := le.Uint32(data[offset:])
	offset += 4

	if mipRefId == 0 {
		return nil, fmt.Errorf("Invoke: VT_DISPATCH has NULL interface pointer")
	}

	// Deferred MInterfacePointer body
	mip, consumed, err := UnmarshalMInterfacePointer(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("Invoke MInterfacePointer: %w", err)
	}
	offset += consumed

	objref, _, err := UnmarshalOBJREF(mip.Data)
	if err != nil {
		return nil, fmt.Errorf("Invoke OBJREF: %w", err)
	}
	if objref.Std == nil {
		return nil, fmt.Errorf("Invoke: expected OBJREF_STANDARD, got flags 0x%08x", objref.Flags)
	}

	return conn.newObjectFromSTDOBJREF(objref.Std, IID_IDispatch), nil
}

// unmarshalInvokeMethodResponse parses an Invoke response for a void/non-interface method.
// Response format: pArgErr(4) + pVarResult(variable) + pExcepInfo(variable) + HRESULT(4)
//
// We read HRESULT from data[len(data)-4:] rather than tracking the offset because
// pVarResult and pExcepInfo are variable-length (contain BSTR pointers with
// potentially deferred data) and we don't need to parse the middle section.
// This is safe because HRESULT is the last NDR parameter and NDR guarantees
// no padding follows the last parameter in the stub.
func unmarshalInvokeMethodResponse(data []byte) error {
	// HRESULT is the last 4 bytes
	if len(data) < 4 {
		return fmt.Errorf("Invoke method response too short")
	}
	hresult := le.Uint32(data[len(data)-4:])
	if hresult != 0 {
		return fmt.Errorf("Invoke method failed: HRESULT 0x%08x", hresult)
	}
	return nil
}
