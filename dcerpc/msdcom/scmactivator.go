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
// IRemoteSCMActivator interface for DCOM COM object activation.
// Reference: [MS-DCOM] Section 3.1.2.5.2

package msdcom

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
)

const (
	MSRPCUuidIRemoteSCMActivator                = "000001a0-0000-0000-c000-000000000046"
	MSRPCIRemoteSCMActivatorMajorVersion uint16 = 0
	MSRPCIRemoteSCMActivatorMinorVersion uint16 = 0
)

const (
	OpRemoteCreateInstance uint16 = 4
)

// Well-known CLSIDs and IIDs for DCOM activation.
var (
	CLSID_ActivationPropertiesIn  = mustGUID("00000338-0000-0000-c000-000000000046")
	CLSID_ActivationPropertiesOut = mustGUID("00000339-0000-0000-c000-000000000046")
	IID_IActivationPropertiesIn   = mustGUID("000001a2-0000-0000-c000-000000000046")
	IID_IActivationPropertiesOut  = mustGUID("000001a3-0000-0000-c000-000000000046")

	CLSID_InstantiationInfo     = mustGUID("000001ab-0000-0000-c000-000000000046")
	CLSID_ActivationContextInfo = mustGUID("000001a5-0000-0000-c000-000000000046")
	CLSID_LocationInfo          = mustGUID("000001a4-0000-0000-c000-000000000046")
	CLSID_ScmRequestInfo        = mustGUID("000001aa-0000-0000-c000-000000000046")
	CLSID_ScmReplyInfo          = mustGUID("000001b6-0000-0000-c000-000000000046")
	CLSID_PropsOutInfo          = mustGUID("00000339-0000-0000-c000-000000000046")

	IID_IUnknown = mustGUID("00000000-0000-0000-c000-000000000046")
)

// SCMActivator wraps a ServiceBind for the IRemoteSCMActivator interface.
type SCMActivator struct {
	*dcerpc.ServiceBind
}

// ActivationResult holds the parsed result from RemoteCreateInstance.
type ActivationResult struct {
	// From ScmReplyInfo
	OXID           uint64
	OxidBindings   DUALSTRINGARRAY
	IpidRemUnknown [16]byte
	AuthnHint      uint32
	ServerVersion  COMVERSION

	// From PropsOutInfo (first requested interface)
	InterfaceIPID [16]byte
	InterfaceOXID uint64
	InterfaceOID  uint64
}

// RemoteCreateInstance activates a COM class and returns interface pointers.
// cid is the causality ID (random, constant per session).
// clsid is the CLSID of the COM class to instantiate.
// iid is the IID of the interface to request on the new object.
//
// MS-DCOM 3.1.2.5.2.3.2 - RemoteCreateInstance (Opnum 4)
func (s *SCMActivator) RemoteCreateInstance(cid [16]byte, clsid, iid [16]byte) (*ActivationResult, error) {
	reqBuf := marshalRemoteCreateInstanceRequest(cid, clsid, iid)

	result, err := s.MakeRequest(OpRemoteCreateInstance, reqBuf)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return unmarshalRemoteCreateInstanceResponse(result)
}

// marshalRemoteCreateInstanceRequest builds the request stub for RemoteCreateInstance.
//
// Wire format:
//
//	ORPCTHIS (32 bytes, ref parameter — inline)
//	pUnkOuter referent_id (4 bytes, null)
//	pActProperties referent_id (4 bytes, non-null)
//	MInterfacePointer (deferred data for pActProperties)
func marshalRemoteCreateInstanceRequest(cid [16]byte, clsid, iid [16]byte) []byte {
	// Build ActivationPropertiesIn
	actProps := buildActivationPropertiesIn(clsid, iid)

	// Wrap in OBJREF_CUSTOM
	objref := MarshalOBJREFCustom(IID_IActivationPropertiesIn, CLSID_ActivationPropertiesIn, actProps)

	// Wrap in MInterfacePointer
	mip := MarshalMInterfacePointer(objref)

	buf := make([]byte, 0, ORPCTHISSize+4+4+len(mip))

	// ORPCTHIS
	orpcThis := &ORPCTHIS{
		Version:     COMVERSION{MajorVersion: 5, MinorVersion: 7},
		Flags:       ORPCFlagsLocal,
		CausalityId: cid,
	}
	buf = append(buf, orpcThis.MarshalBinary()...)

	// pUnkOuter = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// pActProperties = non-null referent ID
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)

	// Deferred: MInterfacePointer
	buf = append(buf, mip...)

	return buf
}

// unmarshalRemoteCreateInstanceResponse parses the response stub.
//
// Wire format:
//
//	ORPCTHAT (variable)
//	ppActProperties referent_id (4 bytes)
//	MInterfacePointer (deferred, contains OBJREF_CUSTOM with ActivationPropertiesOut)
//	ErrorCode/HRESULT (4 bytes, at end)
func unmarshalRemoteCreateInstanceResponse(buf []byte) (*ActivationResult, error) {
	offset := 0

	// Parse ORPCTHAT
	_, consumed, err := UnmarshalORPCTHAT(buf)
	if err != nil {
		return nil, fmt.Errorf("RemoteCreateInstance ORPCTHAT: %w", err)
	}
	offset += consumed

	// ppActProperties referent ID
	if len(buf) < offset+4 {
		return nil, fmt.Errorf("RemoteCreateInstance: buffer too short for ppActProperties ptr")
	}
	actPropsRefId := le.Uint32(buf[offset:])
	offset += 4

	if actPropsRefId == 0 {
		// Server returned NULL ppActProperties — this means activation failed.
		// The HRESULT follows immediately (no deferred MInterfacePointer data).
		if len(buf) >= offset+4 {
			errorCode := le.Uint32(buf[offset:])
			return nil, fmt.Errorf("RemoteCreateInstance failed: HRESULT 0x%08x", errorCode)
		}
		return nil, fmt.Errorf("RemoteCreateInstance: ppActProperties is NULL")
	}

	// Deferred: MInterfacePointer
	mip, consumed, err := UnmarshalMInterfacePointer(buf[offset:])
	if err != nil {
		return nil, fmt.Errorf("RemoteCreateInstance MInterfacePointer: %w", err)
	}
	offset += consumed

	// ErrorCode (HRESULT) at end
	if len(buf) < offset+4 {
		return nil, fmt.Errorf("RemoteCreateInstance: buffer too short for ErrorCode")
	}
	errorCode := le.Uint32(buf[offset:])
	if errorCode != 0 {
		return nil, fmt.Errorf("RemoteCreateInstance failed: HRESULT 0x%08x", errorCode)
	}

	// Parse OBJREF from MInterfacePointer data
	objref, _, err := UnmarshalOBJREF(mip.Data)
	if err != nil {
		return nil, fmt.Errorf("RemoteCreateInstance OBJREF: %w", err)
	}

	if objref.Flags != OBJREFCustom {
		return nil, fmt.Errorf("RemoteCreateInstance: expected OBJREF_CUSTOM, got 0x%08x", objref.Flags)
	}

	return parseActivationPropertiesOut(objref.Custom.Data)
}

// --- ActivationPropertiesIn construction ---

// buildActivationPropertiesIn constructs the ActivationPropertiesBlob.
//
// Each property buffer and the CustomHeader are wrapped with
// TypeSerialization1 headers (MS-RPCE 2.2.6) as required by DCOM.
//
// Layout:
//
//	dwSize (4) — size from CustomHeader to end of last property
//	dwReserved (4) — 0
//	TS1Header + CustomHeader (padded to 8)
//	TS1Header + Property buffers (each padded to 8)
func buildActivationPropertiesIn(clsid, iid [16]byte) []byte {
	// Build individual property buffers wrapped with TS1 headers
	instInfo := wrapTS1(buildInstantiationInfo(clsid, iid))
	actCtxInfo := wrapTS1(buildActivationContextInfo())
	locInfo := wrapTS1(buildLocationInfo())
	scmReqInfo := wrapTS1(buildScmRequestInfo())

	propSizes := []uint32{
		uint32(len(instInfo)),
		uint32(len(actCtxInfo)),
		uint32(len(locInfo)),
		uint32(len(scmReqInfo)),
	}

	propCLSIDs := [][16]byte{
		CLSID_InstantiationInfo,
		CLSID_ActivationContextInfo,
		CLSID_LocationInfo,
		CLSID_ScmRequestInfo,
	}

	var sumPropSizes uint32
	for _, s := range propSizes {
		sumPropSizes += s
	}

	// Build CustomHeader with TS1 wrapper
	// Pass 0 for totalSize; it will be patched after we know headerSize
	customHeaderRaw := buildCustomHeader(0, propCLSIDs, propSizes)
	customHeader := wrapTS1(customHeaderRaw)
	headerSize := uint32(len(customHeader))

	// totalSize = headerSize + sumPropSizes (MS-DCOM 2.2.22.2.1.1:
	// "total size from the beginning of the CustomHeader to the end
	// of the last buffer")
	totalSize := headerSize + sumPropSizes

	// Patch totalSize and headerSize within the TS1-wrapped CustomHeader.
	// The TS1 header is 16 bytes, so CustomHeader data starts at offset 16.
	le.PutUint32(customHeader[ts1HeaderSize:ts1HeaderSize+4], totalSize)
	le.PutUint32(customHeader[ts1HeaderSize+4:ts1HeaderSize+8], headerSize)

	// dwSize = totalSize (same value per MS-DCOM 2.2.22.2)
	dwSize := totalSize

	blob := make([]byte, 0, 8+int(dwSize))
	blob = binary.LittleEndian.AppendUint32(blob, dwSize)
	blob = binary.LittleEndian.AppendUint32(blob, 0) // dwReserved
	blob = append(blob, customHeader...)
	blob = append(blob, instInfo...)
	blob = append(blob, actCtxInfo...)
	blob = append(blob, locInfo...)
	blob = append(blob, scmReqInfo...)

	return blob
}

// ts1HeaderSize is the combined size of the TypeSerialization1
// CommonHeader (8 bytes) and PrivateHeader (8 bytes).
const ts1HeaderSize = 16

// wrapTS1 wraps data with TypeSerialization1 CommonHeader + PrivateHeader
// (MS-RPCE 2.2.6) and pads the total to 8-byte alignment.
func wrapTS1(data []byte) []byte {
	rawSize := uint32(len(data))

	buf := make([]byte, 0, ts1HeaderSize+len(data)+8)

	// CommonHeader (8 bytes)
	buf = append(buf, 0x01)              // Version
	buf = append(buf, 0x10)              // Endianness (little-endian)
	buf = binary.LittleEndian.AppendUint16(buf, 8)           // CommonHeaderLength
	buf = binary.LittleEndian.AppendUint32(buf, 0xCCCCCCCC)  // Filler

	// PrivateHeader (8 bytes)
	buf = binary.LittleEndian.AppendUint32(buf, rawSize)     // ObjectBufferLength
	buf = binary.LittleEndian.AppendUint32(buf, 0xCCCCCCCC)  // Filler

	// Data
	buf = append(buf, data...)

	return padTo8(buf)
}

// buildCustomHeader constructs the NDR-encoded CustomHeader.
//
// Layout:
//
//	totalSize (4) — placeholder, patched by caller
//	headerSize (4) — placeholder, patched by caller
//	dwReserved (4) — 0
//	destCtx (4) — MSHCTX_DIFFERENTMACHINE = 2
//	cIfs (4)
//	classInfoClsid (16) — zeros
//	pclsid referent_id (4)
//	pSizes referent_id (4)
//	padding (4) — NDR alignment to 8 for deferred data
//	--- deferred ---
//	maxCount (4) + CLSIDs
//	maxCount (4) + sizes
func buildCustomHeader(totalSize uint32, clsids [][16]byte, sizes []uint32) []byte {
	cIfs := uint32(len(clsids))

	buf := make([]byte, 0, 140)
	buf = binary.LittleEndian.AppendUint32(buf, totalSize) // totalSize (patched later)
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // headerSize (patched later)
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // dwReserved
	buf = binary.LittleEndian.AppendUint32(buf, 2)         // destCtx = MSHCTX_DIFFERENTMACHINE
	buf = binary.LittleEndian.AppendUint32(buf, cIfs)      // cIfs
	buf = append(buf, make([]byte, 16)...) // classInfoClsid (zeros)
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000)    // pclsid referent ID
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000)    // pSizes referent ID

	// NDR alignment padding to 8-byte boundary before deferred data
	// (44 bytes of inline fields → pad to 48)
	buf = binary.LittleEndian.AppendUint32(buf, 0)

	// Deferred: pclsid conformant array
	buf = binary.LittleEndian.AppendUint32(buf, cIfs) // maxCount
	for _, c := range clsids {
		buf = append(buf, c[:]...)
	}

	// Deferred: pSizes conformant array
	buf = binary.LittleEndian.AppendUint32(buf, cIfs) // maxCount
	for _, s := range sizes {
		buf = binary.LittleEndian.AppendUint32(buf, s)
	}

	return buf
}

// buildInstantiationInfo constructs the NDR-encoded InstantiationInfoData.
//
// MS-DCOM 2.2.22.2.1.2
func buildInstantiationInfo(clsid, iid [16]byte) []byte {
	buf := make([]byte, 0, 72)

	buf = append(buf, clsid[:]...)     // classId (16)
	buf = binary.LittleEndian.AppendUint32(buf, 0x04)      // classCtx = CLSCTX_LOCAL_SERVER
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // actvflags
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // fIsSurrogate
	buf = binary.LittleEndian.AppendUint32(buf, 1)         // cIID = 1
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // instFlag
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000) // pIID referent ID
	buf = binary.LittleEndian.AppendUint32(buf, 0)         // thisSize
	buf = binary.LittleEndian.AppendUint16(buf, 5)         // clientCOM.MajorVersion
	buf = binary.LittleEndian.AppendUint16(buf, 7)         // clientCOM.MinorVersion

	// Deferred: pIID conformant array
	buf = binary.LittleEndian.AppendUint32(buf, 1)        // maxCount = 1
	buf = append(buf, iid[:]...)      // IID

	return buf
}

// buildActivationContextInfo constructs the NDR-encoded ActivationContextInfoData.
//
// MS-DCOM 2.2.22.2.1.3 — all fields zero/null.
func buildActivationContextInfo() []byte {
	buf := make([]byte, 0, 24)

	buf = binary.LittleEndian.AppendUint32(buf, 0) // clientOK
	buf = binary.LittleEndian.AppendUint32(buf, 0) // bReserved
	buf = binary.LittleEndian.AppendUint32(buf, 0) // dwReserved
	buf = binary.LittleEndian.AppendUint32(buf, 0) // dwReserved2
	buf = binary.LittleEndian.AppendUint32(buf, 0) // pIFDClientCtx = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0) // pIFDPrototypeCtx = NULL

	return buf
}

// buildLocationInfo constructs the NDR-encoded LocationInfoData.
//
// MS-DCOM 2.2.22.2.1.4 — all fields zero/null.
func buildLocationInfo() []byte {
	buf := make([]byte, 0, 16)

	buf = binary.LittleEndian.AppendUint32(buf, 0) // machineName = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0) // processId
	buf = binary.LittleEndian.AppendUint32(buf, 0) // apartmentId
	buf = binary.LittleEndian.AppendUint32(buf, 0) // contextId

	return buf
}

// buildScmRequestInfo constructs the NDR-encoded ScmRequestInfoData.
//
// MS-DCOM 2.2.22.2.1.6
func buildScmRequestInfo() []byte {
	buf := make([]byte, 0, 32)

	buf = binary.LittleEndian.AppendUint32(buf, 0)          // pdwReserved = NULL
	buf = binary.LittleEndian.AppendUint32(buf, 0x00020000) // remoteRequest referent ID

	// Deferred: customREMOTE_REQUEST_SCM_INFO
	buf = binary.LittleEndian.AppendUint32(buf, 2)          // ClientImpLevel = RPC_C_IMP_LEVEL_IDENTIFY
	buf = binary.LittleEndian.AppendUint16(buf, 1)          // cRequestedProtseqs = 1
	buf = binary.LittleEndian.AppendUint16(buf, 0)          // padding to 4-byte align
	buf = binary.LittleEndian.AppendUint32(buf, 0x00040000) // pRequestedProtseqs referent ID

	// Deferred: conformant array of protseqs
	buf = binary.LittleEndian.AppendUint32(buf, 1) // maxCount = 1
	buf = binary.LittleEndian.AppendUint16(buf, 7) // ncacn_ip_tcp
	// Note: buffer ends at 30 bytes (not 4-byte aligned). The TS1 wrapper
	// (wrapTS1) pads the total to 8-byte alignment.

	return buf
}

// --- ActivationPropertiesOut parsing ---

// parseActivationPropertiesOut parses the ActivationPropertiesBlob from
// the OBJREF_CUSTOM data in the response.
//
// The blob layout is:
//
//	dwSize (4) + dwReserved (4)
//	TS1Header (16) + CustomHeader data (padded to 8)
//	TS1Header (16) + Property buffer (padded to 8) ...
func parseActivationPropertiesOut(data []byte) (*ActivationResult, error) {
	if len(data) < 8+ts1HeaderSize {
		return nil, fmt.Errorf("ActivationPropertiesOut: too short (%d)", len(data))
	}

	// dwSize and dwReserved
	// dwSize := le.Uint32(data[0:4])
	// dwReserved := le.Uint32(data[4:8])

	// Read the TS1 PrivateHeader to get the CustomHeader's ObjectBufferLength.
	customHeaderOBL := le.Uint32(data[8+8 : 8+12]) // PrivateHeader starts at offset 8+8

	// Skip TS1 header before CustomHeader
	hdrBuf := data[8+ts1HeaderSize:]
	clsids, sizes, _, err := parseCustomHeader(hdrBuf)
	if err != nil {
		return nil, fmt.Errorf("ActivationPropertiesOut CustomHeader: %w", err)
	}

	// Properties start after dwSize+dwReserved (8) + TS1-wrapped CustomHeader.
	// The TS1-wrapped size = ts1HeaderSize + ObjectBufferLength, padded to 8.
	wrappedHeaderSize := padTo8Size(ts1HeaderSize + int(customHeaderOBL))
	propsStart := 8 + wrappedHeaderSize

	log.Debugf("ActivationPropertiesOut: customHeaderOBL=%d wrappedHeaderSize=%d propsStart=%d dataLen=%d clsids=%d sizes=%v",
		customHeaderOBL, wrappedHeaderSize, propsStart, len(data), len(clsids), sizes)
	if propsStart > len(data) {
		return nil, fmt.Errorf("ActivationPropertiesOut: propsStart %d exceeds data length %d", propsStart, len(data))
	}
	propsData := data[propsStart:]

	// Split properties using sizes and match by CLSID.
	// Each property buffer is TS1-wrapped; skip the 16-byte TS1 header.
	result := &ActivationResult{}
	propOffset := 0
	for i := 0; i < len(clsids) && i < len(sizes); i++ {
		propSize := int(sizes[i])
		log.Debugf("ActivationPropertiesOut: property %d CLSID=%x size=%d", i, clsids[i], propSize)
		if propOffset+propSize > len(propsData) {
			return nil, fmt.Errorf("ActivationPropertiesOut: property %d exceeds data bounds", i)
		}
		propBuf := propsData[propOffset : propOffset+propSize]

		// Skip TS1 header within each property buffer
		if len(propBuf) > ts1HeaderSize {
			propBuf = propBuf[ts1HeaderSize:]
		}

		if clsids[i] == CLSID_ScmReplyInfo {
			if err := parseScmReplyInfo(propBuf, result); err != nil {
				return nil, fmt.Errorf("ScmReplyInfo: %w", err)
			}
		} else if clsids[i] == CLSID_PropsOutInfo {
			if err := parsePropsOutInfo(propBuf, result); err != nil {
				return nil, fmt.Errorf("PropsOutInfo: %w", err)
			}
		}

		propOffset += propSize
	}

	return result, nil
}

// parseCustomHeader parses the CustomHeader and returns the CLSID array,
// sizes array, and headerSize.
func parseCustomHeader(buf []byte) (clsids [][16]byte, sizes []uint32, headerSize uint32, err error) {
	if len(buf) < 44 {
		return nil, nil, 0, fmt.Errorf("too short (%d < 44)", len(buf))
	}

	// totalSize := le.Uint32(buf[0:4])
	headerSize = le.Uint32(buf[4:8])
	// dwReserved := le.Uint32(buf[8:12])
	// destCtx := le.Uint32(buf[12:16])
	cIfs := le.Uint32(buf[16:20])
	// classInfoClsid := buf[20:36]
	pclsidPtr := le.Uint32(buf[36:40])
	pSizesPtr := le.Uint32(buf[40:44])

	// NDR alignment padding to 8-byte boundary after 44 bytes of inline fields
	offset := 48
	if len(buf) < offset {
		return nil, nil, 0, fmt.Errorf("too short for NDR alignment (%d < %d)", len(buf), offset)
	}

	// Deferred: CLSID conformant array
	if pclsidPtr != 0 {
		if len(buf) < offset+4 {
			return nil, nil, 0, fmt.Errorf("too short for CLSID maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4
		count := cIfs
		if maxCount < count {
			count = maxCount
		}
		for i := uint32(0); i < count; i++ {
			if len(buf) < offset+16 {
				return nil, nil, 0, fmt.Errorf("too short for CLSID %d", i)
			}
			var c [16]byte
			copy(c[:], buf[offset:offset+16])
			clsids = append(clsids, c)
			offset += 16
		}
	}

	// Deferred: sizes conformant array
	if pSizesPtr != 0 {
		if len(buf) < offset+4 {
			return nil, nil, 0, fmt.Errorf("too short for sizes maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4
		count := cIfs
		if maxCount < count {
			count = maxCount
		}
		for i := uint32(0); i < count; i++ {
			if len(buf) < offset+4 {
				return nil, nil, 0, fmt.Errorf("too short for size %d", i)
			}
			sizes = append(sizes, le.Uint32(buf[offset:]))
			offset += 4
		}
	}

	return clsids, sizes, headerSize, nil
}

// parseScmReplyInfo parses the ScmReplyInfoData property buffer.
//
// NDR layout:
//
//	pdwReserved ptr (4) — null
//	remoteReply ptr (4) — referent ID
//	--- deferred customREMOTE_REPLY_SCM_INFO ---
//	OXID (8)
//	pdsaOxidBindings ptr (4)
//	ipidRemUnknown (16)
//	authnHint (4)
//	COMVERSION (4)
//	--- deferred DUALSTRINGARRAY ---
func parseScmReplyInfo(buf []byte, result *ActivationResult) error {
	if len(buf) < 8 {
		return fmt.Errorf("buffer too short (%d)", len(buf))
	}

	offset := 0
	// pdwReserved pointer (null)
	offset += 4
	// remoteReply pointer
	replyPtr := le.Uint32(buf[offset:])
	offset += 4

	if replyPtr == 0 {
		return fmt.Errorf("remoteReply is NULL")
	}

	// customREMOTE_REPLY_SCM_INFO
	if len(buf) < offset+36 {
		return fmt.Errorf("buffer too short for customREMOTE_REPLY_SCM_INFO (%d)", len(buf))
	}

	result.OXID = le.Uint64(buf[offset:])
	offset += 8

	dsaPtr := le.Uint32(buf[offset:])
	offset += 4

	copy(result.IpidRemUnknown[:], buf[offset:offset+16])
	offset += 16

	result.AuthnHint = le.Uint32(buf[offset:])
	offset += 4

	comVer, err := UnmarshalCOMVERSION(buf[offset:])
	if err != nil {
		return err
	}
	result.ServerVersion = comVer
	offset += 4

	// Deferred: DUALSTRINGARRAY (NDR conformant structure)
	// The conformant maxCount (uint32) precedes the actual structure.
	if dsaPtr != 0 {
		if len(buf) < offset+8 {
			return fmt.Errorf("buffer too short for DUALSTRINGARRAY")
		}
		// Skip NDR conformant maxCount
		offset += 4
		dsa, _, err := UnmarshalDUALSTRINGARRAY(buf[offset:])
		if err != nil {
			return fmt.Errorf("DUALSTRINGARRAY: %w", err)
		}
		result.OxidBindings = dsa
	}

	return nil
}

// parsePropsOutInfo parses the PropsOutInfo property buffer.
//
// NDR layout:
//
//	cIfs (4)
//	piid ptr (4)
//	phresults ptr (4)
//	ppIntfData ptr (4)
//	--- deferred piid: maxCount + IID array ---
//	--- deferred phresults: maxCount + HRESULT array ---
//	--- deferred ppIntfData: maxCount + referent IDs + MInterfacePointer data ---
func parsePropsOutInfo(buf []byte, result *ActivationResult) error {
	if len(buf) < 16 {
		return fmt.Errorf("buffer too short (%d)", len(buf))
	}

	offset := 0
	cIfs := le.Uint32(buf[offset:])
	offset += 4

	piidPtr := le.Uint32(buf[offset:])
	offset += 4

	phresultsPtr := le.Uint32(buf[offset:])
	offset += 4

	ppIntfDataPtr := le.Uint32(buf[offset:])
	offset += 4

	log.Debugf("PropsOutInfo: cIfs=%d piidPtr=0x%x phresultsPtr=0x%x ppIntfDataPtr=0x%x bufLen=%d",
		cIfs, piidPtr, phresultsPtr, ppIntfDataPtr, len(buf))

	// Skip piid conformant array
	if piidPtr != 0 {
		if len(buf) < offset+4 {
			return fmt.Errorf("buffer too short for piid maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4
		skip := int(maxCount) * 16
		if len(buf) < offset+skip {
			return fmt.Errorf("buffer too short for piid array (%d IIDs)", maxCount)
		}
		offset += skip
	}

	// Skip phresults conformant array
	if phresultsPtr != 0 {
		if len(buf) < offset+4 {
			return fmt.Errorf("buffer too short for phresults maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4
		skip := int(maxCount) * 4
		if len(buf) < offset+skip {
			return fmt.Errorf("buffer too short for phresults array (%d entries)", maxCount)
		}
		offset += skip
	}

	// Parse ppIntfData
	if ppIntfDataPtr != 0 && cIfs > 0 {
		if len(buf) < offset+4 {
			return fmt.Errorf("buffer too short for ppIntfData maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4
		_ = maxCount

		// Read referent IDs
		refIds := make([]uint32, cIfs)
		for i := uint32(0); i < cIfs; i++ {
			if len(buf) < offset+4 {
				return fmt.Errorf("buffer too short for ppIntfData referent ID %d", i)
			}
			refIds[i] = le.Uint32(buf[offset:])
			offset += 4
		}

		log.Debugf("PropsOutInfo: refIds=%v offset=%d remaining=%d", refIds, offset, len(buf)-offset)

		// Parse first non-null MInterfacePointer
		for i := uint32(0); i < cIfs; i++ {
			if refIds[i] == 0 {
				log.Debugf("PropsOutInfo: skipping null refId at index %d", i)
				continue
			}

			if len(buf) < offset+8 {
				return fmt.Errorf("buffer too short for MInterfacePointer %d", i)
			}

			log.Debugf("PropsOutInfo: parsing MIP at offset %d, next bytes: %x", offset, buf[offset:min(offset+32, len(buf))])

			mip, consumed, err := UnmarshalMInterfacePointer(buf[offset:])
			if err != nil {
				return fmt.Errorf("MInterfacePointer %d: %w", i, err)
			}

			log.Debugf("PropsOutInfo: MIP cntData=%d dataLen=%d consumed=%d", mip.CntData, len(mip.Data), consumed)

			objref, _, err := UnmarshalOBJREF(mip.Data)
			if err != nil {
				return fmt.Errorf("OBJREF %d: %w", i, err)
			}

			log.Debugf("PropsOutInfo: OBJREF flags=0x%x hasStd=%v", objref.Flags, objref.Std != nil)

			if objref.Std != nil {
				result.InterfaceIPID = objref.Std.IPID
				result.InterfaceOXID = objref.Std.OXID
				result.InterfaceOID = objref.Std.OID
				log.Debugf("PropsOutInfo: found IPID=%x OXID=0x%x OID=0x%x", objref.Std.IPID, objref.Std.OXID, objref.Std.OID)
				return nil
			}

			offset += consumed
		}
	}

	return nil
}

