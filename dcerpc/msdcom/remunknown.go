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
// IRemUnknown interface for DCOM remote object management.
// Reference: [MS-DCOM] Sections 3.1.1.5.6 and 3.1.2.5.1.2

package msdcom

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
)

const (
	MSRPCUuidIRemUnknown                 = "00000131-0000-0000-c000-000000000046"
	MSRPCUuidIRemUnknown2                = "00000143-0000-0000-c000-000000000046"
	MSRPCIRemUnknownMajorVersion  uint16 = 0
	MSRPCIRemUnknownMinorVersion  uint16 = 0
	MSRPCIRemUnknown2MajorVersion uint16 = 0
	MSRPCIRemUnknown2MinorVersion uint16 = 0
)

// IRemUnknown opcodes (IUnknown methods 0-2 are implicit)
const (
	OpRemQueryInterface uint16 = 3
	OpRemAddRef         uint16 = 4
	OpRemRelease        uint16 = 5
)

// RemUnknown wraps a ServiceBind for the IRemUnknown interface.
// The ipid field is the IPID of the IRemUnknown interface itself,
// used as the Object UUID in every request PDU.
type RemUnknown struct {
	*dcerpc.ServiceBind
	ipid [16]byte
}

// NewRemUnknown creates a RemUnknown wrapper with the given IPID.
func NewRemUnknown(sb *dcerpc.ServiceBind, ipid [16]byte) *RemUnknown {
	return &RemUnknown{ServiceBind: sb, ipid: ipid}
}

// RemQueryInterface queries for additional interfaces on a remote COM object.
//
// MS-DCOM 3.1.2.5.1.2 - RemQueryInterface (Opnum 3)
//
// ripid is the IPID of the object to query.
// iids is the list of interface IIDs to request.
// Returns a REMQIRESULT for each requested IID.
func (r *RemUnknown) RemQueryInterface(cid [16]byte, ripid [16]byte, iids [][16]byte) ([]REMQIRESULT, error) {
	log.Debugf("RemQueryInterface: ObjectUUID(IpidRemUnknown)=%x RIPID=%x IIDs=%x", r.ipid, ripid, iids)
	buf := marshalRemQueryInterfaceRequest(cid, ripid, iids)

	result, err := r.MakeRequestWithObjectUUID(OpRemQueryInterface, r.ipid[:], buf)
	if err != nil {
		return nil, err
	}

	return unmarshalRemQueryInterfaceResponse(result, len(iids))
}

// RemRelease releases interface references on the remote COM server.
//
// MS-DCOM 3.1.2.5.1.2 - RemRelease (Opnum 5)
func (r *RemUnknown) RemRelease(cid [16]byte, refs []REMINTERFACEREF) error {
	buf := marshalRemReleaseRequest(cid, refs)

	result, err := r.MakeRequestWithObjectUUID(OpRemRelease, r.ipid[:], buf)
	if err != nil {
		return err
	}

	return unmarshalRemReleaseResponse(result)
}

// marshalRemQueryInterfaceRequest builds the request stub.
//
// Wire format:
//
//	ORPCTHIS (32 bytes)
//	IPID ripid (16 bytes)
//	uint32 cRefs (reference count for new interfaces, typically 5)
//	uint16 cIids
//	padding (2 bytes to align conformant array)
//	uint32 maxCount (= cIids)
//	[cIids] IID (16 bytes each)
func marshalRemQueryInterfaceRequest(cid [16]byte, ripid [16]byte, iids [][16]byte) []byte {
	cIids := uint16(len(iids))

	buf := make([]byte, 0, ORPCTHISSize+28+int(cIids)*16)

	// ORPCTHIS
	orpcThis := &ORPCTHIS{
		Version:     COMVERSION{MajorVersion: 5, MinorVersion: 7},
		CausalityId: cid,
	}
	buf = append(buf, orpcThis.MarshalBinary()...)

	// IPID ripid
	buf = append(buf, ripid[:]...)

	// cRefs (number of references to add per interface)
	buf = binary.LittleEndian.AppendUint32(buf, 5)

	// cIids
	buf = binary.LittleEndian.AppendUint16(buf, cIids)

	// Padding to align conformant array to 4-byte boundary
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	// Conformant array of IIDs
	buf = binary.LittleEndian.AppendUint32(buf, uint32(cIids)) // maxCount
	for _, iid := range iids {
		buf = append(buf, iid[:]...)
	}

	return buf
}

// unmarshalRemQueryInterfaceResponse parses the response stub.
//
// Wire format:
//
//	ORPCTHAT (variable)
//	ppQIResults referent_id (4 bytes)
//	[deferred: conformant array of REMQIRESULT]
//	HRESULT (4 bytes)
func unmarshalRemQueryInterfaceResponse(buf []byte, expectedCount int) ([]REMQIRESULT, error) {
	offset := 0

	// Parse ORPCTHAT
	_, consumed, err := UnmarshalORPCTHAT(buf)
	if err != nil {
		return nil, fmt.Errorf("RemQueryInterface ORPCTHAT: %w", err)
	}
	offset += consumed

	// ppQIResults referent ID
	if len(buf) < offset+4 {
		return nil, fmt.Errorf("RemQueryInterface: buffer too short for ppQIResults ptr")
	}
	refId := le.Uint32(buf[offset:])
	offset += 4

	var results []REMQIRESULT

	if refId != 0 {
		// Deferred: conformant array of REMQIRESULT
		if len(buf) < offset+4 {
			return nil, fmt.Errorf("RemQueryInterface: buffer too short for maxCount")
		}
		maxCount := le.Uint32(buf[offset:])
		offset += 4

		count := int(maxCount)
		if count > expectedCount {
			count = expectedCount
		}

		for i := 0; i < count; i++ {
			if len(buf) < offset+REMQIRESULTSize {
				return nil, fmt.Errorf("RemQueryInterface: buffer too short for REMQIRESULT %d", i)
			}
			r, err := UnmarshalREMQIRESULT(buf[offset:])
			if err != nil {
				return nil, fmt.Errorf("RemQueryInterface REMQIRESULT %d: %w", i, err)
			}
			results = append(results, r)
			offset += REMQIRESULTSize
		}
	}

	// HRESULT at end
	if len(buf) < offset+4 {
		return nil, fmt.Errorf("RemQueryInterface: buffer too short for HRESULT")
	}
	hresult := le.Uint32(buf[offset:])
	if hresult != 0 {
		return results, fmt.Errorf("RemQueryInterface failed: HRESULT 0x%08x", hresult)
	}

	return results, nil
}

// marshalRemReleaseRequest builds the request stub for RemRelease.
//
// Wire format:
//
//	ORPCTHIS (32 bytes)
//	uint16 cInterfaceRefs
//	padding (2 bytes)
//	uint32 maxCount (= cInterfaceRefs)
//	[cInterfaceRefs] REMINTERFACEREF (24 bytes each)
func marshalRemReleaseRequest(cid [16]byte, refs []REMINTERFACEREF) []byte {
	count := uint16(len(refs))

	buf := make([]byte, 0, ORPCTHISSize+8+int(count)*24)

	// ORPCTHIS
	orpcThis := &ORPCTHIS{
		Version:     COMVERSION{MajorVersion: 5, MinorVersion: 7},
		CausalityId: cid,
	}
	buf = append(buf, orpcThis.MarshalBinary()...)

	// cInterfaceRefs
	buf = binary.LittleEndian.AppendUint16(buf, count)

	// Padding to align conformant array
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	// Conformant array of REMINTERFACEREF
	buf = binary.LittleEndian.AppendUint32(buf, uint32(count)) // maxCount
	for _, ref := range refs {
		buf = append(buf, ref.MarshalBinary()...)
	}

	return buf
}

// unmarshalRemReleaseResponse parses the response stub.
//
// Wire format:
//
//	ORPCTHAT (variable)
//	HRESULT (4 bytes)
func unmarshalRemReleaseResponse(buf []byte) error {
	offset := 0

	// Parse ORPCTHAT
	_, consumed, err := UnmarshalORPCTHAT(buf)
	if err != nil {
		return fmt.Errorf("RemRelease ORPCTHAT: %w", err)
	}
	offset += consumed

	// HRESULT
	if len(buf) < offset+4 {
		return fmt.Errorf("RemRelease: buffer too short for HRESULT")
	}
	hresult := le.Uint32(buf[offset:])
	if hresult != 0 {
		return fmt.Errorf("RemRelease failed: HRESULT 0x%08x", hresult)
	}

	return nil
}
