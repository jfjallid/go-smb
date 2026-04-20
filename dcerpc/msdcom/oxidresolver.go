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
// IOXIDResolver (IObjectExporter) interface for DCOM OXID resolution.
// Reference: [MS-DCOM] Section 3.1.2.5.1 (IObjectExporter)
//
// Note: Not used in the current activation flow (bindings come directly from
// the RemoteCreateInstance result). Available for alternative OXID resolution.

package msdcom

import (
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
)

const (
	MSRPCUuidIOXIDResolver                = "99fcfec4-5260-101b-bbcb-00aa0021347a"
	MSRPCIOXIDResolverMajorVersion uint16 = 0
	MSRPCIOXIDResolverMinorVersion uint16 = 0
)

// IOXIDResolver opcodes
const (
	OpResolveOxid2 uint16 = 5
)

// OXIDResolver wraps a ServiceBind for the IObjectExporter interface.
type OXIDResolver struct {
	*dcerpc.ServiceBind
}

// ResolveOxid2Result holds the parsed response from ResolveOxid2.
type ResolveOxid2Result struct {
	Bindings       DUALSTRINGARRAY
	IpidRemUnknown [16]byte
	AuthnHint      uint32
	ComVersion     COMVERSION
}

// ResolveOxid2 resolves an OXID to obtain the string bindings for the
// dynamic endpoint, the IPID of IRemUnknown, and the COM version.
//
// MS-DCOM 3.1.2.5.1.3 - ResolveOxid2 (Opnum 5)
func (o *OXIDResolver) ResolveOxid2(oxid uint64, requestedProtseqs []uint16) (*ResolveOxid2Result, error) {
	buf := marshalResolveOxid2Request(oxid, requestedProtseqs)

	result, err := o.MakeRequest(OpResolveOxid2, buf)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return unmarshalResolveOxid2Response(result)
}

// marshalResolveOxid2Request builds the NDR-encoded request body for ResolveOxid2.
//
// Wire format:
//
//	uint64   oxid
//	uint16   cRequestedProtseqs
//	[cRequestedProtseqs] uint16 arRequestedProtseqs  (conformant array: max_count first)
func marshalResolveOxid2Request(oxid uint64, protseqs []uint16) []byte {
	count := uint16(len(protseqs))
	// 8 (oxid) + 2 (count) + 2 (padding) + 4 (max_count) + count*2 (array)
	size := 8 + 2 + 2 + 4 + int(count)*2
	buf := make([]byte, size)
	offset := 0

	le.PutUint64(buf[offset:], oxid)
	offset += 8

	le.PutUint16(buf[offset:], count)
	offset += 2

	// Padding to align conformant array to 4-byte boundary
	offset += 2

	// Conformant array max_count
	le.PutUint32(buf[offset:], uint32(count))
	offset += 4

	for _, ps := range protseqs {
		le.PutUint16(buf[offset:], ps)
		offset += 2
	}

	return buf
}

// unmarshalResolveOxid2Response parses the response body from ResolveOxid2.
//
// Wire format:
//
//	uint32 referent ID for ppdsaOxidBindings (pointer)
//	[16]byte ipidRemUnknown
//	uint32 authnHint
//	COMVERSION comVersion
//	uint32 status (HRESULT)
//	--- deferred pointer data ---
//	DUALSTRINGARRAY (for ppdsaOxidBindings)
func unmarshalResolveOxid2Response(buf []byte) (*ResolveOxid2Result, error) {
	if len(buf) < 32 {
		return nil, fmt.Errorf("ResolveOxid2 response too short (%d < 32)", len(buf))
	}

	offset := 0

	// Pointer referent ID for ppdsaOxidBindings
	bindingsRefId := le.Uint32(buf[offset:])
	offset += 4

	// ipidRemUnknown (16 bytes)
	var ipid [16]byte
	copy(ipid[:], buf[offset:offset+16])
	offset += 16

	// authnHint
	authnHint := le.Uint32(buf[offset:])
	offset += 4

	// COMVERSION (4 bytes)
	comVersion, err := UnmarshalCOMVERSION(buf[offset:])
	if err != nil {
		return nil, fmt.Errorf("ResolveOxid2: %w", err)
	}
	offset += 4

	// status (HRESULT)
	if len(buf) < offset+4 {
		return nil, fmt.Errorf("ResolveOxid2 response too short for status")
	}
	status := le.Uint32(buf[offset:])
	offset += 4

	if status != 0 {
		return nil, fmt.Errorf("ResolveOxid2 returned error: 0x%08x", status)
	}

	// Deferred pointer data: DUALSTRINGARRAY (only if referent ID was non-zero)
	result := &ResolveOxid2Result{
		IpidRemUnknown: ipid,
		AuthnHint:      authnHint,
		ComVersion:     comVersion,
	}

	if bindingsRefId != 0 {
		if len(buf) < offset+4 {
			return nil, fmt.Errorf("ResolveOxid2: buffer too short for DUALSTRINGARRAY")
		}
		dsa, _, err := UnmarshalDUALSTRINGARRAY(buf[offset:])
		if err != nil {
			return nil, fmt.Errorf("ResolveOxid2 DUALSTRINGARRAY: %w", err)
		}
		result.Bindings = dsa
	}

	return result, nil
}
