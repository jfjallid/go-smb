// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
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

package server

import (
	"encoding/binary"
	"fmt"
)

// SMB2 CREATE contexts (MS-SMB2 §2.2.13.2). A CREATE request and response can
// each carry a chained list of tagged blobs. Each element is:
//
//	Next(4) NameOffset(2) NameLength(2) Reserved(2) DataOffset(2) DataLength(4)
//	Name(NameLength) [pad] Data(DataLength) [pad]
//
// All offsets are relative to the start of that element. Next is the byte
// offset to the following element, or 0 on the last one.

// Create-context names used by the durable-handle feature. The names are
// 4-character ASCII tags carried verbatim on the wire.
const (
	createContextDurableRequest     = "DHnQ" // SMB2_CREATE_DURABLE_HANDLE_REQUEST
	createContextDurableReconnect   = "DHnC" // SMB2_CREATE_DURABLE_HANDLE_RECONNECT
	createContextDurableRequestV2   = "DH2Q" // SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2
	createContextDurableReconnectV2 = "DH2C" // SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2
	createContextQueryMaximalAccess = "MxAc" // SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST
)

// SMB2_DHANDLE_FLAG_PERSISTENT marks a v2 durable request as asking for a
// persistent (rather than merely durable) handle (MS-SMB2 §2.2.13.2.11).
const smb2DHandleFlagPersistent uint32 = 0x00000002

// createContext is one decoded element of a CREATE context list.
type createContext struct {
	Name string
	Data []byte
}

// parseCreateContexts decodes the context list at buf (which must be exactly
// the CreateContexts region of the CREATE PDU). A malformed list is an error
// rather than a partial result: contexts drive handle semantics, so silently
// dropping one we could not parse would be worse than refusing the CREATE.
func parseCreateContexts(buf []byte) ([]createContext, error) {
	var out []createContext
	pos := 0
	for pos < len(buf) {
		if pos+16 > len(buf) {
			return nil, fmt.Errorf("create context header truncated at offset %d", pos)
		}
		e := buf[pos:]
		next := int(binary.LittleEndian.Uint32(e[0:4]))
		nameOff := int(binary.LittleEndian.Uint16(e[4:6]))
		nameLen := int(binary.LittleEndian.Uint16(e[6:8]))
		dataOff := int(binary.LittleEndian.Uint16(e[10:12]))
		dataLen := int(binary.LittleEndian.Uint32(e[12:16]))

		// The element extends to the next one, or to the end of the buffer for
		// the last element. Every field must land inside it.
		elemEnd := len(buf) - pos
		if next != 0 {
			if next < 16 || pos+next > len(buf) {
				return nil, fmt.Errorf("create context Next=%d out of range at offset %d", next, pos)
			}
			elemEnd = next
		}
		if nameOff < 0 || nameLen < 0 || nameOff+nameLen > elemEnd {
			return nil, fmt.Errorf("create context name out of range at offset %d", pos)
		}
		if dataLen < 0 || dataOff < 0 || (dataLen > 0 && dataOff+dataLen > elemEnd) {
			return nil, fmt.Errorf("create context data out of range at offset %d", pos)
		}

		cc := createContext{Name: string(e[nameOff : nameOff+nameLen])}
		if dataLen > 0 {
			cc.Data = append([]byte(nil), e[dataOff:dataOff+dataLen]...)
		}
		out = append(out, cc)

		if next == 0 {
			break
		}
		pos += next
	}
	return out, nil
}

// findCreateContext returns the first context with the given name.
func findCreateContext(ctxs []createContext, name string) (createContext, bool) {
	for _, cc := range ctxs {
		if cc.Name == name {
			return cc, true
		}
	}
	return createContext{}, false
}

// marshalCreateContexts serializes a context list for a CREATE response. The
// caller supplies the byte offset at which the list will be placed within the
// PDU; it is not needed for the encoding itself (all offsets are
// element-relative) but keeps the signature honest about the layout contract.
func marshalCreateContexts(ctxs []createContext) []byte {
	if len(ctxs) == 0 {
		return nil
	}
	var out []byte
	for i, cc := range ctxs {
		name := []byte(cc.Name)
		// Header(16) || Name || pad-to-8 || Data
		nameOff := 16
		dataOff := nameOff + len(name)
		if pad := dataOff % 8; pad != 0 {
			dataOff += 8 - pad
		}
		size := dataOff
		if len(cc.Data) > 0 {
			size += len(cc.Data)
		}
		// Every element but the last is padded to an 8-byte boundary so its
		// successor starts aligned.
		last := i == len(ctxs)-1
		if !last {
			if pad := size % 8; pad != 0 {
				size += 8 - pad
			}
		}

		e := make([]byte, size)
		if !last {
			binary.LittleEndian.PutUint32(e[0:4], uint32(size))
		}
		binary.LittleEndian.PutUint16(e[4:6], uint16(nameOff))
		binary.LittleEndian.PutUint16(e[6:8], uint16(len(name)))
		if len(cc.Data) > 0 {
			binary.LittleEndian.PutUint16(e[10:12], uint16(dataOff))
			binary.LittleEndian.PutUint32(e[12:16], uint32(len(cc.Data)))
			copy(e[dataOff:], cc.Data)
		}
		copy(e[nameOff:], name)
		out = append(out, e...)
	}
	return out
}

// durableRequestV2 is the decoded SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2 data
// (MS-SMB2 §2.2.13.2.11): Timeout(4) Flags(4) Reserved(8) CreateGuid(16).
type durableRequestV2 struct {
	Timeout    uint32 // requested timeout in milliseconds; 0 means "server picks"
	Flags      uint32
	CreateGuid [16]byte
}

func parseDurableRequestV2(data []byte) (durableRequestV2, error) {
	var d durableRequestV2
	if len(data) < 32 {
		return d, fmt.Errorf("DH2Q data is %d bytes, want 32", len(data))
	}
	d.Timeout = binary.LittleEndian.Uint32(data[0:4])
	d.Flags = binary.LittleEndian.Uint32(data[4:8])
	copy(d.CreateGuid[:], data[16:32])
	return d, nil
}

// durableReconnectV2 is the decoded SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2
// data (MS-SMB2 §2.2.13.2.12): FileId(16) CreateGuid(16) Flags(4).
type durableReconnectV2 struct {
	FileID     [16]byte
	CreateGuid [16]byte
	Flags      uint32
}

func parseDurableReconnectV2(data []byte) (durableReconnectV2, error) {
	var d durableReconnectV2
	if len(data) < 36 {
		return d, fmt.Errorf("DH2C data is %d bytes, want 36", len(data))
	}
	copy(d.FileID[:], data[0:16])
	copy(d.CreateGuid[:], data[16:32])
	d.Flags = binary.LittleEndian.Uint32(data[32:36])
	return d, nil
}

// parseDurableReconnect decodes SMB2_CREATE_DURABLE_HANDLE_RECONNECT (v1)
// data, which is just the 16-byte FileId (MS-SMB2 §2.2.13.2.4).
func parseDurableReconnect(data []byte) ([16]byte, error) {
	var id [16]byte
	if len(data) < 16 {
		return id, fmt.Errorf("DHnC data is %d bytes, want 16", len(data))
	}
	copy(id[:], data[0:16])
	return id, nil
}

// durableResponseV2 builds the SMB2_CREATE_DURABLE_HANDLE_RESPONSE_V2 data
// (MS-SMB2 §2.2.14.2.12): Timeout(4) Flags(4).
func durableResponseV2(timeoutMS uint32, persistent bool) []byte {
	data := make([]byte, 8)
	binary.LittleEndian.PutUint32(data[0:4], timeoutMS)
	if persistent {
		binary.LittleEndian.PutUint32(data[4:8], smb2DHandleFlagPersistent)
	}
	return data
}

// durableResponseV1 builds the SMB2_CREATE_DURABLE_HANDLE_RESPONSE data
// (MS-SMB2 §2.2.14.2.3), which is 8 reserved bytes.
func durableResponseV1() []byte {
	return make([]byte, 8)
}
