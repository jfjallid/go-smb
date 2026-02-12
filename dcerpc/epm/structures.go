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

package epm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/ndr"
)

// Floor represents a single floor in an EPM tower.
type Floor struct {
	ProtocolID  byte
	UUID        []byte // 16 bytes, only for UUID floors (proto 0x0d)
	UUIDVersion uint16 // Major version for UUID floors
	RHSData     []byte
}

// Tower represents a DCE/RPC tower with multiple protocol floors.
type Tower struct {
	Floors []Floor
}

// NewRequestTower builds a 5-floor request tower for querying the EPM.
// Floor 1: Interface UUID
// Floor 2: NDR transfer syntax
// Floor 3: RPC connection-oriented protocol
// Floor 4: TCP (port 0 = unknown)
// Floor 5: IP (0.0.0.0)
func NewRequestTower(interfaceUUID string, majorVersion, minorVersion uint16) (*Tower, error) {
	ifUUID, err := dcerpc.UUIDToBin(interfaceUUID)
	if err != nil {
		return nil, fmt.Errorf("failed to encode interface UUID: %w", err)
	}

	ndrUUID, err := dcerpc.UUIDToBin(dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("failed to encode NDR UUID: %w", err)
	}

	t := &Tower{
		Floors: []Floor{
			{
				ProtocolID:  FloorProtoUUID,
				UUID:        ifUUID,
				UUIDVersion: majorVersion,
				RHSData:     make([]byte, 2), // minor version (LE)
			},
			{
				ProtocolID:  FloorProtoUUID,
				UUID:        ndrUUID,
				UUIDVersion: 2,
				RHSData:     make([]byte, 2), // minor version 0
			},
			{
				ProtocolID: FloorProtoRPCConn,
				RHSData:    make([]byte, 2), // minor version 0
			},
			{
				ProtocolID: FloorProtoTCP,
				RHSData:    make([]byte, 2), // port 0 (unknown)
			},
			{
				ProtocolID: FloorProtoIP,
				RHSData:    make([]byte, 4), // IP 0.0.0.0
			},
		},
	}

	// Encode minor version in floor 1 RHS (little-endian)
	le.PutUint16(t.Floors[0].RHSData, minorVersion)

	return t, nil
}

// MarshalTowerOctets encodes a tower into its binary octet string representation.
func (t *Tower) MarshalTowerOctets() ([]byte, error) {
	var buf bytes.Buffer

	// Number of floors (uint16 LE)
	if err := binary.Write(&buf, le, uint16(len(t.Floors))); err != nil {
		return nil, err
	}

	for _, f := range t.Floors {
		// LHS length (uint16 LE)
		lhsLen := uint16(1) // protocol ID byte
		if f.ProtocolID == FloorProtoUUID {
			lhsLen += 16 + 2 // UUID + major version
		}
		if err := binary.Write(&buf, le, lhsLen); err != nil {
			return nil, err
		}

		// LHS data
		buf.WriteByte(f.ProtocolID)
		if f.ProtocolID == FloorProtoUUID {
			buf.Write(f.UUID)
			if err := binary.Write(&buf, le, f.UUIDVersion); err != nil {
				return nil, err
			}
		}

		// RHS length (uint16 LE)
		if err := binary.Write(&buf, le, uint16(len(f.RHSData))); err != nil {
			return nil, err
		}

		// RHS data
		buf.Write(f.RHSData)
	}

	return buf.Bytes(), nil
}

// UnmarshalTowerOctets parses a tower from its binary octet string representation.
func UnmarshalTowerOctets(data []byte) (*Tower, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("tower data too short")
	}
	r := bytes.NewReader(data)

	var numFloors uint16
	if err := binary.Read(r, le, &numFloors); err != nil {
		return nil, fmt.Errorf("failed to read floor count: %w", err)
	}

	t := &Tower{Floors: make([]Floor, numFloors)}
	for i := uint16(0); i < numFloors; i++ {
		var lhsLen uint16
		if err := binary.Read(r, le, &lhsLen); err != nil {
			return nil, fmt.Errorf("failed to read LHS length for floor %d: %w", i, err)
		}

		if lhsLen < 1 {
			return nil, fmt.Errorf("invalid LHS length for floor %d: %d", i, lhsLen)
		}

		protoByte, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("failed to read protocol ID for floor %d: %w", i, err)
		}
		t.Floors[i].ProtocolID = protoByte

		if protoByte == FloorProtoUUID {
			// Remaining LHS is UUID (16) + version (2) = 18 bytes
			if lhsLen < 19 {
				return nil, fmt.Errorf("UUID floor %d LHS too short: %d", i, lhsLen)
			}
			t.Floors[i].UUID = make([]byte, 16)
			if _, err := r.Read(t.Floors[i].UUID); err != nil {
				return nil, fmt.Errorf("failed to read UUID for floor %d: %w", i, err)
			}
			if err := binary.Read(r, le, &t.Floors[i].UUIDVersion); err != nil {
				return nil, fmt.Errorf("failed to read UUID version for floor %d: %w", i, err)
			}
		} else {
			// Skip remaining LHS bytes (we already read the protocol ID)
			remaining := int(lhsLen) - 1
			if remaining > 0 {
				skip := make([]byte, remaining)
				if _, err := r.Read(skip); err != nil {
					return nil, fmt.Errorf("failed to skip LHS data for floor %d: %w", i, err)
				}
			}
		}

		var rhsLen uint16
		if err := binary.Read(r, le, &rhsLen); err != nil {
			return nil, fmt.Errorf("failed to read RHS length for floor %d: %w", i, err)
		}

		t.Floors[i].RHSData = make([]byte, rhsLen)
		if rhsLen > 0 {
			if _, err := r.Read(t.Floors[i].RHSData); err != nil {
				return nil, fmt.Errorf("failed to read RHS data for floor %d: %w", i, err)
			}
		}
	}

	return t, nil
}

// GetTCPPort extracts the TCP port from a tower's TCP floor.
// The port is stored big-endian in the RHS data.
func (t *Tower) GetTCPPort() (uint16, error) {
	for _, f := range t.Floors {
		if f.ProtocolID == FloorProtoTCP {
			if len(f.RHSData) < 2 {
				return 0, fmt.Errorf("TCP floor RHS data too short")
			}
			return binary.BigEndian.Uint16(f.RHSData[:2]), nil
		}
	}
	return 0, fmt.Errorf("no TCP floor found in tower")
}

// towerNDR maps to DCE IDL twr_t:
//
//	struct { uint32 tower_length; [size_is(tower_length)] byte tower_octet_string[]; }
type towerNDR struct {
	TowerLength      uint32
	TowerOctetString []byte `ndr:"conformant"`
}

// towerPtrNDR wraps towerNDR with a pointer tag so that in a conformant array
// of towers, each element is an NDR pointer (referent ID inline, data deferred).
type towerPtrNDR struct {
	Tower towerNDR `ndr:"pointer"`
}

// contextHandle maps to DCE context_handle_t:
//
//	struct { uint32 attributes; uuid_t uuid; }
//
// Using a struct (not [20]byte) so the uint32 field enforces 4-byte alignment
// after preceding conformant byte arrays (e.g., tower octets in the request).
type contextHandle struct {
	Attributes uint32
	UUID       [16]byte
}

// eptMapRequestNDR is the NDR wire representation of ept_map [in] parameters.
type eptMapRequestNDR struct {
	Object      *[16]byte     `ndr:"toppointer,fullpointer"` // uuid_p_t (nullable)
	MapTower    *towerNDR     `ndr:"toppointer,fullpointer"` // twr_p_t (nullable)
	EntryHandle contextHandle                                 // ept_lookup_handle_t
	MaxTowers   uint32
}

// eptMapResponseNDR is the NDR wire representation of ept_map [out] parameters.
type eptMapResponseNDR struct {
	EntryHandle [20]byte
	NumTowers   uint32
	Towers      []towerPtrNDR `ndr:"toppointer,conformant,varying"`
	Status      uint32
}

// EptMapRequest represents the NDR-encoded ept_map request body.
type EptMapRequest struct {
	Tower     *Tower
	MaxTowers uint32
}

// MarshalBinary encodes the ept_map request into NDR wire format.
func (req *EptMapRequest) MarshalBinary() ([]byte, error) {
	towerOctets, err := req.Tower.MarshalTowerOctets()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tower: %w", err)
	}

	ndrReq := &eptMapRequestNDR{
		MapTower: &towerNDR{
			TowerLength:      uint32(len(towerOctets)),
			TowerOctetString: towerOctets,
		},
		MaxTowers: req.MaxTowers,
	}

	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(ndrReq)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ept_map request: %w", err)
	}

	return b, nil
}

// EptMapResponse represents the NDR-encoded ept_map response body.
type EptMapResponse struct {
	ContextHandle [ContextHandleSize]byte
	NumTowers     uint32
	Towers        []Tower
	Status        uint32
}

// UnmarshalBinary decodes the ept_map response from NDR wire format.
func (resp *EptMapResponse) UnmarshalBinary(data []byte) error {
	var ndrResp eptMapResponseNDR
	dec := ndr.NewDecoder(bytes.NewReader(data), false)
	if err := dec.Decode(&ndrResp); err != nil {
		return fmt.Errorf("failed to decode ept_map response: %w", err)
	}

	// Convert contextHandle struct back to [20]byte
	//binary.LittleEndian.PutUint32(resp.ContextHandle[:4], ndrResp.EntryHandle.Attributes)
	//copy(resp.ContextHandle[4:], ndrResp.EntryHandle.UUID[:])
	copy(resp.ContextHandle[:], ndrResp.EntryHandle[:])

	resp.NumTowers = ndrResp.NumTowers
	resp.Status = ndrResp.Status

	resp.Towers = make([]Tower, 0, len(ndrResp.Towers))
	//for i, tp := range ndrResp.Towers {
	for i, tp := range ndrResp.Towers {
		if len(tp.Tower.TowerOctetString) == 0 {
	//	if len(tp.Tower.TowerOctetString) == 0 {
			continue // NULL tower pointer
		}
		tower, err := UnmarshalTowerOctets(tp.Tower.TowerOctetString)
		if err != nil {
			return fmt.Errorf("failed to unmarshal tower %d: %w", i, err)
		}
		resp.Towers = append(resp.Towers, *tower)
	}

	return nil
}
