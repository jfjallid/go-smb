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
	"net"

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

// UUIDFloor holds the parsed content of a UUID protocol floor.
type UUIDFloor struct {
	UUID         string
	MajorVersion uint16
	MinorVersion uint16
}

// GetTCPPort returns the TCP port number from this floor.
// Returns an error if the floor is not a TCP floor or the RHS data is too short.
func (f *Floor) GetTCPPort() (uint16, error) {
	if f.ProtocolID != FloorProtoTCP {
		return 0, fmt.Errorf("floor is not a TCP floor (proto 0x%02x)", f.ProtocolID)
	}
	if len(f.RHSData) < 2 {
		return 0, fmt.Errorf("TCP floor RHS data too short")
	}
	return binary.BigEndian.Uint16(f.RHSData[:2]), nil
}

// GetUDPPort returns the UDP port number from this floor.
// Returns an error if the floor is not a UDP floor or the RHS data is too short.
func (f *Floor) GetUDPPort() (uint16, error) {
	if f.ProtocolID != FloorProtoUDP {
		return 0, fmt.Errorf("floor is not a UDP floor (proto 0x%02x)", f.ProtocolID)
	}
	if len(f.RHSData) < 2 {
		return 0, fmt.Errorf("UDP floor RHS data too short")
	}
	return binary.BigEndian.Uint16(f.RHSData[:2]), nil
}

// GetIPv4Address returns the IPv4 address from this floor.
// Returns an error if the floor is not an IP floor or the RHS data is too short.
func (f *Floor) GetIPv4Address() (net.IP, error) {
	if f.ProtocolID != FloorProtoIP {
		return nil, fmt.Errorf("floor is not an IP floor (proto 0x%02x)", f.ProtocolID)
	}
	if len(f.RHSData) < 4 {
		return nil, fmt.Errorf("IP floor RHS data too short")
	}
	ip := make(net.IP, 4)
	copy(ip, f.RHSData[:4])
	return ip, nil
}

// GetUUID returns the parsed UUID, major version, and minor version from this floor.
// Returns an error if the floor is not a UUID floor or the data is malformed.
func (f *Floor) GetUUID() (UUIDFloor, error) {
	if f.ProtocolID != FloorProtoUUID {
		return UUIDFloor{}, fmt.Errorf("floor is not a UUID floor (proto 0x%02x)", f.ProtocolID)
	}
	if len(f.UUID) < 16 {
		return UUIDFloor{}, fmt.Errorf("UUID floor has insufficient UUID bytes: %d", len(f.UUID))
	}
	if len(f.RHSData) < 2 {
		return UUIDFloor{}, fmt.Errorf("UUID floor RHS data too short for minor version")
	}
	// Reverse of dcerpc.UUIDToBin: Data1/Data2/Data3 are little-endian, Data4 is big-endian.
	d1 := binary.LittleEndian.Uint32(f.UUID[0:4])
	d2 := binary.LittleEndian.Uint16(f.UUID[4:6])
	d3 := binary.LittleEndian.Uint16(f.UUID[6:8])
	uuidStr := fmt.Sprintf("%08X-%04X-%04X-%04X-%04X%08X",
		d1, d2, d3,
		binary.BigEndian.Uint16(f.UUID[8:10]),
		binary.BigEndian.Uint16(f.UUID[10:12]),
		binary.BigEndian.Uint32(f.UUID[12:16]))
	minor := binary.LittleEndian.Uint16(f.RHSData[:2])
	return UUIDFloor{UUID: uuidStr, MajorVersion: f.UUIDVersion, MinorVersion: minor}, nil
}

// GetRPCVersion returns the minor version from an RPC connection-oriented floor.
// Returns an error if the floor is not an RPC connection floor or the RHS data is too short.
func (f *Floor) GetRPCVersion() (uint16, error) {
	if f.ProtocolID != FloorProtoRPCConn {
		return 0, fmt.Errorf("floor is not an RPC connection floor (proto 0x%02x)", f.ProtocolID)
	}
	if len(f.RHSData) < 2 {
		return 0, fmt.Errorf("RPC connection floor RHS data too short")
	}
	return binary.LittleEndian.Uint16(f.RHSData[:2]), nil
}

// GetPipeName returns the named pipe path from this floor as a string.
// The name is stored as a null-terminated byte string in the RHS data.
// Returns an error if the floor is not a named pipe floor.
func (f *Floor) GetPipeName() (string, error) {
	if f.ProtocolID != FloorProtoNPipe {
		return "", fmt.Errorf("floor is not a named pipe floor (proto 0x%02x)", f.ProtocolID)
	}
	name := f.RHSData
	if idx := bytes.IndexByte(name, 0); idx >= 0 {
		name = name[:idx]
	}
	return string(name), nil
}

// GetNetBIOSName returns the NetBIOS name from this floor as a string.
// The name is stored as a null-terminated byte string in the RHS data.
// Returns an error if the floor is not a NetBIOS name floor.
func (f *Floor) GetNetBIOSName() (string, error) {
	if f.ProtocolID != FloorProtoNBName {
		return "", fmt.Errorf("floor is not a NetBIOS name floor (proto 0x%02x)", f.ProtocolID)
	}
	name := f.RHSData
	if idx := bytes.IndexByte(name, 0); idx >= 0 {
		name = name[:idx]
	}
	return string(name), nil
}

// GetTCPPorts returns all TCP port numbers found across all TCP floors in the tower.
func (t *Tower) GetTCPPorts() ([]uint16, error) {
	var ports []uint16
	for _, f := range t.Floors {
		if f.ProtocolID != FloorProtoTCP {
			continue
		}
		port, err := f.GetTCPPort()
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// GetUDPPorts returns all UDP port numbers found across all UDP floors in the tower.
func (t *Tower) GetUDPPorts() ([]uint16, error) {
	var ports []uint16
	for _, f := range t.Floors {
		if f.ProtocolID != FloorProtoUDP {
			continue
		}
		port, err := f.GetUDPPort()
		if err != nil {
			return nil, err
		}
		ports = append(ports, port)
	}
	return ports, nil
}

// GetIPAddresses returns all IPv4 addresses (as dotted-decimal strings) found
// across all IP floors in the tower.
func (t *Tower) GetIPAddresses() ([]string, error) {
	var addrs []string
	for _, f := range t.Floors {
		if f.ProtocolID != FloorProtoIP {
			continue
		}
		ip, err := f.GetIPv4Address()
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, ip.String())
	}
	return addrs, nil
}

// GetUUIDs returns all parsed UUID floors found in the tower.
func (t *Tower) GetUUIDs() ([]UUIDFloor, error) {
	var uuids []UUIDFloor
	for _, f := range t.Floors {
		if f.ProtocolID != FloorProtoUUID {
			continue
		}
		u, err := f.GetUUID()
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, u)
	}
	return uuids, nil
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

// GetTCPPort extracts the TCP port from the first TCP floor in the tower.
// Use GetTCPPorts to retrieve all TCP ports when more than one may be present.
func (t *Tower) GetTCPPort() (uint16, error) {
	ports, err := t.GetTCPPorts()
	if err != nil {
		return 0, err
	}
	if len(ports) == 0 {
		return 0, fmt.Errorf("no TCP floor found in tower")
	}
	return ports[0], nil
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
	EntryHandle contextHandle // ept_lookup_handle_t
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
	copy(resp.ContextHandle[:], ndrResp.EntryHandle[:])

	resp.NumTowers = ndrResp.NumTowers
	resp.Status = ndrResp.Status

	resp.Towers = make([]Tower, 0, len(ndrResp.Towers))
	for i, tp := range ndrResp.Towers {
		if len(tp.Tower.TowerOctetString) == 0 {
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
