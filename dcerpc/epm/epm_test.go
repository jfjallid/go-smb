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
	"encoding/hex"
	"testing"
)

func TestNewRequestTower(t *testing.T) {
	// Use the SRVS interface UUID as test input
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	tower, err := NewRequestTower(srvUUID, 3, 0)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	if len(tower.Floors) != 5 {
		t.Fatalf("expected 5 floors, got %d", len(tower.Floors))
	}

	// Floor 1: Interface UUID
	if tower.Floors[0].ProtocolID != FloorProtoUUID {
		t.Errorf("floor 0: expected proto 0x0d, got 0x%02x", tower.Floors[0].ProtocolID)
	}
	if len(tower.Floors[0].UUID) != 16 {
		t.Errorf("floor 0: expected 16-byte UUID, got %d", len(tower.Floors[0].UUID))
	}
	if tower.Floors[0].UUIDVersion != 3 {
		t.Errorf("floor 0: expected major version 3, got %d", tower.Floors[0].UUIDVersion)
	}

	// Floor 2: NDR transfer syntax
	if tower.Floors[1].ProtocolID != FloorProtoUUID {
		t.Errorf("floor 1: expected proto 0x0d, got 0x%02x", tower.Floors[1].ProtocolID)
	}
	if tower.Floors[1].UUIDVersion != 2 {
		t.Errorf("floor 1: expected NDR version 2, got %d", tower.Floors[1].UUIDVersion)
	}

	// Floor 3: RPC connection-oriented
	if tower.Floors[2].ProtocolID != FloorProtoRPCConn {
		t.Errorf("floor 2: expected proto 0x0b, got 0x%02x", tower.Floors[2].ProtocolID)
	}

	// Floor 4: TCP
	if tower.Floors[3].ProtocolID != FloorProtoTCP {
		t.Errorf("floor 3: expected proto 0x07, got 0x%02x", tower.Floors[3].ProtocolID)
	}

	// Floor 5: IP
	if tower.Floors[4].ProtocolID != FloorProtoIP {
		t.Errorf("floor 4: expected proto 0x09, got 0x%02x", tower.Floors[4].ProtocolID)
	}
}

func TestGetTCPPort(t *testing.T) {
	// Build a tower with a known TCP port (big-endian 0x01BB = 443)
	tower := &Tower{
		Floors: []Floor{
			{ProtocolID: FloorProtoUUID, UUID: make([]byte, 16), UUIDVersion: 1, RHSData: []byte{0, 0}},
			{ProtocolID: FloorProtoUUID, UUID: make([]byte, 16), UUIDVersion: 2, RHSData: []byte{0, 0}},
			{ProtocolID: FloorProtoRPCConn, RHSData: []byte{0, 0}},
			{ProtocolID: FloorProtoTCP, RHSData: []byte{0x01, 0xBB}}, // port 443 big-endian
			{ProtocolID: FloorProtoIP, RHSData: []byte{192, 168, 1, 1}},
		},
	}

	port, err := tower.GetTCPPort()
	if err != nil {
		t.Fatalf("GetTCPPort failed: %v", err)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestGetTCPPortNoTCPFloor(t *testing.T) {
	tower := &Tower{
		Floors: []Floor{
			{ProtocolID: FloorProtoUUID, UUID: make([]byte, 16), UUIDVersion: 1, RHSData: []byte{0, 0}},
			{ProtocolID: FloorProtoRPCConn, RHSData: []byte{0, 0}},
		},
	}

	_, err := tower.GetTCPPort()
	if err == nil {
		t.Fatal("expected error for tower without TCP floor")
	}
}

func TestTowerMarshalRoundtrip(t *testing.T) {
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	tower, err := NewRequestTower(srvUUID, 3, 0)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	data, err := tower.MarshalTowerOctets()
	if err != nil {
		t.Fatalf("MarshalTowerOctets failed: %v", err)
	}

	tower2, err := UnmarshalTowerOctets(data)
	if err != nil {
		t.Fatalf("UnmarshalTowerOctets failed: %v", err)
	}

	data2, err := tower2.MarshalTowerOctets()
	if err != nil {
		t.Fatalf("second MarshalTowerOctets failed: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Errorf("roundtrip mismatch:\n  first:  %s\n  second: %s", hex.EncodeToString(data), hex.EncodeToString(data2))
	}

	// Verify parsed tower matches original
	if len(tower2.Floors) != 5 {
		t.Fatalf("expected 5 floors after roundtrip, got %d", len(tower2.Floors))
	}
	if tower2.Floors[0].UUIDVersion != 3 {
		t.Errorf("expected major version 3 after roundtrip, got %d", tower2.Floors[0].UUIDVersion)
	}
	if !bytes.Equal(tower.Floors[0].UUID, tower2.Floors[0].UUID) {
		t.Errorf("UUID mismatch after roundtrip")
	}
}

func TestEptMapRequestMarshal(t *testing.T) {
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	tower, err := NewRequestTower(srvUUID, 3, 0)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	req := &EptMapRequest{
		Tower:     tower,
		MaxTowers: 4,
	}

	data, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// Verify structure:
	// [0:4] Object UUID ptr = NULL (0x00000000)
	if binary.LittleEndian.Uint32(data[0:4]) != 0 {
		t.Error("expected NULL object UUID pointer")
	}

	// [4:8] Tower referent ID (non-NULL)
	if binary.LittleEndian.Uint32(data[4:8]) == 0 {
		t.Error("expected non-NULL tower referent ID")
	}

	// The tower octets follow at offset 16 (after 2x uint32 for conformant header)
	towerOctets, err := tower.MarshalTowerOctets()
	if err != nil {
		t.Fatalf("MarshalTowerOctets failed: %v", err)
	}
	towerLen := uint32(len(towerOctets))

	// [8:12] max_count
	if binary.LittleEndian.Uint32(data[8:12]) != towerLen {
		t.Errorf("expected max_count %d, got %d", towerLen, binary.LittleEndian.Uint32(data[8:12]))
	}

	// [12:16] actual_length
	if binary.LittleEndian.Uint32(data[12:16]) != towerLen {
		t.Errorf("expected actual_length %d, got %d", towerLen, binary.LittleEndian.Uint32(data[12:16]))
	}

	// Tower data at [16:16+towerLen]
	if !bytes.Equal(data[16:16+towerLen], towerOctets) {
		t.Error("tower octet data mismatch in marshaled request")
	}

	// After tower data + padding: context handle (20 zeros) + max_towers (4)
	padLen := (4 - (int(towerLen) % 4)) % 4
	handleOffset := 16 + int(towerLen) + padLen
	contextHandle := data[handleOffset : handleOffset+ContextHandleSize]
	if !bytes.Equal(contextHandle, make([]byte, ContextHandleSize)) {
		t.Error("expected zero context handle")
	}

	maxTowersVal := binary.LittleEndian.Uint32(data[handleOffset+ContextHandleSize:])
	if maxTowersVal != 4 {
		t.Errorf("expected max_towers 4, got %d", maxTowersVal)
	}
}

func TestEptMapResponseUnmarshal(t *testing.T) {
	// Build a synthetic ept_map response with one tower containing TCP port 49152 (0xC000 big-endian)
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	respTower, err := NewRequestTower(srvUUID, 3, 0)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	// Set the TCP port to 49152 (big-endian: 0xC0, 0x00)
	respTower.Floors[3].RHSData = []byte{0xC0, 0x00}
	// Set an IP address
	respTower.Floors[4].RHSData = []byte{10, 0, 0, 1}

	towerOctets, err := respTower.MarshalTowerOctets()
	if err != nil {
		t.Fatalf("MarshalTowerOctets failed: %v", err)
	}

	var buf bytes.Buffer

	// Context handle (20 zero bytes)
	buf.Write(make([]byte, ContextHandleSize))

	// num_towers = 1
	binary.Write(&buf, le, uint32(1))

	// Towers array immediate representation.
	// The toppointer tag causes a recursive process() call that reads max_count inline
	// (not hoisted), then offset/actual_count, then referent IDs for each element.
	// The recursive process() also immediately processes all deferred pointer data
	// (actual tower structs) before returning, so Status must come AFTER tower data.
	binary.Write(&buf, le, uint32(1)) // max_count
	binary.Write(&buf, le, uint32(0)) // offset
	binary.Write(&buf, le, uint32(1)) // actual_count
	binary.Write(&buf, le, uint32(0x00020000)) // referent ID for towers[0] (non-null)

	// Deferred tower pointer data (consumed by inner process() before Status is read).
	// towerNDR: conformant byte array — max_count hoisted to front of this struct.
	towerLen := uint32(len(towerOctets))
	binary.Write(&buf, le, towerLen) // conformant max_count for TowerOctetString
	binary.Write(&buf, le, towerLen) // TowerLength field
	buf.Write(towerOctets)

	// Pad to 4-byte alignment
	padLen := (4 - (int(towerLen) % 4)) % 4
	for i := 0; i < padLen; i++ {
		buf.WriteByte(0)
	}

	// Status comes after all deferred pointer data because the toppointer inner
	// process() consumes deferred data before returning to outer fill() for Status.
	binary.Write(&buf, le, uint32(0))

	// Now unmarshal
	var resp EptMapResponse
	if err := resp.UnmarshalBinary(buf.Bytes()); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if resp.NumTowers != 1 {
		t.Fatalf("expected 1 tower, got %d", resp.NumTowers)
	}
	if len(resp.Towers) != 1 {
		t.Fatalf("expected 1 parsed tower, got %d", len(resp.Towers))
	}
	if resp.Status != 0 {
		t.Errorf("expected status 0, got 0x%08x", resp.Status)
	}

	port, err := resp.Towers[0].GetTCPPort()
	if err != nil {
		t.Fatalf("GetTCPPort failed: %v", err)
	}
	if port != 49152 {
		t.Errorf("expected port 49152, got %d", port)
	}
}

func TestEptMapResponseNotRegistered(t *testing.T) {
	var buf bytes.Buffer

	// Context handle
	buf.Write(make([]byte, ContextHandleSize))

	// num_towers = 0
	binary.Write(&buf, le, uint32(0))

	// max_count for Towers: inline (not hoisted) because toppointer tag causes a
	// recursive process() call that reads max_count at the current stream position.
	binary.Write(&buf, le, uint32(4)) // max_count (from max_towers)

	// Varying array header (always present even when empty)
	binary.Write(&buf, le, uint32(0)) // offset
	binary.Write(&buf, le, uint32(0)) // actual_count

	// Status = EPT_S_NOT_REGISTERED
	binary.Write(&buf, le, EptSNotRegistered)

	var resp EptMapResponse
	if err := resp.UnmarshalBinary(buf.Bytes()); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if resp.NumTowers != 0 {
		t.Errorf("expected 0 towers, got %d", resp.NumTowers)
	}
	if resp.Status != EptSNotRegistered {
		t.Errorf("expected EPT_S_NOT_REGISTERED (0x%08x), got 0x%08x", EptSNotRegistered, resp.Status)
	}
}

func TestEptMapResponseUnmarshal2(t *testing.T) {
	resBytes, err := hex.DecodeString("000000000000000000000000000000000000000001000000040000000000000001000000010002004b0000004b000000050013000d81bb7a364498f135ad3298f03800100302000200000013000d045d888aeb1cc9119fe808002b10486002000200000001000b020000000100070200c20f0100090400646464340000000000")
	if err != nil {
		t.Errorf("failed to decode testdata: %v", err)
	}

	var resp EptMapResponse
	if err := resp.UnmarshalBinary(resBytes); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if resp.NumTowers != 1 {
		t.Fatalf("expected 1 tower, got %d", resp.NumTowers)
	}
	if len(resp.Towers) != 1 {
		t.Fatalf("expected 1 parsed tower, got %d", len(resp.Towers))
	}
	if resp.Status != 0 {
		t.Errorf("expected status 0, got 0x%08x", resp.Status)
	}

	port, err := resp.Towers[0].GetTCPPort()
	if err != nil {
		t.Fatalf("GetTCPPort failed: %v", err)
	}
	if port != 49679 {
		t.Errorf("expected port 49679, got %d", port)
	}

	// The captured wire data encodes IP floor as bytes 0x64 0x64 0x64 0x34 = 100.100.100.52
	addrs, err := resp.Towers[0].GetIPAddresses()
	if err != nil {
		t.Fatalf("GetIPAddresses failed: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 IP address, got %d", len(addrs))
	}
	if addrs[0] != "100.100.100.52" {
		t.Errorf("expected IP 100.100.100.52, got %s", addrs[0])
	}
	uuids, err := resp.Towers[0].GetUUIDs()
	if err != nil {
		t.Fatalf("GetUUIDs failed: %v", err)
	}
	if len(uuids) != 2 {
		t.Fatalf("expected 2 UUIDs, got %d", len(uuids))
	}
	if uuids[0].UUID != "367ABB81-9844-35F1-AD32-98F038001003" {
		t.Errorf("expected UUID 367ABB81-9844-35F1-AD32-98F038001003, got %s", uuids[0].UUID)
	}
	if uuids[0].MajorVersion != 2 {
		t.Errorf("expected UUID Major version 2, got %d", uuids[0].MajorVersion)
	}
	if uuids[0].MinorVersion != 0 {
		t.Errorf("expected UUID Minor version 0, got %d", uuids[0].MinorVersion)
	}
	if uuids[1].UUID != "8A885D04-1CEB-11C9-9FE8-08002B104860" {
		t.Errorf("expected UUID 8A885D04-1CEB-11C9-9FE8-08002B104860, got %s", uuids[1].UUID)
	}
	if uuids[1].MajorVersion != 2 {
		t.Errorf("expected UUID Major version 2, got %d", uuids[1].MajorVersion)
	}
	if uuids[1].MinorVersion != 0 {
		t.Errorf("expected UUID Minor version 0, got %d", uuids[1].MinorVersion)
	}
}

func TestFloorGetTCPPort(t *testing.T) {
	f := Floor{ProtocolID: FloorProtoTCP, RHSData: []byte{0x01, 0xBB}} // port 443 big-endian
	port, err := f.GetTCPPort()
	if err != nil {
		t.Fatalf("GetTCPPort failed: %v", err)
	}
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}

	wrong := Floor{ProtocolID: FloorProtoUDP, RHSData: []byte{0x01, 0xBB}}
	if _, err := wrong.GetTCPPort(); err == nil {
		t.Error("expected error for non-TCP floor, got nil")
	}
}

func TestFloorGetUDPPort(t *testing.T) {
	f := Floor{ProtocolID: FloorProtoUDP, RHSData: []byte{0x00, 0x35}} // port 53 big-endian
	port, err := f.GetUDPPort()
	if err != nil {
		t.Fatalf("GetUDPPort failed: %v", err)
	}
	if port != 53 {
		t.Errorf("expected port 53, got %d", port)
	}

	wrong := Floor{ProtocolID: FloorProtoTCP, RHSData: []byte{0x00, 0x35}}
	if _, err := wrong.GetUDPPort(); err == nil {
		t.Error("expected error for non-UDP floor, got nil")
	}
}

func TestFloorGetIPv4Address(t *testing.T) {
	f := Floor{ProtocolID: FloorProtoIP, RHSData: []byte{192, 168, 1, 100}}
	ip, err := f.GetIPv4Address()
	if err != nil {
		t.Fatalf("GetIPv4Address failed: %v", err)
	}
	if ip.String() != "192.168.1.100" {
		t.Errorf("expected 192.168.1.100, got %s", ip.String())
	}

	wrong := Floor{ProtocolID: FloorProtoTCP, RHSData: []byte{192, 168, 1, 100}}
	if _, err := wrong.GetIPv4Address(); err == nil {
		t.Error("expected error for non-IP floor, got nil")
	}
}

func TestFloorGetUUID(t *testing.T) {
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	tower, err := NewRequestTower(srvUUID, 3, 1)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	// Floor 0 is the interface UUID floor
	u, err := tower.Floors[0].GetUUID()
	if err != nil {
		t.Fatalf("GetUUID failed: %v", err)
	}
	if u.UUID != srvUUID {
		t.Errorf("expected UUID %s, got %s", srvUUID, u.UUID)
	}
	if u.MajorVersion != 3 {
		t.Errorf("expected major version 3, got %d", u.MajorVersion)
	}
	if u.MinorVersion != 1 {
		t.Errorf("expected minor version 1, got %d", u.MinorVersion)
	}

	wrong := Floor{ProtocolID: FloorProtoTCP, RHSData: []byte{0, 0}}
	if _, err := wrong.GetUUID(); err == nil {
		t.Error("expected error for non-UUID floor, got nil")
	}
}

func TestFloorGetRPCVersion(t *testing.T) {
	f := Floor{ProtocolID: FloorProtoRPCConn, RHSData: []byte{0x03, 0x00}} // minor version 3
	ver, err := f.GetRPCVersion()
	if err != nil {
		t.Fatalf("GetRPCVersion failed: %v", err)
	}
	if ver != 3 {
		t.Errorf("expected version 3, got %d", ver)
	}

	wrong := Floor{ProtocolID: FloorProtoTCP, RHSData: []byte{0x03, 0x00}}
	if _, err := wrong.GetRPCVersion(); err == nil {
		t.Error("expected error for non-RPC-conn floor, got nil")
	}
}

func TestFloorGetPipeName(t *testing.T) {
	pipe := `\PIPE\svcctl`
	f := Floor{ProtocolID: FloorProtoNPipe, RHSData: append([]byte(pipe), 0x00)}
	name, err := f.GetPipeName()
	if err != nil {
		t.Fatalf("GetPipeName failed: %v", err)
	}
	if name != pipe {
		t.Errorf("expected %q, got %q", pipe, name)
	}

	// No null terminator — should return the whole RHS as-is
	f2 := Floor{ProtocolID: FloorProtoNPipe, RHSData: []byte(pipe)}
	name2, err := f2.GetPipeName()
	if err != nil {
		t.Fatalf("GetPipeName (no null) failed: %v", err)
	}
	if name2 != pipe {
		t.Errorf("expected %q, got %q", pipe, name2)
	}

	wrong := Floor{ProtocolID: FloorProtoTCP}
	if _, err := wrong.GetPipeName(); err == nil {
		t.Error("expected error for non-pipe floor, got nil")
	}
}

func TestFloorGetNetBIOSName(t *testing.T) {
	nbname := "WORKSTATION"
	f := Floor{ProtocolID: FloorProtoNBName, RHSData: append([]byte(nbname), 0x00)}
	name, err := f.GetNetBIOSName()
	if err != nil {
		t.Fatalf("GetNetBIOSName failed: %v", err)
	}
	if name != nbname {
		t.Errorf("expected %q, got %q", nbname, name)
	}

	wrong := Floor{ProtocolID: FloorProtoTCP}
	if _, err := wrong.GetNetBIOSName(); err == nil {
		t.Error("expected error for non-NetBIOS floor, got nil")
	}
}

func TestGetTCPPorts(t *testing.T) {
	tower := &Tower{
		Floors: []Floor{
			{ProtocolID: FloorProtoTCP, RHSData: []byte{0x00, 0x50}},  // port 80
			{ProtocolID: FloorProtoTCP, RHSData: []byte{0x01, 0xBB}},  // port 443
			{ProtocolID: FloorProtoIP, RHSData: []byte{10, 0, 0, 1}},
		},
	}

	ports, err := tower.GetTCPPorts()
	if err != nil {
		t.Fatalf("GetTCPPorts failed: %v", err)
	}
	if len(ports) != 2 {
		t.Fatalf("expected 2 TCP ports, got %d", len(ports))
	}
	if ports[0] != 80 {
		t.Errorf("expected first port 80, got %d", ports[0])
	}
	if ports[1] != 443 {
		t.Errorf("expected second port 443, got %d", ports[1])
	}

	// Empty case — no TCP floors
	empty := &Tower{Floors: []Floor{{ProtocolID: FloorProtoIP, RHSData: []byte{0, 0, 0, 0}}}}
	emptyPorts, err := empty.GetTCPPorts()
	if err != nil {
		t.Fatalf("GetTCPPorts (empty) failed: %v", err)
	}
	if len(emptyPorts) != 0 {
		t.Errorf("expected 0 ports for tower with no TCP floors, got %d", len(emptyPorts))
	}
}

func TestGetUDPPorts(t *testing.T) {
	tower := &Tower{
		Floors: []Floor{
			{ProtocolID: FloorProtoUDP, RHSData: []byte{0x00, 0x35}}, // port 53
			{ProtocolID: FloorProtoIP, RHSData: []byte{10, 0, 0, 1}},
		},
	}

	ports, err := tower.GetUDPPorts()
	if err != nil {
		t.Fatalf("GetUDPPorts failed: %v", err)
	}
	if len(ports) != 1 {
		t.Fatalf("expected 1 UDP port, got %d", len(ports))
	}
	if ports[0] != 53 {
		t.Errorf("expected port 53, got %d", ports[0])
	}

	// Empty case — no UDP floors
	empty := &Tower{Floors: []Floor{{ProtocolID: FloorProtoTCP, RHSData: []byte{0, 80}}}}
	emptyPorts, err := empty.GetUDPPorts()
	if err != nil {
		t.Fatalf("GetUDPPorts (empty) failed: %v", err)
	}
	if len(emptyPorts) != 0 {
		t.Errorf("expected 0 ports for tower with no UDP floors, got %d", len(emptyPorts))
	}
}

func TestGetIPAddresses(t *testing.T) {
	tower := &Tower{
		Floors: []Floor{
			{ProtocolID: FloorProtoIP, RHSData: []byte{10, 0, 0, 1}},
			{ProtocolID: FloorProtoIP, RHSData: []byte{192, 168, 1, 100}},
		},
	}

	addrs, err := tower.GetIPAddresses()
	if err != nil {
		t.Fatalf("GetIPAddresses failed: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 IP addresses, got %d", len(addrs))
	}
	if addrs[0] != "10.0.0.1" {
		t.Errorf("expected first address 10.0.0.1, got %s", addrs[0])
	}
	if addrs[1] != "192.168.1.100" {
		t.Errorf("expected second address 192.168.1.100, got %s", addrs[1])
	}
}

func TestGetUUIDs(t *testing.T) {
	srvUUID := "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	tower, err := NewRequestTower(srvUUID, 3, 0)
	if err != nil {
		t.Fatalf("NewRequestTower failed: %v", err)
	}

	uuids, err := tower.GetUUIDs()
	if err != nil {
		t.Fatalf("GetUUIDs failed: %v", err)
	}
	// Request tower has 2 UUID floors: interface UUID (floor 0) and NDR transfer syntax (floor 1)
	if len(uuids) != 2 {
		t.Fatalf("expected 2 UUID floors, got %d", len(uuids))
	}

	// Floor 0: interface UUID
	if uuids[0].UUID != srvUUID {
		t.Errorf("expected interface UUID %s, got %s", srvUUID, uuids[0].UUID)
	}
	if uuids[0].MajorVersion != 3 {
		t.Errorf("expected major version 3, got %d", uuids[0].MajorVersion)
	}
	if uuids[0].MinorVersion != 0 {
		t.Errorf("expected minor version 0, got %d", uuids[0].MinorVersion)
	}

	// Floor 1: NDR transfer syntax
	ndrUUID := "8A885D04-1CEB-11C9-9FE8-08002B104860"
	if uuids[1].UUID != ndrUUID {
		t.Errorf("expected NDR UUID %s, got %s", ndrUUID, uuids[1].UUID)
	}
	if uuids[1].MajorVersion != 2 {
		t.Errorf("expected NDR major version 2, got %d", uuids[1].MajorVersion)
	}
}
