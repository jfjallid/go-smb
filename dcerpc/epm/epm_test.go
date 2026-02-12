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

	// Hoisted max_count for the conformant,varying Towers array
	binary.Write(&buf, le, uint32(1)) // max_count

	// Context handle (20 zero bytes)
	buf.Write(make([]byte, ContextHandleSize))

	// num_towers = 1
	binary.Write(&buf, le, uint32(1))

	// Varying array header (offset + actual_count)
	binary.Write(&buf, le, uint32(0)) // offset
	binary.Write(&buf, le, uint32(1)) // actual_count

	// Referent ID for tower pointer (non-zero)
	binary.Write(&buf, le, uint32(0x00020000))

	// Status
	binary.Write(&buf, le, uint32(0))

	// Deferred tower pointer data: towerNDR conformant byte array
	towerLen := uint32(len(towerOctets))
	binary.Write(&buf, le, towerLen) // conformant max_count for TowerOctetString
	binary.Write(&buf, le, towerLen) // TowerLength field
	buf.Write(towerOctets)

	// Pad to 4-byte alignment
	padLen := (4 - (int(towerLen) % 4)) % 4
	for i := 0; i < padLen; i++ {
		buf.WriteByte(0)
	}

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

	// Hoisted max_count for the conformant,varying Towers array
	binary.Write(&buf, le, uint32(4)) // max_count (from max_towers)

	// Context handle
	buf.Write(make([]byte, ContextHandleSize))

	// num_towers = 0
	binary.Write(&buf, le, uint32(0))

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
