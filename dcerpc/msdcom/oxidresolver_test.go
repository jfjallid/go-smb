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
package msdcom

import (
	"bytes"
	"testing"
)

func TestMarshalResolveOxid2Request(t *testing.T) {
	oxid := uint64(0x1234567890abcdef)
	protseqs := []uint16{7} // ncacn_ip_tcp

	buf := marshalResolveOxid2Request(oxid, protseqs)

	// Expected layout:
	// [0:8]   oxid (LE)
	// [8:10]  cRequestedProtseqs = 1
	// [10:12] padding
	// [12:16] max_count = 1
	// [16:18] protseq[0] = 7
	if len(buf) != 18 {
		t.Fatalf("expected 18 bytes, got %d", len(buf))
	}

	// Check OXID
	gotOxid := le.Uint64(buf[0:8])
	if gotOxid != oxid {
		t.Fatalf("OXID mismatch: 0x%x vs 0x%x", gotOxid, oxid)
	}

	// Check count
	gotCount := le.Uint16(buf[8:10])
	if gotCount != 1 {
		t.Fatalf("expected count 1, got %d", gotCount)
	}

	// Check max_count
	gotMaxCount := le.Uint32(buf[12:16])
	if gotMaxCount != 1 {
		t.Fatalf("expected max_count 1, got %d", gotMaxCount)
	}

	// Check protseq
	gotProtseq := le.Uint16(buf[16:18])
	if gotProtseq != 7 {
		t.Fatalf("expected protseq 7, got %d", gotProtseq)
	}
}

func TestMarshalResolveOxid2RequestMultipleProtseqs(t *testing.T) {
	oxid := uint64(0xdeadbeef)
	protseqs := []uint16{7, 15} // TCP, named pipe

	buf := marshalResolveOxid2Request(oxid, protseqs)

	// [0:8]   oxid
	// [8:10]  count = 2
	// [10:12] padding
	// [12:16] max_count = 2
	// [16:18] protseq[0] = 7
	// [18:20] protseq[1] = 15
	if len(buf) != 20 {
		t.Fatalf("expected 20 bytes, got %d", len(buf))
	}

	gotCount := le.Uint16(buf[8:10])
	if gotCount != 2 {
		t.Fatalf("expected count 2, got %d", gotCount)
	}

	gotMaxCount := le.Uint32(buf[12:16])
	if gotMaxCount != 2 {
		t.Fatalf("expected max_count 2, got %d", gotMaxCount)
	}

	if le.Uint16(buf[16:18]) != 7 {
		t.Fatalf("expected protseq[0] = 7")
	}
	if le.Uint16(buf[18:20]) != 15 {
		t.Fatalf("expected protseq[1] = 15")
	}
}

func TestUnmarshalResolveOxid2Response(t *testing.T) {
	// Build a synthetic ResolveOxid2 response:
	// [0:4]   referent ID for bindings pointer (non-zero)
	// [4:20]  ipidRemUnknown
	// [20:24] authnHint
	// [24:28] COMVERSION {5, 7}
	// [28:32] status = 0
	// [32:..] DUALSTRINGARRAY

	ipid := [16]byte{
		0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
	}

	// Build a minimal DUALSTRINGARRAY: {0, 0} (empty)
	dsa := DUALSTRINGARRAY{
		NumEntries:     2,
		SecurityOffset: 1,
		StringArray:    []uint16{0, 0},
	}
	dsaBytes := dsa.MarshalBinary()

	buf := make([]byte, 32+len(dsaBytes))
	offset := 0

	// Referent ID (non-zero)
	le.PutUint32(buf[offset:], 0x00020000)
	offset += 4

	// IPID
	copy(buf[offset:], ipid[:])
	offset += 16

	// AuthnHint
	le.PutUint32(buf[offset:], 10)
	offset += 4

	// COMVERSION
	le.PutUint16(buf[offset:], 5)
	le.PutUint16(buf[offset+2:], 7)
	offset += 4

	// Status = 0 (success)
	le.PutUint32(buf[offset:], 0)
	offset += 4

	// DUALSTRINGARRAY
	copy(buf[offset:], dsaBytes)

	result, err := unmarshalResolveOxid2Response(buf)
	if err != nil {
		t.Fatal(err)
	}

	if result.IpidRemUnknown != ipid {
		t.Fatalf("IPID mismatch\n got:  %x\n want: %x", result.IpidRemUnknown, ipid)
	}
	if result.AuthnHint != 10 {
		t.Fatalf("AuthnHint mismatch: %d vs 10", result.AuthnHint)
	}
	if result.ComVersion.MajorVersion != 5 || result.ComVersion.MinorVersion != 7 {
		t.Fatalf("ComVersion mismatch: %d.%d", result.ComVersion.MajorVersion, result.ComVersion.MinorVersion)
	}
	if result.Bindings.NumEntries != 2 {
		t.Fatalf("Bindings.NumEntries mismatch: %d vs 2", result.Bindings.NumEntries)
	}
}

func TestUnmarshalResolveOxid2ResponseError(t *testing.T) {
	// Build a response with non-zero status
	buf := make([]byte, 32)
	offset := 0

	// Referent ID
	le.PutUint32(buf[offset:], 0)
	offset += 4

	// IPID (zeros)
	offset += 16

	// AuthnHint
	le.PutUint32(buf[offset:], 0)
	offset += 4

	// COMVERSION
	le.PutUint16(buf[offset:], 5)
	le.PutUint16(buf[offset+2:], 7)
	offset += 4

	// Status = error
	le.PutUint32(buf[offset:], 0x80070005)

	_, err := unmarshalResolveOxid2Response(buf)
	if err == nil {
		t.Fatal("expected error for non-zero status")
	}
}

func TestUnmarshalResolveOxid2ResponseWithTCPBindings(t *testing.T) {
	// Build a response with TCP string binding "10.0.0.1[49152]"
	ipid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	// String bindings: TowerId=7, "10.0.0.1[49152]", null, null-term
	addrChars := []uint16{'1', '0', '.', '0', '.', '0', '.', '1'}
	strBindings := []uint16{7}
	strBindings = append(strBindings, addrChars...)
	strBindings = append(strBindings, 0) // null-terminate address
	strBindings = append(strBindings, 0) // end of string bindings section

	// Security bindings: empty
	secBindings := []uint16{0}

	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	dsa := DUALSTRINGARRAY{
		NumEntries:     uint16(len(allEntries)),
		SecurityOffset: secOffset,
		StringArray:    allEntries,
	}
	dsaBytes := dsa.MarshalBinary()

	buf := make([]byte, 32+len(dsaBytes))
	offset := 0

	le.PutUint32(buf[offset:], 0x00020000) // referent ID
	offset += 4
	copy(buf[offset:], ipid[:])
	offset += 16
	le.PutUint32(buf[offset:], 10) // authnHint
	offset += 4
	le.PutUint16(buf[offset:], 5)   // major
	le.PutUint16(buf[offset+2:], 7) // minor
	offset += 4
	le.PutUint32(buf[offset:], 0) // status
	offset += 4
	copy(buf[offset:], dsaBytes)

	result, err := unmarshalResolveOxid2Response(buf)
	if err != nil {
		t.Fatal(err)
	}

	bindings := result.Bindings.ParseStringBindings()
	if len(bindings) != 1 {
		t.Fatalf("expected 1 string binding, got %d", len(bindings))
	}
	if bindings[0].TowerId != TowerIDTCP {
		t.Fatalf("expected TowerId %d, got %d", TowerIDTCP, bindings[0].TowerId)
	}
	if bindings[0].Address != "10.0.0.1" {
		t.Fatalf("expected address '10.0.0.1', got '%s'", bindings[0].Address)
	}

	if !bytes.Equal(result.IpidRemUnknown[:], ipid[:]) {
		t.Fatalf("IPID mismatch")
	}
}
