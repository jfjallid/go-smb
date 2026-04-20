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
	"strings"
	"testing"
)

func TestParseDCOMAddress(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort string
	}{
		{"10.0.0.1[49152]", "10.0.0.1", "49152"},
		{"192.168.1.100[135]", "192.168.1.100", "135"},
		{"10.0.0.1", "10.0.0.1", ""},
		{"hostname[8080]", "hostname", "8080"},
		{"", "", ""},
		{"[49152]", "", "49152"},
	}

	for _, tc := range tests {
		host, port := parseDCOMAddress(tc.input)
		if host != tc.wantHost || port != tc.wantPort {
			t.Errorf("parseDCOMAddress(%q) = (%q, %q), want (%q, %q)",
				tc.input, host, port, tc.wantHost, tc.wantPort)
		}
	}
}

func TestResolveDynamicAddress(t *testing.T) {
	d := &DCOMConnection{
		host: "10.0.0.5",
	}

	// Build an ActivationResult with a TCP string binding "10.0.0.1[49152]"
	addrChars := []uint16{'1', '0', '.', '0', '.', '0', '.', '1', '[', '4', '9', '1', '5', '2', ']'}
	strBindings := []uint16{7} // TowerId = TCP
	strBindings = append(strBindings, addrChars...)
	strBindings = append(strBindings, 0) // null-terminate
	strBindings = append(strBindings, 0) // end of string bindings

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d: %v", len(addrs), addrs)
	}

	// d.host should be preferred first even though it wasn't in the bindings
	if addrs[0] != "10.0.0.5:49152" {
		t.Fatalf("expected '10.0.0.5:49152' as preferred, got '%s'", addrs[0])
	}
	// Original binding host as fallback
	if addrs[1] != "10.0.0.1:49152" {
		t.Fatalf("expected '10.0.0.1:49152' as fallback, got '%s'", addrs[1])
	}
}

func TestResolveDynamicAddressHostMatch(t *testing.T) {
	d := &DCOMConnection{
		host: "10.0.0.1",
	}

	// Build an ActivationResult with a TCP string binding "10.0.0.1[49152]"
	addrChars := []uint16{'1', '0', '.', '0', '.', '0', '.', '1', '[', '4', '9', '1', '5', '2', ']'}
	strBindings := []uint16{7} // TowerId = TCP
	strBindings = append(strBindings, addrChars...)
	strBindings = append(strBindings, 0) // null-terminate
	strBindings = append(strBindings, 0) // end of string bindings

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d: %v", len(addrs), addrs)
	}

	// Direct match: d.host is in bindings, so only one entry
	if addrs[0] != "10.0.0.1:49152" {
		t.Fatalf("expected '10.0.0.1:49152', got '%s'", addrs[0])
	}
}

func TestResolveDynamicAddressMultipleBindings(t *testing.T) {
	d := &DCOMConnection{
		host: "192.168.1.10",
	}

	// Build bindings: "10.0.0.1[49152]" and "192.168.1.10[49152]"
	strBindings := []uint16{7} // TowerId = TCP
	for _, c := range "10.0.0.1[49152]" {
		strBindings = append(strBindings, uint16(c))
	}
	strBindings = append(strBindings, 0) // null-terminate

	strBindings = append(strBindings, 7) // TowerId = TCP
	for _, c := range "192.168.1.10[49152]" {
		strBindings = append(strBindings, uint16(c))
	}
	strBindings = append(strBindings, 0) // null-terminate
	strBindings = append(strBindings, 0) // end of string bindings

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d: %v", len(addrs), addrs)
	}

	// d.host match should come first
	if addrs[0] != "192.168.1.10:49152" {
		t.Fatalf("expected '192.168.1.10:49152' as preferred, got '%s'", addrs[0])
	}
	// Other binding as fallback
	if addrs[1] != "10.0.0.1:49152" {
		t.Fatalf("expected '10.0.0.1:49152' as fallback, got '%s'", addrs[1])
	}
}

func TestResolveDynamicAddressWildcard(t *testing.T) {
	d := &DCOMConnection{
		host: "10.0.0.5",
	}

	// Build with wildcard address "0.0.0.0[49152]"
	addrChars := []uint16{'0', '.', '0', '.', '0', '.', '0', '[', '4', '9', '1', '5', '2', ']'}
	strBindings := []uint16{7}
	strBindings = append(strBindings, addrChars...)
	strBindings = append(strBindings, 0, 0)

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) == 0 {
		t.Fatal("expected at least one address")
	}

	// Should substitute the original host
	if addrs[0] != "10.0.0.5:49152" {
		t.Fatalf("expected '10.0.0.5:49152', got '%s'", addrs[0])
	}
}

func TestResolveDynamicAddressNoTCPBinding(t *testing.T) {
	d := &DCOMConnection{host: "10.0.0.5"}

	// Only a named pipe binding (TowerId 15), no TCP
	strBindings := []uint16{15, 'p', 'i', 'p', 'e', 0, 0}
	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) != 0 {
		t.Fatalf("expected no addresses, got %v", addrs)
	}
}

func TestValidateDynamicPortMatch(t *testing.T) {
	d := &DCOMConnection{
		host:    "10.0.0.5",
		dynAddr: "10.0.0.5:49152",
	}

	// Build bindings with TCP binding "10.0.0.5[49152]"
	strBindings := []uint16{7} // TowerId = TCP
	for _, c := range "10.0.0.5[49152]" {
		strBindings = append(strBindings, uint16(c))
	}
	strBindings = append(strBindings, 0, 0) // null-terminate + end

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	if err := d.validateDynamicPort(activation); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateDynamicPortMismatch(t *testing.T) {
	d := &DCOMConnection{
		host:    "10.0.0.5",
		dynAddr: "10.0.0.5:49152",
	}

	// Build bindings with a different port "10.0.0.5[49153]"
	strBindings := []uint16{7} // TowerId = TCP
	for _, c := range "10.0.0.5[49153]" {
		strBindings = append(strBindings, uint16(c))
	}
	strBindings = append(strBindings, 0, 0)

	secBindings := []uint16{0}
	secOffset := uint16(len(strBindings))
	allEntries := append(strBindings, secBindings...)

	activation := &ActivationResult{
		OxidBindings: DUALSTRINGARRAY{
			NumEntries:     uint16(len(allEntries)),
			SecurityOffset: secOffset,
			StringArray:    allEntries,
		},
	}

	err := d.validateDynamicPort(activation)
	if err == nil {
		t.Fatal("expected error for port mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "multiple dynamic transports") {
		t.Fatalf("expected error containing 'multiple dynamic transports', got: %v", err)
	}
}

func TestCOMObjectIPIDAndIID(t *testing.T) {
	ipid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	iid := IID_IUnknown

	obj := &COMObject{
		ipid: ipid,
		iid:  iid,
		refs: 5,
	}

	if obj.IPID() != ipid {
		t.Fatal("IPID mismatch")
	}
	if obj.IID() != iid {
		t.Fatal("IID mismatch")
	}
}
