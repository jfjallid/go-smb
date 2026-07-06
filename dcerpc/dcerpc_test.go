// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
package dcerpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"

	"testing"
)

func TestBindReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("05000b0310000000480000004204cb9ab810b81000000000010000000000010081bb7a364498f135ad3298f03800100302000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}

	req, err := newBindReq(2596996162, "367abb81-9844-35f1-ad32-98f038001003", 2, 0, "8a885d04-1ceb-11c9-9fe8-08002b104860", 4280, 4280)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Update FragLength to actual PDU size (newHeader sets it to 0)
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))

	if !bytes.Equal(pkt, buf) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", buf, pkt)
	}
}

func TestBindRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("05000c0310000000440000004204cb9ab810b810d75400000d005c706970655c6e747376637300000100000000000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}
	var res BindRes
	err = res.UnmarshalBinary(resPkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.MajorVersion != 5 {
		t.Fatalf("expected res.MajorVersion==5, got %v", res.MajorVersion)
	}

	if res.Flags != 3 {
		t.Fatalf("expected res.Flags==3, got %v", res.Flags)
	}

	if res.Representation != 16 {
		t.Fatalf("expected res.Representation==16, got %v", res.Representation)
	}

	if res.FragLength != 68 {
		t.Fatalf("expected res.FragLength==68, got %v", res.FragLength)
	}

	if res.CallId != 2596996162 {
		t.Fatalf("expected res.CallId==2596996162, got %v", res.CallId)
	}

	if res.MaxRecvFragSize != 4280 {
		t.Fatalf("expected res.MaxRecvFragSize==4280, got %v", res.MaxRecvFragSize)
	}

	if res.MaxSendFragSize != 4280 {
		t.Fatalf("expected res.MaxSendFragSize==4280, got %v", res.MaxSendFragSize)
	}

	if res.Association != 0x000054d7 {
		t.Fatalf("expected res.Association==0x000054d7, got %v", res.Association)
	}

	if res.SecAddrLen != 13 {
		t.Fatalf("expected res.SecAddrLen==13, got %v", res.SecAddrLen)
	}

	if !bytes.Equal(res.SecAddr, []byte("\\pipe\\ntsvcs\x00")) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", res.SecAddr, []byte("\\pipe\\ntsvcs\x00"))
	}

	if res.ResultList.Results != 1 {
		t.Fatalf("expected res.ResultList.Results==1, got %v", res.ResultList.Results)
	}

	if res.ResultList.Items[0].Result != acceptance {
		t.Fatalf("expected res.ResultList.Items[0].Result==acceptance, got %v", res.ResultList.Items[0].Result)
	}

	if res.ResultList.Items[0].Reason != reasonNotSpecified {
		t.Fatalf("expected res.ResultList.Items[0].Reason==reasonNotSpecified, got %v", res.ResultList.Items[0].Reason)
	}

	ndr, err := hex.DecodeString("045d888aeb1cc9119fe808002b104860")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(res.ResultList.Items[0].TransferSyntax.UUID, ndr) {
		t.Fatalf("bytes mismatch\n got:  %x\n want: %x", res.ResultList.Items[0].TransferSyntax.UUID, ndr)
	}

	if res.ResultList.Items[0].TransferSyntax.Version != 2 {
		t.Fatalf("expected res.ResultList.Items[0].TransferSyntax.Version==2, got %v", res.ResultList.Items[0].TransferSyntax.Version)
	}
}

func TestRequestReqWithObjectUUID(t *testing.T) {
	objectUUID := []byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}
	stubData := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	req, err := newRequestReq(1, 5, objectUUID)
	if err != nil {
		t.Fatal(err)
	}
	req.Buffer = stubData
	req.AllocHint = uint32(len(stubData))
	req.FragLength = uint16(RequestHeaderWithObjectUUIDSize + len(stubData))

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Verify total length: 16 (header) + 4 (AllocHint) + 2 (ContextId) + 2 (Opnum) + 16 (UUID) + 4 (stub) = 44
	if len(buf) != 44 {
		t.Fatalf("expected length 44, got %d", len(buf))
	}

	// Verify PfcObjectUUID flag is set (byte 3 = Flags)
	if buf[3]&PfcObjectUUID == 0 {
		t.Fatal("PfcObjectUUID flag not set")
	}

	// Verify Opnum at offset 22-23
	opnum := binary.LittleEndian.Uint16(buf[22:24])
	if opnum != 5 {
		t.Fatalf("expected opnum 5, got %d", opnum)
	}

	// Verify ObjectUUID at offset 24-39
	if !bytes.Equal(buf[24:40], objectUUID) {
		t.Fatalf("ObjectUUID mismatch\n got:  %x\n want: %x", buf[24:40], objectUUID)
	}

	// Verify stub data at offset 40-43
	if !bytes.Equal(buf[40:44], stubData) {
		t.Fatalf("stub data mismatch\n got:  %x\n want: %x", buf[40:44], stubData)
	}

	// Verify FragLength in header
	fragLen := binary.LittleEndian.Uint16(buf[8:10])
	if fragLen != 44 {
		t.Fatalf("expected FragLength 44, got %d", fragLen)
	}
}

func TestRequestReqWithoutObjectUUID(t *testing.T) {
	stubData := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	req, err := newRequestReq(1, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Buffer = stubData
	req.AllocHint = uint32(len(stubData))
	req.FragLength = uint16(RequestHeaderSize + len(stubData))

	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	// Verify total length: 24 (header) + 4 (stub) = 28
	if len(buf) != 28 {
		t.Fatalf("expected length 28, got %d", len(buf))
	}

	// Verify PfcObjectUUID flag is NOT set
	if buf[3]&PfcObjectUUID != 0 {
		t.Fatal("PfcObjectUUID flag should not be set")
	}

	// Verify stub data at offset 24-27
	if !bytes.Equal(buf[24:28], stubData) {
		t.Fatalf("stub data mismatch\n got:  %x\n want: %x", buf[24:28], stubData)
	}
}

func TestRequestReqInvalidObjectUUID(t *testing.T) {
	// ObjectUUID must be exactly 16 bytes
	_, err := newRequestReq(1, 0, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for invalid ObjectUUID length")
	}
}

// makeCommonHeader builds a 16-byte DCERPC common header with the given PDU
// type, FragLength and CallId. Field offsets per MS-RPCE: Type@2, FragLength@8,
// CallId@12.
func makeCommonHeader(pduType uint8, fragLength uint16, callId uint32) []byte {
	h := make([]byte, 16)
	h[0] = 5 // MajorVersion
	h[1] = 0 // MinorVersion
	h[2] = pduType
	h[3] = 0x03 // Flags (first+last frag)
	binary.LittleEndian.PutUint16(h[8:10], fragLength)
	binary.LittleEndian.PutUint32(h[12:16], callId)
	return h
}

// TestParseCommonHeaderShortResponse is the regression guard for finding D3: a
// malicious server returning a PDU shorter than the 16-byte common header (or a
// 16-byte BindNak, so response[16:18] is out of range) must return an error,
// not panic the caller's goroutine.
func TestParseCommonHeaderShortResponse(t *testing.T) {
	const callId = 0x11223344

	t.Run("shorter than common header", func(t *testing.T) {
		for n := 0; n < 16; n++ {
			if err := parseAndValidateCommonHeader(make([]byte, n), callId); err == nil {
				t.Fatalf("len=%d: expected error, got nil", n)
			}
		}
	})

	t.Run("16-byte BindNak (no reason bytes)", func(t *testing.T) {
		// A BindNak whose buffer ends exactly at the common header: the reason
		// code at response[16:18] is absent and must be rejected, not sliced.
		hdr := makeCommonHeader(PacketTypeBindNak, 18, callId)
		if err := parseAndValidateCommonHeader(hdr, callId); err == nil {
			t.Fatal("expected error for truncated BindNak, got nil")
		}
	})

	t.Run("valid BindNak with reason", func(t *testing.T) {
		// 18-byte BindNak with a reason code parses (and returns a BindNakError).
		buf := append(makeCommonHeader(PacketTypeBindNak, 18, callId), 0x00, 0x00)
		err := parseAndValidateCommonHeader(buf, callId)
		if err == nil {
			t.Fatal("expected BindNakError, got nil")
		}
		if _, ok := err.(*BindNakError); !ok {
			t.Fatalf("expected *BindNakError, got %T: %v", err, err)
		}
	})
}

// TestRequestResFragLengthUnderflow is the regression guard for finding D4: a
// Response PDU with FragLength < 24 must be rejected, not pass the buffer check
// (the FragLength-24 subtraction underflows the uint16 to ~65 K) and trigger a
// 64 KiB over-allocation handed back to callers as a mostly-zero Buffer.
func TestRequestResFragLengthUnderflow(t *testing.T) {
	for _, fragLen := range []uint16{0, 1, 16, 23} {
		buf := makeCommonHeader(PacketTypeResponse, fragLen, 1)
		var res RequestRes
		err := res.UnmarshalBinary(buf)
		if err == nil {
			t.Fatalf("FragLength=%d: expected error, got nil (Buffer len=%d)", fragLen, len(res.Buffer))
		}
		if len(res.Buffer) > 0 {
			t.Fatalf("FragLength=%d: over-allocated Buffer of %d bytes", fragLen, len(res.Buffer))
		}
	}
}
