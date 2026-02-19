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
