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
	"encoding/hex"

	"github.com/jfjallid/go-smb/smb/encoder"

	"testing"
)

func TestBindReq(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	pkt, err := hex.DecodeString("05000b0310000000480000004204cb9ab810b81000000000010000000000010081bb7a364498f135ad3298f03800100302000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}

	req, err := NewBindReq(2596996162, "367abb81-9844-35f1-ad32-98f038001003", 2, 0, "8a885d04-1ceb-11c9-9fe8-08002b104860")
	if err != nil {
		t.Fatal(err)
	}

	buf, err := encoder.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, buf) {
		t.Fatal("Fail")
	}
}

func TestBindRes(t *testing.T) {
	// Simple test to verify that the packet structure is valid
	resPkt, err := hex.DecodeString("05000c0310000000440000004204cb9ab810b810d75400000d005c706970655c6e747376637300000100000000000000045d888aeb1cc9119fe808002b10486002000000")
	if err != nil {
		t.Fatal(err)
	}
	var res BindRes = NewBindRes()
	err = encoder.Unmarshal(resPkt, &res)
	if err != nil {
		t.Fatal(err)
	}

	if res.MajorVersion != 5 {
		t.Fatal("Fail")
	}

	if res.Flags != 3 {
		t.Fatal("Fail")
	}

	if res.Representation != 16 {
		t.Fatal("Fail")
	}

	if res.FragLength != 68 {
		t.Fatal("Fail")
	}

	if res.CallId != 2596996162 {
		t.Fatal("Fail")
	}

	if res.MaxRecvFragSize != 4280 {
		t.Fatal("Fail")
	}

	if res.MaxSendFragSize != 4280 {
		t.Fatal("Fail")
	}

	if res.Association != 0x000054d7 {
		t.Fatal("Fail")
	}

	if res.SecAddrLen != 13 {
		t.Fatal("Fail")
	}

	if !bytes.Equal(res.SecAddr, []byte("\\pipe\\ntsvcs\x00")) {
		t.Fatal("Fail")
	}

	if res.CtxCount != 1 {
		t.Fatal("Fail")
	}
	var items ContextResItems = *res.Context

	if items[0].Result != 0 {
		t.Fatal("Fail")
	}

	ndr, err := hex.DecodeString("045d888aeb1cc9119fe808002b104860")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(items[0].TransferUUID, ndr) {
		t.Fatal("Fail")
	}

	if items[0].TransferVersion != 2 {
		t.Fatal("Fail")
	}
}
