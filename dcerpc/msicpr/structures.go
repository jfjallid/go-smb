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

package msicpr

import (
	"bytes"
	"encoding/binary"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/ndr"
)

var le = binary.LittleEndian

// certRequester is the single call the enrollment path needs from its
// transport. *dcerpc.ServiceBind satisfies it.
type certRequester interface {
	MakeRequest(opcode uint16, innerBuf []byte) ([]byte, error)
}

// RPCCon wraps a bound MS-ICPR (ICertPassage) interface.
type RPCCon struct {
	*dcerpc.ServiceBind

	// requester overrides the embedded ServiceBind as the source of RPC calls.
	// It is nil in normal use — NewRPCCon leaves it unset — and exists so the
	// call path can be exercised without standing up a DCERPC transport.
	requester certRequester
}

// request issues an RPC call over whichever transport this RPCCon is bound to.
func (sb *RPCCon) request(opnum uint16, innerBuf []byte) ([]byte, error) {
	if sb.requester != nil {
		return sb.requester.MakeRequest(opnum, innerBuf)
	}
	return sb.ServiceBind.MakeRequest(opnum, innerBuf)
}

// CERTTRANSBLOB (MS-WCCE 2.2.2.2 / MS-ICPR): a length-prefixed byte buffer
// carried by a unique pointer.
//
//	typedef struct _CERTTRANSBLOB {
//	    ULONG cb;
//	    [size_is(cb), unique] BYTE *pb;
//	} CERTTRANSBLOB;
//
// Pb is an *embedded* [unique] pointer, so its referent is deferred to the end
// of the enclosing parameter's deferral scope — which is what the `toplevel`
// tag on each parameter below establishes.
type CERTTRANSBLOB struct {
	Cb uint32
	Pb []byte `ndr:"pointer,fullpointer,conformant,maxcount:Cb"`
}

func newBlob(b []byte) CERTTRANSBLOB {
	return CERTTRANSBLOB{Cb: uint32(len(b)), Pb: b}
}

// CertServerRequestReq is the [in] parameter block for CertServerRequest
// (opnum 0). MS-ICPR 3.2.1.4.3.1.1:
//
//	DWORD CertServerRequest(
//	    [in] handle_t h,
//	    [in] DWORD dwFlags,
//	    [in, string, unique] wchar_t const *pwszAuthority,
//	    [in, out, ref] DWORD *pdwRequestId,
//	    [out] DWORD *pdwDisposition,
//	    [in, ref] CERTTRANSBLOB const *pctbAttribs,
//	    [in, ref] CERTTRANSBLOB const *pctbRequest,
//	    [out, ref] CERTTRANSBLOB *pctbCertChain,
//	    [out, ref] CERTTRANSBLOB *pctbEncodedCert,
//	    [out, ref] CERTTRANSBLOB *pctbDispositionMessage);
//
// Every pointer parameter carries `toplevel`, which gives it its own NDR
// deferral scope: the parameter's fixed part is followed immediately by its own
// referents before the next parameter starts. That is the per-parameter model
// Windows' NDR engine (MIDL) uses. Without `toplevel` the embedded referents of
// all parameters are deferred to the end of the whole stub — a layout Windows
// rejects with DCERPC fault 0x000006f7 (nca_s_fault_ndr).
//
// PwszAuthority is [unique] but a CA name is mandatory here, so it is modelled
// as a plain string (never NULL); a nil *string would be needed to send NULL.
type CertServerRequestReq struct {
	DwFlags       uint32
	PwszAuthority string        `ndr:"toplevel,fullpointer,conformant,varying"`
	PdwRequestId  uint32        `ndr:"toplevel"`
	PctbAttribs   CERTTRANSBLOB `ndr:"toplevel"`
	PctbRequest   CERTTRANSBLOB `ndr:"toplevel"`
}

// CertServerRequestRes is the [out] parameter block. The same per-parameter
// deferral applies on the way back: the server writes each [out] parameter's
// referents inline before the next parameter.
type CertServerRequestRes struct {
	PdwRequestId           uint32        `ndr:"toplevel"`
	PdwDisposition         uint32        `ndr:"toplevel"`
	PctbCertChain          CERTTRANSBLOB `ndr:"toplevel"`
	PctbEncodedCert        CERTTRANSBLOB `ndr:"toplevel"`
	PctbDispositionMessage CERTTRANSBLOB `ndr:"toplevel"`
	ReturnValue            uint32
}

// Marshal encodes the request stub with the shared NDR encoder.
func (s *CertServerRequestReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	return enc.Encode(s)
}

// Unmarshal decodes the response stub with the shared NDR decoder.
func (s *CertServerRequestRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	return dec.Decode(s)
}
