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
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc/msdcom"
	"github.com/jfjallid/ndr"
)

// ICertRequestDRequestOp is the opnum of ICertRequestD::Request over DCOM. The
// three IUnknown methods (QueryInterface/AddRef/Release) occupy opnums 0-2, so
// the first interface method, Request, is opnum 3 (MS-WCCE 3.1.1.4.3).
const ICertRequestDRequestOp uint16 = 3

// COM class / interface identifiers for the DCOM enrollment path (MS-WCCE):
//
//	CLSIDICertRequest — the CertRequest COM class (ICertRequest).
//	IIDICertRequestD  — the ICertRequestD interface exposing CertServerRequest.
var (
	CLSIDICertRequest = mustGUID("d99e6e74-fc88-11d0-b498-00a0c90312f3")
	IIDICertRequestD  = mustGUID("d99e6e70-fc88-11d0-b498-00a0c90312f3")
)

func mustGUID(s string) [16]byte {
	g, err := msdcom.GUIDFromString(s)
	if err != nil {
		panic("msicpr: invalid GUID " + s + ": " + err.Error())
	}
	return g
}

// CertServerRequestDReq is the [in] parameter block for ICertRequestD::Request
// (opnum 3) — the DCOM counterpart of the ICPR CertServerRequest. It differs in
// exactly one place from the ICPR call: the request attributes travel as a
// [unique] wide string (pwszAttributes) rather than a CERTTRANSBLOB. As in the
// ICPR request, every pointer parameter carries `toplevel` so the NDR encoder
// uses the per-parameter deferral layout Windows expects (see structures.go).
//
//	HRESULT Request(
//	    [in]  DWORD             dwFlags,
//	    [in, string, unique]  wchar_t const *pwszAuthority,
//	    [in, out] DWORD        *pdwRequestId,
//	    [in, string, unique]  wchar_t const *pwszAttributes,
//	    [in, ref] CERTTRANSBLOB const *pctbRequest,
//	    [out] DWORD            *pdwDisposition,
//	    [out, ref] CERTTRANSBLOB *pctbCertChain,
//	    [out, ref] CERTTRANSBLOB *pctbEncodedCert,
//	    [out, ref] CERTTRANSBLOB *pctbDispositionMessage);
//
// PwszAttributes is [unique] and legitimately NULL: on the retrieve-pending
// path the caller has no attributes to send. It is therefore a *string, not a
// string, so that "" (which would marshal as a pointer to an empty wide string
// L"") can be distinguished from absent (a NULL pointer). The CA rejects the
// former on the retrieve path with 0x80070057 (ERROR_INVALID_PARAMETER); this
// is the one place the DCOM stub must match the ICPR CERTTRANSBLOB (which sends
// a NULL pb for empty attributes). A nil *string encodes as a NULL referent;
// a non-nil one as the pointer + the conformant/varying wide-string referent.
type CertServerRequestDReq struct {
	DwFlags        uint32
	PwszAuthority  string        `ndr:"toplevel,fullpointer,conformant,varying"`
	PdwRequestId   uint32        `ndr:"toplevel"`
	PwszAttributes *string       `ndr:"toplevel,fullpointer,conformant,varying"`
	PctbRequest    CERTTRANSBLOB `ndr:"toplevel"`
}

// Marshal encodes the DCOM request stub with the shared NDR encoder. The
// response has the same shape as the ICPR call, so CertServerRequestRes decodes
// it (the trailing ReturnValue is the method HRESULT).
func (s *CertServerRequestDReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	return enc.Encode(s)
}

// comCaller is the slice of an activated COM object this package actually uses.
// *msdcom.COMObject satisfies it; keeping the internal dependency this narrow
// lets the call paths be exercised without a live CA. The exported constructors
// still take a *msdcom.COMObject, so this is an implementation detail.
type comCaller interface {
	CallMethod(opnum uint16, stubData []byte) ([]byte, error)
	Release() error
}

// ICertRequestD wraps an activated ICertRequestD COM object and exposes the same
// CertServerRequest call as the SMB/RPC RPCCon so the two transports are
// interchangeable behind a common interface.
type ICertRequestD struct {
	obj comCaller
}

// NewICertRequestD wraps a COM object previously activated for IIDICertRequestD,
// e.g. via msdcom.DCOMConnection.CreateInstance(CLSIDICertRequest,
// IIDICertRequestD). A nil obj yields a client whose calls fail with a clear
// error rather than panicking: assigning a nil *COMObject straight to the
// interface field would leave it non-nil but unusable.
func NewICertRequestD(obj *msdcom.COMObject) *ICertRequestD {
	if obj == nil {
		return &ICertRequestD{}
	}
	return &ICertRequestD{obj: obj}
}

// CertServerRequest submits a certificate request over DCOM. The signature is
// identical to RPCCon.CertServerRequest: authority is the CA common name,
// request is the DER PKCS#10 (or CMC for on-behalf-of), attributes is the
// request-attribute string (e.g. "CertificateTemplate:User"), and requestID is
// 0 for a new request or a prior ID to retrieve a pending certificate.
//
// As on the ICPR path, a refused request yields both a *CertResponse and an
// error so the CA's disposition message is not lost.
func (c *ICertRequestD) CertServerRequest(authority string, request []byte, attributes string, requestID uint32) (*CertResponse, error) {
	log.Traceln("In ICertRequestD.CertServerRequest")

	if c.obj == nil {
		return nil, fmt.Errorf("msicpr: ICertRequestD has no activated COM object")
	}

	// An empty attribute string must become a NULL pointer, not a pointer to
	// L"" — the CA rejects the latter on the retrieve path (see the struct doc).
	var attrs *string
	if attributes != "" {
		attrs = &attributes
	}
	req := CertServerRequestDReq{
		DwFlags:        0,
		PwszAuthority:  authority,
		PdwRequestId:   requestID,
		PwszAttributes: attrs,
		PctbRequest:    newBlob(request),
	}
	inBuf, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	outBuf, err := c.obj.CallMethod(ICertRequestDRequestOp, inBuf)
	if err != nil {
		return nil, err
	}

	return parseCertResponse(outBuf, "ICertRequestD::Request")
}
