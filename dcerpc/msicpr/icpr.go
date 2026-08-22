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

// Package msicpr implements the client side of the three protocols an Active
// Directory Certificate Services CA exposes for enrollment and administration.
// The package is named for the first of them, the one that needs no DCOM:
//
//   - MS-ICPR (ICertPassage Remote Protocol) — certificate enrollment over the
//     \pipe\cert named pipe or a dynamic TCP endpoint. CertServerRequest
//     (opnum 0) is the only method, and it both submits a PKCS#10 (or CMC)
//     request and retrieves an issued or pending certificate. See icpr.go and
//     structures.go.
//   - MS-WCCE (ICertRequestD) — the same enrollment call over DCOM/ORPC
//     (opnum 3), for hosts where the named pipe is filtered but DCOM is
//     reachable. It differs from the ICPR call in one field: the request
//     attributes travel as a wide string rather than a CERTTRANSBLOB. Both
//     paths return a CertResponse, so the transports are interchangeable
//     behind a common interface. See dcom.go.
//   - MS-CSRA (ICertAdminD / ICertAdminD2) — CA administration over DCOM:
//     approve or deny a pending request, read and write the CA's
//     enabled-template list, and read and write the CA security descriptor
//     that carries the ManageCA / ManageCertificates roles. See certadmin.go.
//
// The DCOM paths take an already-activated object (or an activation function)
// from dcerpc/msdcom rather than dialing anything themselves, so the caller
// keeps control of authentication and object lifetime.
//
// All three share one NDR convention: every pointer parameter is tagged
// `toplevel` so its referents are emitted inside its own deferral scope, which
// is the per-parameter layout Windows' MIDL-generated server stubs expect.
// structures.go documents why, and each stub has a byte-exact layout test.
package msicpr

import (
	"fmt"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/msicpr").SetDisplayName("msicpr")

const (
	// MSRPCCertPassagePipe is the named pipe the ICertPassage interface listens on.
	MSRPCCertPassagePipe = "cert"
	// MSRPCUuidICertPassage is the ICertPassage interface UUID (MS-ICPR 1.9).
	MSRPCUuidICertPassage                = "91AE6020-9E3C-11CF-8D7C-00AA00C091BE"
	MSRPCICertPassageMajorVersion uint16 = 0
	MSRPCICertPassageMinorVersion uint16 = 0
)

// CertServerRequest opnum.
const CertServerRequestOp uint16 = 0

// Certificate request disposition codes (MS-WCCE 3.2.1.4.2.1.4, CR_DISP_*).
const (
	DispIncomplete      uint32 = 0
	DispError           uint32 = 1
	DispDenied          uint32 = 2
	DispIssued          uint32 = 3
	DispIssuedOutOfBand uint32 = 4
	DispUnderSubmission uint32 = 5
	DispRevoked         uint32 = 6
)

var dispositionNames = map[uint32]string{
	DispIncomplete:      "incomplete",
	DispError:           "error",
	DispDenied:          "denied",
	DispIssued:          "issued",
	DispIssuedOutOfBand: "issued out of band",
	DispUnderSubmission: "under submission (pending)",
	DispRevoked:         "revoked",
}

// DispositionName returns a human readable name for a CR_DISP_* code.
func DispositionName(code uint32) string {
	if s, ok := dispositionNames[code]; ok {
		return s
	}
	return fmt.Sprintf("unknown disposition 0x%x", code)
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

// CertResponse holds the decoded result of a CertServerRequest call.
type CertResponse struct {
	RequestID          uint32
	Disposition        uint32
	DispositionMessage string // decoded from the CA's UTF-16LE status blob
	EncodedCert        []byte // DER-encoded issued leaf certificate (empty unless issued)
	CertChain          []byte // PKCS#7/CMS chain blob (may be empty)
}

// Issued reports whether the CA issued the certificate.
func (r *CertResponse) Issued() bool { return r.Disposition == DispIssued }

// parseCertResponse decodes a CertServerRequest response stub. The ICPR and
// DCOM enrollment calls return the same five [out] parameters followed by a
// status word — a DWORD for ICPR, an HRESULT for DCOM — so both share this
// path; op names the call in the error.
//
// A non-zero status yields a *dcerpc.StatusError, but the decoded CertResponse
// is returned alongside it rather than discarded: the CA puts its reason for
// refusing in the disposition message, which is usually the only thing that
// says *why* ("Denied by Policy Module 0x80094800, The request was for a
// certificate template that is not supported by the Certificate Services
// policy"). That message is also appended to the error text, so a caller that
// only prints the error still sees it.
func parseCertResponse(outBuf []byte, op string) (*CertResponse, error) {
	res := CertServerRequestRes{}
	if err := res.Unmarshal(outBuf); err != nil {
		return nil, err
	}

	resp := &CertResponse{
		RequestID:          res.PdwRequestId,
		Disposition:        res.PdwDisposition,
		DispositionMessage: decodeUTF16(res.PctbDispositionMessage.Pb),
		EncodedCert:        res.PctbEncodedCert.Pb,
		CertChain:          res.PctbCertChain.Pb,
	}

	err := checkReturnCode(op, res.ReturnValue)
	if err != nil {
		if resp.DispositionMessage != "" {
			// Wrapped, so errors.Is/As still reach the StatusError beneath.
			err = fmt.Errorf("%w: %s", err, resp.DispositionMessage)
		}
		return resp, err
	}
	return resp, nil
}

// CertServerRequest submits a certificate request to the named CA. authority is
// the CA common name (the "CA Name", not the host). request is the DER-encoded
// PKCS#10 CSR (or a CMC/PKCS#7 for on-behalf-of enrollment). attributes is the
// request-attribute string (e.g. "CertificateTemplate:User"), lines separated by
// "\n"; it is transmitted as a UTF-16LE, NUL-terminated buffer. requestID is 0
// for a new request, or a prior request ID to retrieve a pending certificate.
//
// When the CA refuses the request, both a *CertResponse and an error are
// returned: the response carries the disposition and the CA's explanation.
func (sb *RPCCon) CertServerRequest(authority string, request []byte, attributes string, requestID uint32) (*CertResponse, error) {
	log.Traceln("In CertServerRequest")

	req := CertServerRequestReq{
		DwFlags:       0,
		PwszAuthority: authority,
		PdwRequestId:  requestID,
		PctbAttribs:   newBlob(encodeUTF16Attribs(attributes)),
		PctbRequest:   newBlob(request),
	}
	inBuf, err := req.Marshal()
	if err != nil {
		return nil, err
	}

	outBuf, err := sb.request(CertServerRequestOp, inBuf)
	if err != nil {
		return nil, err
	}

	return parseCertResponse(outBuf, "CertServerRequest")
}

// encodeUTF16Attribs encodes the request-attribute string as a UTF-16LE,
// NUL-terminated buffer as the CA expects. An empty string yields an empty blob.
func encodeUTF16Attribs(s string) []byte {
	if s == "" {
		return nil
	}
	u := utf16.Encode([]rune(s))
	u = append(u, 0) // NUL terminator
	out := make([]byte, len(u)*2)
	for i, r := range u {
		le.PutUint16(out[i*2:], r)
	}
	return out
}

// decodeUTF16 decodes a UTF-16LE byte blob (the CA's disposition message),
// trimming a trailing NUL.
func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = le.Uint16(b[i*2:])
	}
	if u[len(u)-1] == 0 {
		u = u[:len(u)-1]
	}
	return string(utf16.Decode(u))
}
