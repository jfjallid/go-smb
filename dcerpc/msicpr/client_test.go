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

// Tests for the client call paths — the layer above the stub marshalling that
// icpr_test.go and certadmin_test.go lock byte-for-byte. Everything here drives
// a fakeCOM standing in for an activated msdcom.COMObject, so the opnum
// dispatch, the HRESULT-to-error translation, the interface-activation cache
// and the template-list round trip are exercised without a live CA.

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/msdcom"
)

// =========================================================================
// Test doubles
// =========================================================================

// fakeCOM implements comCaller. It records every call and replies from a
// per-opnum table, so a test can assert both what went out and what the client
// made of what came back.
type fakeCOM struct {
	mu         sync.Mutex
	calls      []fakeCall
	replies    map[uint16][]byte
	err        error // returned from CallMethod instead of a reply
	releaseErr error // returned from Release
	released   int
}

type fakeCall struct {
	opnum uint16
	stub  []byte
}

func newFakeCOM() *fakeCOM {
	return &fakeCOM{replies: map[uint16][]byte{}}
}

func (f *fakeCOM) CallMethod(opnum uint16, stubData []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, fakeCall{opnum: opnum, stub: append([]byte{}, stubData...)})
	if f.err != nil {
		return nil, f.err
	}
	reply, ok := f.replies[opnum]
	if !ok {
		return nil, fmt.Errorf("fakeCOM: no canned reply for opnum %d", opnum)
	}
	return reply, nil
}

func (f *fakeCOM) Release() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.released++
	return f.releaseErr
}

func (f *fakeCOM) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// u32 appends a little-endian uint32, the unit every stub in this package is
// built from.
func u32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

// blobStub appends a CERTTRANSBLOB as a server writes it: Cb, referent id,
// max_count, the payload, then padding back to a 4-byte boundary. A nil payload
// is written as a NULL pointer.
func blobStub(b []byte, payload []byte) []byte {
	if payload == nil {
		b = u32(b, 0) // Cb
		return u32(b, 0)
	}
	b = u32(b, uint32(len(payload)))
	b = u32(b, 0x00020000) // referent id (value is never inspected)
	b = u32(b, uint32(len(payload)))
	b = append(b, payload...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// certResponseStub builds a CertServerRequest response stub.
func certResponseStub(requestID, disposition uint32, chain, cert, msg []byte, hresult uint32) []byte {
	b := u32(nil, requestID)
	b = u32(b, disposition)
	b = blobStub(b, chain)
	b = blobStub(b, cert)
	b = blobStub(b, msg)
	return u32(b, hresult)
}

// =========================================================================
// parseCertResponse — shared by both enrollment transports
// =========================================================================

func TestParseCertResponseIssued(t *testing.T) {
	cert := []byte{0x30, 0x82, 0x01, 0x02, 0x03}
	chain := []byte{0x30, 0x80}
	stub := certResponseStub(42, DispIssued, chain, cert, encodeUTF16Attribs("Issued"), 0)

	resp, err := parseCertResponse(stub, "CertServerRequest")
	if err != nil {
		t.Fatalf("parseCertResponse: %v", err)
	}
	if resp.RequestID != 42 {
		t.Errorf("RequestID = %d, want 42", resp.RequestID)
	}
	if !resp.Issued() {
		t.Errorf("Issued() = false, want true (disposition %d)", resp.Disposition)
	}
	if !bytes.Equal(resp.EncodedCert, cert) {
		t.Errorf("EncodedCert = % x, want % x", resp.EncodedCert, cert)
	}
	if !bytes.Equal(resp.CertChain, chain) {
		t.Errorf("CertChain = % x, want % x", resp.CertChain, chain)
	}
	if resp.DispositionMessage != "Issued" {
		t.Errorf("DispositionMessage = %q, want %q", resp.DispositionMessage, "Issued")
	}
}

// A pending request is a success at the RPC layer: no error, no certificate,
// and a disposition the caller is expected to act on. This is the path
// manager-approval templates take, so it must not be mistaken for a failure.
func TestParseCertResponsePending(t *testing.T) {
	stub := certResponseStub(7, DispUnderSubmission, nil, nil,
		encodeUTF16Attribs("Taken Under Submission"), 0)

	resp, err := parseCertResponse(stub, "CertServerRequest")
	if err != nil {
		t.Fatalf("parseCertResponse: %v", err)
	}
	if resp.Issued() {
		t.Error("Issued() = true for a pending request")
	}
	if resp.Disposition != DispUnderSubmission {
		t.Errorf("Disposition = %d, want %d", resp.Disposition, DispUnderSubmission)
	}
	if len(resp.EncodedCert) != 0 {
		t.Errorf("EncodedCert = % x, want empty", resp.EncodedCert)
	}
	if resp.RequestID != 7 {
		t.Errorf("RequestID = %d, want 7 (needed to retrieve the cert later)", resp.RequestID)
	}
}

// A non-zero trailing status must surface as a StatusError carrying the raw
// code and the operation name.
func TestParseCertResponseStatusError(t *testing.T) {
	stub := certResponseStub(0, DispError, nil, nil, nil, EAccessDenied)

	_, err := parseCertResponse(stub, "ICertRequestD::Request")
	if err == nil {
		t.Fatal("expected an error for a non-zero HRESULT")
	}
	var se *dcerpc.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is %T (%v), want *dcerpc.StatusError", err, err)
	}
	if se.Code != EAccessDenied {
		t.Errorf("Code = 0x%08x, want 0x%08x", se.Code, EAccessDenied)
	}
	if se.Op != "ICertRequestD::Request" {
		t.Errorf("Op = %q, want the caller-supplied operation name", se.Op)
	}
}

// A known return code must carry a sentinel so callers can branch on the
// specific reason rather than string-matching a hex code. Without it the whole
// error reads "unknown return code 0x80094012", which says nothing about the
// difference between a denied template and a missing one.
func TestParseCertResponseMapsKnownCode(t *testing.T) {
	stub := certResponseStub(0, DispDenied, nil, nil, nil, CertSrvTemplateDenied)

	_, err := parseCertResponse(stub, "CertServerRequest")
	if !errors.Is(err, ResponseCodeMap[CertSrvTemplateDenied]) {
		t.Fatalf("error %v does not match the CERTSRV_E_TEMPLATE_DENIED sentinel", err)
	}
	if strings.Contains(err.Error(), "unknown return code") {
		t.Errorf("error = %q, want the mapped description", err)
	}
}

// The CA's explanation for a refusal lives in the disposition message, so a
// failing call must hand back the decoded response as well as the error, and
// must fold the message into the error text for callers that only print it.
func TestParseCertResponseKeepsDispositionMessage(t *testing.T) {
	const reason = "Denied by Policy Module 0x80094800, The request was for a certificate template that is not supported"
	stub := certResponseStub(11, DispDenied, nil, nil,
		encodeUTF16Attribs(reason), CertSrvUnsupportedCertType)

	resp, err := parseCertResponse(stub, "CertServerRequest")
	if err == nil {
		t.Fatal("expected an error for a non-zero HRESULT")
	}
	if resp == nil {
		t.Fatal("expected the decoded response alongside the error")
	}
	if resp.DispositionMessage != reason {
		t.Errorf("DispositionMessage = %q, want %q", resp.DispositionMessage, reason)
	}
	if resp.Disposition != DispDenied {
		t.Errorf("Disposition = %d, want %d", resp.Disposition, DispDenied)
	}
	if resp.RequestID != 11 {
		t.Errorf("RequestID = %d, want 11", resp.RequestID)
	}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("error = %q, want it to carry the CA's reason", err)
	}
	// Wrapping must not hide the StatusError beneath.
	var se *dcerpc.StatusError
	if !errors.As(err, &se) || se.Code != CertSrvUnsupportedCertType {
		t.Errorf("error %v does not unwrap to the StatusError", err)
	}
}

func TestParseCertResponseTruncated(t *testing.T) {
	if _, err := parseCertResponse([]byte{0x01, 0x02, 0x03}, "CertServerRequest"); err == nil {
		t.Error("expected an error decoding a truncated stub")
	}
}

func TestDispositionName(t *testing.T) {
	for code, want := range map[uint32]string{
		DispIssued:          "issued",
		DispDenied:          "denied",
		DispUnderSubmission: "under submission (pending)",
	} {
		if got := DispositionName(code); got != want {
			t.Errorf("DispositionName(%d) = %q, want %q", code, got, want)
		}
	}
	// An unmapped code must still render usefully rather than as an empty
	// string, since it reaches the operator verbatim.
	if got := DispositionName(0x99); got != "unknown disposition 0x99" {
		t.Errorf("DispositionName(0x99) = %q", got)
	}
}

// =========================================================================
// RPCCon (MS-ICPR enrollment over \pipe\cert or a dynamic TCP endpoint)
// =========================================================================

// fakeBind implements certRequester, standing in for the bound ServiceBind.
type fakeBind struct {
	calls   []fakeCall
	replies map[uint16][]byte
	err     error
}

func (f *fakeBind) MakeRequest(opnum uint16, innerBuf []byte) ([]byte, error) {
	f.calls = append(f.calls, fakeCall{opnum: opnum, stub: append([]byte{}, innerBuf...)})
	if f.err != nil {
		return nil, f.err
	}
	return f.replies[opnum], nil
}

// The named-pipe path is the default transport. It must dispatch on opnum 0 and
// send the attributes as a UTF-16LE CERTTRANSBLOB (where the DCOM twin sends a
// wide string), then share the response parsing with it.
func TestRPCConCertServerRequest(t *testing.T) {
	cert := []byte{0x30, 0x82, 0xBB, 0xCC}
	fake := &fakeBind{replies: map[uint16][]byte{
		CertServerRequestOp: certResponseStub(5, DispIssued, nil, cert, nil, 0),
	}}

	resp, err := (&RPCCon{requester: fake}).CertServerRequest(
		"CA", []byte{0xDE, 0xAD, 0xBE}, "CertificateTemplate:User", 0)
	if err != nil {
		t.Fatalf("CertServerRequest: %v", err)
	}
	if !resp.Issued() || !bytes.Equal(resp.EncodedCert, cert) {
		t.Errorf("got disposition %d cert % x, want issued + % x", resp.Disposition, resp.EncodedCert, cert)
	}
	if resp.RequestID != 5 {
		t.Errorf("RequestID = %d, want 5", resp.RequestID)
	}

	if len(fake.calls) != 1 {
		t.Fatalf("made %d calls, want 1", len(fake.calls))
	}
	if fake.calls[0].opnum != CertServerRequestOp {
		t.Errorf("dispatched on opnum %d, want %d", fake.calls[0].opnum, CertServerRequestOp)
	}
	want, err := (&CertServerRequestReq{
		PwszAuthority: "CA",
		PctbAttribs:   newBlob(encodeUTF16Attribs("CertificateTemplate:User")),
		PctbRequest:   newBlob([]byte{0xDE, 0xAD, 0xBE}),
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal expectation: %v", err)
	}
	if !bytes.Equal(fake.calls[0].stub, want) {
		t.Errorf("sent stub\n got: % x\nwant: % x", fake.calls[0].stub, want)
	}
}

// Retrieving a previously pending request sends the request id with no CSR and
// no attributes — the shape `download` relies on.
func TestRPCConRetrievePending(t *testing.T) {
	cert := []byte{0x30, 0x82, 0x01}
	fake := &fakeBind{replies: map[uint16][]byte{
		CertServerRequestOp: certResponseStub(7, DispIssued, nil, cert, nil, 0),
	}}

	resp, err := (&RPCCon{requester: fake}).CertServerRequest("CA", nil, "", 7)
	if err != nil {
		t.Fatalf("CertServerRequest: %v", err)
	}
	if !resp.Issued() {
		t.Errorf("disposition = %d, want issued", resp.Disposition)
	}
	want, _ := (&CertServerRequestReq{PwszAuthority: "CA", PdwRequestId: 7}).Marshal()
	if !bytes.Equal(fake.calls[0].stub, want) {
		t.Errorf("retrieve stub\n got: % x\nwant: % x", fake.calls[0].stub, want)
	}
}

func TestRPCConTransportError(t *testing.T) {
	sentinel := errors.New("pipe broken")
	fake := &fakeBind{err: sentinel}

	if _, err := (&RPCCon{requester: fake}).CertServerRequest("CA", nil, "", 0); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the transport error", err)
	}
}

// NewRPCCon must leave the test seam unset so a real RPCCon calls through its
// embedded ServiceBind.
func TestNewRPCConUsesEmbeddedBind(t *testing.T) {
	con := NewRPCCon(nil)
	if con.requester != nil {
		t.Error("NewRPCCon set the requester override; it must default to the embedded ServiceBind")
	}
	if con.ServiceBind != nil {
		t.Error("NewRPCCon did not carry through the ServiceBind it was given")
	}
}

// =========================================================================
// ICertRequestD (DCOM enrollment)
// =========================================================================

// Both enrollment transports must satisfy one interface, which is what lets a
// caller swap them without special-casing.
func TestTransportsShareOneSignature(t *testing.T) {
	type enroller interface {
		CertServerRequest(authority string, request []byte, attributes string, requestID uint32) (*CertResponse, error)
	}
	var _ enroller = (*RPCCon)(nil)
	var _ enroller = (*ICertRequestD)(nil)

	// *msdcom.COMObject must keep satisfying the internal comCaller contract.
	var _ comCaller = (*msdcom.COMObject)(nil)

	// A nil COM object must produce an error, not a panic, on first use.
	client := NewICertRequestD(nil)
	if client.obj != nil {
		t.Error("NewICertRequestD wrapped a non-nil object from a nil argument")
	}
	if _, err := client.CertServerRequest("CA", nil, "", 0); err == nil {
		t.Error("expected an error from a client with no activated object")
	}
}

// The DCOM enrollment call must dispatch on opnum 3 and send the stub the
// layout test in icpr_test.go pins, then decode the reply through the shared
// parser.
func TestICertRequestDCertServerRequest(t *testing.T) {
	fake := newFakeCOM()
	cert := []byte{0x30, 0x82, 0xAA}
	fake.replies[ICertRequestDRequestOp] = certResponseStub(11, DispIssued, nil, cert, nil, 0)

	client := &ICertRequestD{obj: fake}
	resp, err := client.CertServerRequest("CA", []byte{0xDE, 0xAD}, "CertificateTemplate:User", 0)
	if err != nil {
		t.Fatalf("CertServerRequest: %v", err)
	}
	if !resp.Issued() || !bytes.Equal(resp.EncodedCert, cert) {
		t.Errorf("got disposition %d cert % x, want issued + % x", resp.Disposition, resp.EncodedCert, cert)
	}

	if len(fake.calls) != 1 {
		t.Fatalf("made %d calls, want 1", len(fake.calls))
	}
	if fake.calls[0].opnum != ICertRequestDRequestOp {
		t.Errorf("dispatched on opnum %d, want %d", fake.calls[0].opnum, ICertRequestDRequestOp)
	}
	wantAttrs := "CertificateTemplate:User"
	want, err := (&CertServerRequestDReq{
		PwszAuthority:  "CA",
		PwszAttributes: &wantAttrs,
		PctbRequest:    newBlob([]byte{0xDE, 0xAD}),
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal expectation: %v", err)
	}
	if !bytes.Equal(fake.calls[0].stub, want) {
		t.Errorf("sent stub\n got: % x\nwant: % x", fake.calls[0].stub, want)
	}
}

// A transport failure must reach the caller unwrapped rather than being
// reported as a decode error against a nil buffer.
func TestICertRequestDTransportError(t *testing.T) {
	sentinel := errors.New("connection reset")
	fake := newFakeCOM()
	fake.err = sentinel

	_, err := (&ICertRequestD{obj: fake}).CertServerRequest("CA", nil, "", 0)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the transport error", err)
	}
}

// =========================================================================
// ICertAdmin — activation cache
// =========================================================================

// newTestAdmin returns an ICertAdmin whose activation is recorded, along with
// the per-IID objects it hands out.
func newTestAdmin() (*ICertAdmin, map[[16]byte]*fakeCOM, *int) {
	objects := map[[16]byte]*fakeCOM{}
	var activations int
	admin := newICertAdmin(func(iid [16]byte) (comCaller, error) {
		activations++
		obj := newFakeCOM()
		objects[iid] = obj
		return obj, nil
	})
	return admin, objects, &activations
}

// The two admin interfaces have separate IPIDs and must be activated
// independently — and each only once, since activating both up front breaks a
// Kerberos session's second RemoteCreateInstance.
func TestICertAdminActivatesLazilyAndCaches(t *testing.T) {
	admin, objects, activations := newTestAdmin()

	if *activations != 0 {
		t.Fatalf("constructor activated %d interfaces, want 0 (activation is lazy)", *activations)
	}

	// Two calls on ICertAdminD: one activation.
	for _, iid := range [][16]byte{IIDICertAdminD, IIDICertAdminD} {
		if _, err := admin.object(iid); err != nil {
			t.Fatalf("object: %v", err)
		}
	}
	if *activations != 1 {
		t.Errorf("activations = %d after two calls on one interface, want 1", *activations)
	}

	// A call on ICertAdminD2 activates the second interface separately.
	if _, err := admin.object(IIDICertAdminD2); err != nil {
		t.Fatalf("object: %v", err)
	}
	if *activations != 2 {
		t.Errorf("activations = %d, want 2 (one per interface)", *activations)
	}
	if objects[IIDICertAdminD] == objects[IIDICertAdminD2] {
		t.Error("both interfaces resolved to the same object")
	}
}

func TestICertAdminCloseReleasesAndAllowsReactivation(t *testing.T) {
	admin, objects, activations := newTestAdmin()

	if _, err := admin.object(IIDICertAdminD); err != nil {
		t.Fatalf("object: %v", err)
	}
	first := objects[IIDICertAdminD]

	if err := admin.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if first.released != 1 {
		t.Errorf("released = %d after Close, want 1", first.released)
	}

	// Close is idempotent: a second call must not double-release.
	if err := admin.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if first.released != 1 {
		t.Errorf("released = %d after a second Close, want 1", first.released)
	}

	// The cache was emptied, so the next call activates afresh.
	if _, err := admin.object(IIDICertAdminD); err != nil {
		t.Fatalf("object after Close: %v", err)
	}
	if *activations != 2 {
		t.Errorf("activations = %d, want 2 (re-activated after Close)", *activations)
	}
}

func TestICertAdminActivationError(t *testing.T) {
	sentinel := errors.New("RPC_S_SEC_PKG_ERROR")
	admin := newICertAdmin(func(iid [16]byte) (comCaller, error) { return nil, sentinel })

	_, err := admin.ResubmitRequest("CA", 1)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want the activation error", err)
	}

	// A failed activation must not be cached as a usable object.
	if _, err := admin.object(IIDICertAdminD); !errors.Is(err, sentinel) {
		t.Errorf("second attempt err = %v, want the activation error again", err)
	}
}

func TestICertAdminNoActivator(t *testing.T) {
	admin := &ICertAdmin{objects: map[[16]byte]comCaller{}}
	if _, err := admin.object(IIDICertAdminD); err == nil {
		t.Error("expected an error with no activation function")
	}
}

// NewICertAdmin wraps an activator returning the concrete *msdcom.COMObject. A
// (nil, nil) return must become an error rather than a non-nil interface
// wrapping a nil pointer, which would panic on the first CallMethod.
func TestNewICertAdminRejectsNilObject(t *testing.T) {
	admin := NewICertAdmin(func(iid [16]byte) (*msdcom.COMObject, error) { return nil, nil })
	if _, err := admin.object(IIDICertAdminD); err == nil {
		t.Error("expected an error when activation yields a nil object")
	}
}

// Concurrent first calls must activate each interface exactly once. Run with
// -race, this also covers the mutex guarding the cache.
func TestICertAdminConcurrentActivation(t *testing.T) {
	var mu sync.Mutex
	activations := map[[16]byte]int{}

	admin := newICertAdmin(func(iid [16]byte) (comCaller, error) {
		mu.Lock()
		activations[iid]++
		mu.Unlock()
		return newFakeCOM(), nil
	})

	iids := [][16]byte{IIDICertAdminD, IIDICertAdminD2}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := admin.object(iids[i%len(iids)]); err != nil {
				t.Errorf("object: %v", err)
			}
		}(i)
	}
	wg.Wait()

	for _, iid := range iids {
		if activations[iid] != 1 {
			t.Errorf("interface %x activated %d times, want 1", iid, activations[iid])
		}
	}
}

// =========================================================================
// ICertAdmin — the CA operations
// =========================================================================

// adminWithReplies wires one fake object behind every interface so a single
// table serves both ICertAdminD and ICertAdminD2 opnums.
func adminWithReplies(replies map[uint16][]byte) (*ICertAdmin, *fakeCOM) {
	fake := newFakeCOM()
	fake.replies = replies
	return newICertAdmin(func(iid [16]byte) (comCaller, error) { return fake, nil }), fake
}

// ResubmitRequest is the ESC7 weaponisation: it must dispatch on opnum 5 and
// return the CA's new disposition.
func TestResubmitRequest(t *testing.T) {
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminDResubmitRequestOp: u32(u32(nil, DispIssued), 0),
	})

	disp, err := admin.ResubmitRequest("CA", 7)
	if err != nil {
		t.Fatalf("ResubmitRequest: %v", err)
	}
	if disp != DispIssued {
		t.Errorf("disposition = %d, want %d", disp, DispIssued)
	}
	if fake.calls[0].opnum != ICertAdminDResubmitRequestOp {
		t.Errorf("opnum = %d, want %d", fake.calls[0].opnum, ICertAdminDResubmitRequestOp)
	}
	want, _ := encodeStub(&ResubmitRequestReq{PwszAuthority: "CA", DwRequestId: 7})
	if !bytes.Equal(fake.calls[0].stub, want) {
		t.Errorf("sent stub\n got: % x\nwant: % x", fake.calls[0].stub, want)
	}
}

// Access denied is the expected reply when the caller lacks the CA role, so the
// code must reach the caller intact — it is what distinguishes "no permission"
// from "no such request". The disposition is returned alongside the error.
func TestResubmitRequestAccessDenied(t *testing.T) {
	const accessDenied = 0x80070005
	admin, _ := adminWithReplies(map[uint16][]byte{
		ICertAdminDResubmitRequestOp: u32(u32(nil, DispError), accessDenied),
	})

	disp, err := admin.ResubmitRequest("CA", 7)
	var se *dcerpc.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error is %T (%v), want *dcerpc.StatusError", err, err)
	}
	if se.Code != accessDenied {
		t.Errorf("Code = 0x%08x, want 0x%08x", se.Code, accessDenied)
	}
	if disp != DispError {
		t.Errorf("disposition = %d, want the CA's reported %d", disp, DispError)
	}
}

func TestDenyRequest(t *testing.T) {
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminDDenyRequestOp: u32(nil, 0),
	})

	if err := admin.DenyRequest("CA", 9); err != nil {
		t.Fatalf("DenyRequest: %v", err)
	}
	if fake.calls[0].opnum != ICertAdminDDenyRequestOp {
		t.Errorf("opnum = %d, want %d", fake.calls[0].opnum, ICertAdminDDenyRequestOp)
	}

	admin2, _ := adminWithReplies(map[uint16][]byte{
		ICertAdminDDenyRequestOp: u32(nil, 0x80070005),
	})
	if err := admin2.DenyRequest("CA", 9); err == nil {
		t.Error("expected an error for a non-zero HRESULT")
	}
}

func TestGetCASecurity(t *testing.T) {
	sd := []byte{0x01, 0x00, 0x04, 0x80, 0xAA, 0xBB}
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCASecurityOp: u32(blobStub(nil, sd), 0),
	})

	got, err := admin.GetCASecurity("CA")
	if err != nil {
		t.Fatalf("GetCASecurity: %v", err)
	}
	if !bytes.Equal(got, sd) {
		t.Errorf("security descriptor = % x, want % x", got, sd)
	}
	if fake.calls[0].opnum != ICertAdminD2GetCASecurityOp {
		t.Errorf("opnum = %d, want %d", fake.calls[0].opnum, ICertAdminD2GetCASecurityOp)
	}
}

// The officer/manager grant path is a read-modify-write, so the descriptor
// handed to SetCASecurity must arrive on the wire byte-for-byte.
func TestSetCASecurity(t *testing.T) {
	sd := []byte{0x01, 0x00, 0x04, 0x80, 0xAA}
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2SetCASecurityOp: u32(nil, 0),
	})

	if err := admin.SetCASecurity("CA", sd); err != nil {
		t.Fatalf("SetCASecurity: %v", err)
	}
	want, _ := encodeStub(&SetCASecurityReq{PwszAuthority: "CA", PctbSD: newBlob(sd)})
	if !bytes.Equal(fake.calls[0].stub, want) {
		t.Errorf("sent stub\n got: % x\nwant: % x", fake.calls[0].stub, want)
	}
}

// Template publish/unpublish reads the list, edits it and writes it back. The
// CA's trailing NUL entry must survive that round trip, or the rewritten list
// is not in the CA's own format.
func TestTemplateListReadModifyWrite(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\nMachine\n1.2.4\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
		ICertAdminD2SetCAPropertyOp: u32(nil, 0),
	})

	list, err := admin.GetTemplateList("CA")
	if err != nil {
		t.Fatalf("GetTemplateList: %v", err)
	}
	want := []string{"User", "1.2.3", "Machine", "1.2.4", "\x00"}
	if len(list) != len(want) {
		t.Fatalf("list = %q, want %q", list, want)
	}
	for i := range want {
		if list[i] != want[i] {
			t.Errorf("entry %d = %q, want %q", i, list[i], want[i])
		}
	}

	// Write the untouched list back and confirm the payload is unchanged.
	if err := admin.SetTemplateList("CA", list); err != nil {
		t.Fatalf("SetTemplateList: %v", err)
	}
	sent := fake.calls[1]
	if sent.opnum != ICertAdminD2SetCAPropertyOp {
		t.Fatalf("opnum = %d, want %d", sent.opnum, ICertAdminD2SetCAPropertyOp)
	}
	wantStub, _ := encodeStub(&SetCAPropertyReq{
		PwszAuthority:     "CA",
		PropId:            CRPropTemplates,
		PropType:          PropTypeString,
		PctbPropertyValue: newBlob(stored),
	})
	if !bytes.Equal(sent.stub, wantStub) {
		t.Errorf("round trip changed the stored list\n got: % x\nwant: % x", sent.stub, wantStub)
	}
}

// Appending to the list GetTemplateList returns puts the new pair after the
// CA's terminator, where it is not read back — so AddTemplate must prepend.
func TestAddTemplatePrependsAheadOfTerminator(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
		ICertAdminD2SetCAPropertyOp: u32(nil, 0),
	})

	added, err := admin.AddTemplate("CA", "ESC1", "1.2.9")
	if err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}
	if !added {
		t.Fatal("added = false, want true for a template not yet enabled")
	}

	wantStub, _ := encodeStub(&SetCAPropertyReq{
		PwszAuthority:     "CA",
		PropId:            CRPropTemplates,
		PropType:          PropTypeString,
		PctbPropertyValue: newBlob(encodeUTF16Raw("ESC1\n1.2.9\nUser\n1.2.3\n\x00")),
	})
	if !bytes.Equal(fake.calls[1].stub, wantStub) {
		t.Errorf("written list\n got: % x\nwant: % x", fake.calls[1].stub, wantStub)
	}
}

// An already-enabled template must not be written twice, and the comparison is
// case-insensitive because AD treats template names that way.
func TestAddTemplateIsANoOpWhenEnabled(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
		ICertAdminD2SetCAPropertyOp: u32(nil, 0),
	})

	added, err := admin.AddTemplate("CA", "uSeR", "1.2.3")
	if err != nil {
		t.Fatalf("AddTemplate: %v", err)
	}
	if added {
		t.Error("added = true for a template already enabled")
	}
	if fake.callCount() != 1 {
		t.Errorf("made %d calls, want 1 (the read) with no write", fake.callCount())
	}
}

// An OID must never be mistaken for a template name, or removing a template
// whose OID happens to match another's name would cut the list at the wrong
// place. The terminator must not be matched either.
func TestRemoveTemplateDropsThePairAndKeepsTheTerminator(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\nMachine\n1.2.4\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
		ICertAdminD2SetCAPropertyOp: u32(nil, 0),
	})

	removed, err := admin.RemoveTemplate("CA", "User")
	if err != nil {
		t.Fatalf("RemoveTemplate: %v", err)
	}
	if !removed {
		t.Fatal("removed = false, want true")
	}

	wantStub, _ := encodeStub(&SetCAPropertyReq{
		PwszAuthority:     "CA",
		PropId:            CRPropTemplates,
		PropType:          PropTypeString,
		PctbPropertyValue: newBlob(encodeUTF16Raw("Machine\n1.2.4\n\x00")),
	})
	if !bytes.Equal(fake.calls[1].stub, wantStub) {
		t.Errorf("written list\n got: % x\nwant: % x", fake.calls[1].stub, wantStub)
	}
}

func TestRemoveTemplateNotEnabled(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
	})

	removed, err := admin.RemoveTemplate("CA", "Machine")
	if err != nil {
		t.Fatalf("RemoveTemplate: %v", err)
	}
	if removed {
		t.Error("removed = true for a template that was not enabled")
	}
	if fake.callCount() != 1 {
		t.Errorf("made %d calls, want 1 (the read) with no write", fake.callCount())
	}
}

// Removing the last template leaves an even-length list, which would be written
// back without the trailing element the CA keeps after the final newline.
func TestRemoveLastTemplateKeepsTerminator(t *testing.T) {
	stored := encodeUTF16Raw("User\n1.2.3\n\x00")
	admin, fake := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, stored), 0),
		ICertAdminD2SetCAPropertyOp: u32(nil, 0),
	})

	if _, err := admin.RemoveTemplate("CA", "User"); err != nil {
		t.Fatalf("RemoveTemplate: %v", err)
	}
	wantStub, _ := encodeStub(&SetCAPropertyReq{
		PwszAuthority:     "CA",
		PropId:            CRPropTemplates,
		PropType:          PropTypeString,
		PctbPropertyValue: newBlob(encodeUTF16Raw("\x00")),
	})
	if !bytes.Equal(fake.calls[1].stub, wantStub) {
		t.Errorf("written list\n got: % x\nwant: % x", fake.calls[1].stub, wantStub)
	}
}

// A failing Release must be reported rather than swallowed, and must not stop
// the remaining interfaces from being released.
func TestCloseReportsReleaseFailures(t *testing.T) {
	boom := errors.New("release failed")
	objects := map[[16]byte]*fakeCOM{}
	admin := newICertAdmin(func(iid [16]byte) (comCaller, error) {
		obj := newFakeCOM()
		obj.releaseErr = boom
		objects[iid] = obj
		return obj, nil
	})
	for _, iid := range [][16]byte{IIDICertAdminD, IIDICertAdminD2} {
		if _, err := admin.object(iid); err != nil {
			t.Fatalf("object: %v", err)
		}
	}

	err := admin.Close()
	if !errors.Is(err, boom) {
		t.Fatalf("Close error = %v, want it to carry the Release failure", err)
	}
	for iid, obj := range objects {
		if obj.released != 1 {
			t.Errorf("interface %x released %d times, want 1 despite the error", iid, obj.released)
		}
	}
}

func TestGetTemplateListEmpty(t *testing.T) {
	admin, _ := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, nil), 0),
	})

	list, err := admin.GetTemplateList("CA")
	if err != nil {
		t.Fatalf("GetTemplateList: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("list = %q, want empty for a CA with no templates", list)
	}
}

// GetCAProperty must surface a failing HRESULT rather than an empty payload —
// an empty template list and a denied read are very different findings.
func TestGetCAPropertyError(t *testing.T) {
	admin, _ := adminWithReplies(map[uint16][]byte{
		ICertAdminD2GetCAPropertyOp: u32(blobStub(nil, nil), 0x80070005),
	})

	if _, err := admin.GetTemplateList("CA"); err == nil {
		t.Error("expected an error for a non-zero HRESULT")
	}
}

// Each operation must land on the interface that actually implements it:
// opnums 3-30 on ICertAdminD, 31+ on ICertAdminD2.
func TestOperationsUseTheRightInterface(t *testing.T) {
	var mu sync.Mutex
	byIID := map[[16]byte]*fakeCOM{}
	admin := newICertAdmin(func(iid [16]byte) (comCaller, error) {
		mu.Lock()
		defer mu.Unlock()
		obj := newFakeCOM()
		obj.replies = map[uint16][]byte{
			ICertAdminDResubmitRequestOp: u32(u32(nil, DispIssued), 0),
			ICertAdminD2GetCASecurityOp:  u32(blobStub(nil, []byte{0x01}), 0),
		}
		byIID[iid] = obj
		return obj, nil
	})

	if _, err := admin.ResubmitRequest("CA", 1); err != nil {
		t.Fatalf("ResubmitRequest: %v", err)
	}
	if _, err := admin.GetCASecurity("CA"); err != nil {
		t.Fatalf("GetCASecurity: %v", err)
	}

	d, ok := byIID[IIDICertAdminD]
	if !ok {
		t.Fatal("ResubmitRequest did not activate ICertAdminD")
	}
	d2, ok := byIID[IIDICertAdminD2]
	if !ok {
		t.Fatal("GetCASecurity did not activate ICertAdminD2")
	}
	if d.callCount() != 1 || d.calls[0].opnum != ICertAdminDResubmitRequestOp {
		t.Errorf("ICertAdminD saw %d calls (%v), want just ResubmitRequest", d.callCount(), d.calls)
	}
	if d2.callCount() != 1 || d2.calls[0].opnum != ICertAdminD2GetCASecurityOp {
		t.Errorf("ICertAdminD2 saw %d calls (%v), want just GetCASecurity", d2.callCount(), d2.calls)
	}
}

// =========================================================================
// Encoding helpers
// =========================================================================

func TestEncodeUTF16AttribsEmpty(t *testing.T) {
	// An empty attribute string must produce a NULL blob, not a lone NUL: the
	// download/retrieve path sends no attributes at all.
	if got := encodeUTF16Attribs(""); got != nil {
		t.Errorf("encodeUTF16Attribs(\"\") = % x, want nil", got)
	}
	if b := newBlob(encodeUTF16Attribs("")); b.Cb != 0 || b.Pb != nil {
		t.Errorf("newBlob of an empty attribute string = %+v, want a NULL blob", b)
	}
}

func TestDecodeUTF16Edges(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"nil", nil, ""},
		{"single byte", []byte{0x41}, ""},
		{"no trailing NUL", []byte{0x41, 0x00}, "A"},
		{"trailing NUL trimmed", []byte{0x41, 0x00, 0x00, 0x00}, "A"},
	} {
		if got := decodeUTF16(tc.in); got != tc.want {
			t.Errorf("%s: decodeUTF16(% x) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// decodeUTF16Raw keeps the trailing NUL (the template list depends on it) and
// must not panic on an odd-length buffer.
func TestDecodeUTF16RawKeepsNUL(t *testing.T) {
	if got := decodeUTF16Raw([]byte{0x41, 0x00, 0x00, 0x00}); got != "A\x00" {
		t.Errorf("decodeUTF16Raw = %q, want %q", got, "A\x00")
	}
	if got := decodeUTF16Raw([]byte{0x41, 0x00, 0x42}); got != "A" {
		t.Errorf("odd-length decodeUTF16Raw = %q, want %q", got, "A")
	}
	if got := decodeUTF16Raw(nil); got != "" {
		t.Errorf("decodeUTF16Raw(nil) = %q, want empty", got)
	}
}

func TestNewBlob(t *testing.T) {
	b := newBlob([]byte{1, 2, 3})
	if b.Cb != 3 || !bytes.Equal(b.Pb, []byte{1, 2, 3}) {
		t.Errorf("newBlob = %+v, want Cb=3 with the payload", b)
	}
	if n := newBlob(nil); n.Cb != 0 || n.Pb != nil {
		t.Errorf("newBlob(nil) = %+v, want a NULL blob", n)
	}
}
