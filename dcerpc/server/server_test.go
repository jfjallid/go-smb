// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
)

// fakeService is a tiny Service used to verify that PipeHandler routes
// requests by abstract syntax UUID and opnum. Opnum 7 returns the input
// bytes back; opnum 99 returns an error to exercise the fault path.
type fakeService struct {
	uuid  string
	major uint16
	minor uint16

	// mu guards the call-recording fields: TestPipeHandlerConcurrentTransceive
	// dispatches from several goroutines at once.
	mu         sync.Mutex
	lastOpnum  uint16
	lastBuffer []byte
}

func (s *fakeService) InterfaceUUID() string              { return s.uuid }
func (s *fakeService) InterfaceVersion() (uint16, uint16) { return s.major, s.minor }

// last returns the opnum and stub of the most recent Dispatch call.
func (s *fakeService) last() (uint16, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastOpnum, s.lastBuffer
}

func (s *fakeService) Dispatch(_ context.Context, op uint16, in []byte) ([]byte, error) {
	s.mu.Lock()
	s.lastOpnum = op
	s.lastBuffer = append([]byte(nil), in...)
	s.mu.Unlock()
	switch op {
	case 7:
		return append([]byte("ok:"), in...), nil
	default:
		return nil, errOpUnsupported
	}
}

var errOpUnsupported = &dispatchErr{msg: "unsupported op"}

type dispatchErr struct{ msg string }

func (e *dispatchErr) Error() string { return e.msg }

// helper: build a client Bind PDU offering one context for the given UUID.
func clientBind(t *testing.T, callID uint32, ifaceUUID string, major, minor uint16) []byte {
	t.Helper()
	req, err := newBindReqExported(callID, ifaceUUID, major, minor)
	if err != nil {
		t.Fatalf("newBindReq: %v", err)
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("Bind marshal: %v", err)
	}
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))
	return buf
}

// newBindReqExported re-creates the package-private newBindReq from
// dcerpc.go for test use; we need the wire-format Bind to feed PipeHandler.
func newBindReqExported(callID uint32, ifaceUUID string, major, minor uint16) (*dcerpc.BindReq, error) {
	abstractUUID, err := dcerpc.UUIDToBin(ifaceUUID)
	if err != nil {
		return nil, err
	}
	transferUUID, err := dcerpc.UUIDToBin(dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}
	return &dcerpc.BindReq{
		Header: dcerpc.Header{
			MajorVersion:   5,
			MinorVersion:   0,
			Type:           dcerpc.PacketTypeBind,
			Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
			Representation: 0x00000010,
			CallId:         callID,
		},
		MaxSendFragSize: 4280,
		MaxRecvFragSize: 4280,
		ContextList: dcerpc.ContextList{
			Items: []dcerpc.ContextItem{{
				Id:             0,
				AbstractSyntax: dcerpc.SyntaxId{UUID: abstractUUID, Version: (uint32(minor) << 16) | uint32(major)},
				TransferSyntax: []dcerpc.SyntaxId{{UUID: transferUUID, Version: 2}},
			}},
		},
	}, nil
}

// helper: build a client Request PDU on contextId 0 with given opnum/stub.
func clientRequest(t *testing.T, callID uint32, contextID, opnum uint16, stub []byte) []byte {
	t.Helper()
	req := dcerpc.RequestReq{
		Header: dcerpc.Header{
			MajorVersion:   5,
			MinorVersion:   0,
			Type:           dcerpc.PacketTypeRequest,
			Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
			Representation: 0x00000010,
			CallId:         callID,
		},
		AllocHint: uint32(len(stub)),
		ContextId: contextID,
		Opnum:     opnum,
		Buffer:    stub,
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("Request marshal: %v", err)
	}
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))
	return buf
}

func TestPipeHandlerBindAndRequest(t *testing.T) {
	const ifaceUUID = "12345678-1234-1234-1234-123456789012"
	svc := &fakeService{uuid: ifaceUUID, major: 1, minor: 0}

	h := NewPipeHandler("testpipe", svc)

	// 1) Bind succeeds and returns a BindAck with one acceptance result.
	bindReq := clientBind(t, 1, ifaceUUID, 1, 0)
	resp, status, err := h.Transceive(context.Background(), bindReq)
	if err != nil {
		t.Fatalf("Bind Transceive: %v", err)
	}
	if status != 0 {
		t.Fatalf("Bind status = 0x%x", status)
	}

	var bindRes dcerpc.BindRes
	if err := bindRes.UnmarshalBinary(resp); err != nil {
		t.Fatalf("BindRes parse: %v", err)
	}
	if bindRes.Header.Type != dcerpc.PacketTypeBindAck {
		t.Fatalf("expected BindAck, got type %d", bindRes.Header.Type)
	}
	if bindRes.Header.CallId != 1 {
		t.Fatalf("CallId = %d", bindRes.Header.CallId)
	}
	if len(bindRes.ResultList.Items) != 1 || bindRes.ResultList.Items[0].Result != 0 {
		t.Fatalf("expected one acceptance, got %+v", bindRes.ResultList)
	}
	if !bytes.Contains(bindRes.SecAddr, []byte("testpipe")) {
		t.Fatalf("SecAddr should contain pipe name, got %q", bindRes.SecAddr)
	}

	// 2) Request opnum 7 reaches the service and the response stub is
	//    returned to the caller.
	reqStub := []byte("hello")
	reqPDU := clientRequest(t, 2, 0, 7, reqStub)
	resp, _, err = h.Transceive(context.Background(), reqPDU)
	if err != nil {
		t.Fatalf("Request Transceive: %v", err)
	}
	var reqRes dcerpc.RequestRes
	if err := reqRes.UnmarshalBinary(resp); err != nil {
		t.Fatalf("RequestRes parse: %v", err)
	}
	if reqRes.Header.Type != dcerpc.PacketTypeResponse {
		t.Fatalf("expected Response, got type %d", reqRes.Header.Type)
	}
	if reqRes.Header.CallId != 2 {
		t.Fatalf("CallId = %d", reqRes.Header.CallId)
	}
	if !bytes.Equal(reqRes.Buffer, append([]byte("ok:"), reqStub...)) {
		t.Fatalf("response stub = %q", reqRes.Buffer)
	}
	if gotOp, gotBuf := svc.last(); gotOp != 7 || !bytes.Equal(gotBuf, reqStub) {
		t.Fatalf("Service.Dispatch was not called as expected: op=%d buf=%q", gotOp, gotBuf)
	}

	// 3) Request on a context that was never bound -> fault PDU.
	reqPDU = clientRequest(t, 3, 99, 7, reqStub)
	resp, _, err = h.Transceive(context.Background(), reqPDU)
	if err != nil {
		t.Fatalf("Request (unbound ctx) Transceive: %v", err)
	}
	var hdr dcerpc.Header
	if err := hdr.UnmarshalBinary(resp[:16]); err != nil {
		t.Fatalf("fault header parse: %v", err)
	}
	if hdr.Type != dcerpc.PacketTypeFault {
		t.Fatalf("expected Fault, got type %d", hdr.Type)
	}
	gotStatus := binary.LittleEndian.Uint32(resp[24:28])
	if gotStatus != dcerpc.ErrorContextMismatch {
		t.Fatalf("fault status = 0x%x, want 0x%x", gotStatus, dcerpc.ErrorContextMismatch)
	}

	// 4) Request opnum 99 -> service errors -> fault PDU.
	reqPDU = clientRequest(t, 4, 0, 99, nil)
	resp, _, err = h.Transceive(context.Background(), reqPDU)
	if err != nil {
		t.Fatalf("Request (failing op) Transceive: %v", err)
	}
	if err := hdr.UnmarshalBinary(resp[:16]); err != nil {
		t.Fatalf("fault header parse: %v", err)
	}
	if hdr.Type != dcerpc.PacketTypeFault {
		t.Fatalf("expected Fault, got type %d", hdr.Type)
	}
}

func TestPipeHandlerBindRejectsUnknownInterface(t *testing.T) {
	const ifaceUUID = "12345678-1234-1234-1234-123456789012"
	svc := &fakeService{uuid: ifaceUUID, major: 1, minor: 0}
	h := NewPipeHandler("", svc)

	// Different UUID from what the service offers.
	bindReq := clientBind(t, 1, "00000000-0000-0000-0000-000000000000", 1, 0)
	resp, _, err := h.Transceive(context.Background(), bindReq)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	var bindRes dcerpc.BindRes
	if err := bindRes.UnmarshalBinary(resp); err != nil {
		t.Fatalf("BindRes parse: %v", err)
	}
	if bindRes.Header.Type != dcerpc.PacketTypeBindAck {
		t.Fatalf("expected BindAck (with rejection), got %d", bindRes.Header.Type)
	}
	if len(bindRes.ResultList.Items) != 1 {
		t.Fatalf("expected one result item, got %d", len(bindRes.ResultList.Items))
	}
	// 1 = user_rejection
	if bindRes.ResultList.Items[0].Result != 1 {
		t.Fatalf("expected user_rejection, got %d", bindRes.ResultList.Items[0].Result)
	}
}

// Ensure interface-value indirection doesn't leak — exercising the lock
// path under concurrent Transceive calls (defensive smoke).
func TestPipeHandlerConcurrentTransceive(t *testing.T) {
	const ifaceUUID = "12345678-1234-1234-1234-123456789012"
	svc := &fakeService{uuid: ifaceUUID, major: 1, minor: 0}
	h := NewPipeHandler("p", svc)
	if _, _, err := h.Transceive(context.Background(), clientBind(t, 1, ifaceUUID, 1, 0)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	var counter atomic.Uint32
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 50; j++ {
				if _, _, err := h.Transceive(context.Background(), clientRequest(t, counter.Add(1)+1, 0, 7, []byte{1, 2, 3})); err != nil {
					t.Errorf("Transceive: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}
