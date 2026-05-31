// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
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

// Package server provides a minimal server-side DCERPC dispatcher. It pairs
// with smb/server's PipeBackend abstraction (via PipeHandler) so a service
// like srvsvc can be hosted on an SMB named pipe (IPC$\\srvsvc).
//
// The dispatcher handles Bind / AlterContext / Request PDUs. It does not
// implement RPC-level authentication: any inbound Bind that carries an
// auth_verifier is rejected with a bind_nak. The underlying SMB session's
// NTLMSSP authentication is sufficient for srvsvc, wkssvc, and other
// IPC$ services.
package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/smb"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/server").SetDisplayName("dcerpc_server")

// Service is one bound RPC interface (e.g. srvsvc, wkssvc). Dispatch is by
// opnum.
type Service interface {
	// InterfaceUUID returns the abstract syntax UUID, in canonical
	// "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" form. Used to match against
	// the AbstractSyntax in inbound Bind context items.
	InterfaceUUID() string
	// InterfaceVersion returns the major / minor interface version.
	// Bind matches by major version only; minor is echoed back.
	InterfaceVersion() (major, minor uint16)
	// Dispatch handles one opnum. The returned bytes are the NDR-encoded
	// response stub (the service's own response struct, including any
	// trailing Win32 error code). Returning a non-nil err generates a
	// fault PDU with status nca_op_rng_error.
	Dispatch(ctx context.Context, opnum uint16, in []byte) (out []byte, err error)
}

// NCA status codes used in fault PDUs (MS-RPCE 2.2.2.6).
const (
	NCAStatusUnspecReject    uint32 = 0x1c000001
	NCAStatusOpRngError      uint32 = 0x1c010002
	NCAStatusUnsupportedType uint32 = 0x1c010017
	NCAStatusProtoError      uint32 = 0x1c01000b
)

// boundCtx records the service that accepted a Bind context-item, keyed by
// the negotiated presentation context id (uint16).
type boundCtx struct {
	service Service
}

// PipeHandler is a smb/server.PipeBackend that runs a DCERPC server over a
// single named-pipe open. One PipeHandler instance per pipe open; it
// maintains the bind state (context id -> Service) for the life of the
// open.
type PipeHandler struct {
	// pipeName is reported in the BindAck SecAddr ("\PIPE\<pipeName>\0").
	// Optional — empty produces SecAddrLen=0, which is also valid on the
	// wire and tolerated by Windows clients.
	pipeName string

	// services keyed by abstract-syntax UUID (lower-case canonical form).
	services map[string]Service

	mu       sync.Mutex
	contexts map[uint16]*boundCtx
}

// NewPipeHandler builds a PipeHandler that exposes the given services. The
// pipeName is reported as the SecAddr in the BindAck (use "" for none).
// Each service's InterfaceUUID identifies which inbound Bind context items
// will be accepted.
func NewPipeHandler(pipeName string, services ...Service) *PipeHandler {
	h := &PipeHandler{
		pipeName: pipeName,
		services: make(map[string]Service, len(services)),
		contexts: make(map[uint16]*boundCtx),
	}
	for _, svc := range services {
		h.services[strings.ToLower(svc.InterfaceUUID())] = svc
	}
	return h
}

// Transceive implements smb/server.PipeBackend. It parses the inbound PDU
// type and dispatches accordingly.
func (h *PipeHandler) Transceive(ctx context.Context, in []byte) ([]byte, uint32, error) {
	if len(in) < dcerpc.PDUHeaderCommonSize {
		return nil, smb.StatusInvalidParameter, fmt.Errorf("PDU too short (%d bytes)", len(in))
	}
	var hdr dcerpc.Header
	if err := hdr.UnmarshalBinary(in[:dcerpc.PDUHeaderCommonSize]); err != nil {
		return nil, smb.StatusInvalidParameter, err
	}
	switch hdr.Type {
	case dcerpc.PacketTypeBind, dcerpc.PacketTypeAlterContext:
		out, err := h.handleBind(in, &hdr)
		if err != nil {
			log.Errorf("handleBind (call_id=%d): %v", hdr.CallId, err)
		}
		return out, smb.StatusOk, err
	case dcerpc.PacketTypeRequest:
		out, err := h.handleRequest(ctx, in, &hdr)
		if err != nil {
			log.Errorf("handleRequest (call_id=%d): %v", hdr.CallId, err)
		}
		return out, smb.StatusOk, err
	default:
		out, err := h.buildFault(&hdr, 0, NCAStatusUnsupportedType)
		if err != nil {
			log.Errorf("buildFault (call_id=%d type=0x%x): %v", hdr.CallId, hdr.Type, err)
		}
		return out, smb.StatusOk, err
	}
}

// Read / Write are not supported. Most clients use Transceive; the few that
// split request/response across separate WRITE+READ are uncommon for the
// services we host (srvsvc, wkssvc).
func (h *PipeHandler) Read(_ context.Context, _ int) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

func (h *PipeHandler) Write(_ context.Context, _ []byte) (int, uint32, error) {
	return 0, smb.StatusNotSupported, nil
}

func (h *PipeHandler) Close(_ context.Context) error {
	h.mu.Lock()
	h.contexts = nil
	h.mu.Unlock()
	return nil
}

// handleBind processes Bind and AlterContext PDUs. For each requested
// context item, it checks whether we offer a service matching the
// abstract syntax UUID (case-insensitive, version major must match) and
// builds an acceptance / rejection in the response result list. Auth on
// the bind is rejected with a bind_nak.
func (h *PipeHandler) handleBind(in []byte, hdr *dcerpc.Header) ([]byte, error) {
	if hdr.AuthLength > 0 {
		log.Debugf("rejecting bind with auth_verifier (auth not supported)")
		return h.buildBindNak(hdr, 2 /* local_limit_exceeded */)
	}
	var req dcerpc.BindReq
	if err := req.UnmarshalBinary(in); err != nil {
		return h.buildBindNak(hdr, 0 /* not specified */)
	}

	results := make([]dcerpc.ContextResItem, 0, len(req.ContextList.Items))
	h.mu.Lock()
	for i := range req.ContextList.Items {
		item := &req.ContextList.Items[i]
		svc := h.lookupServiceLocked(item.AbstractSyntax)
		if svc == nil || len(item.TransferSyntax) == 0 {
			results = append(results, dcerpc.ContextResItem{
				Result: 1, // user_rejection
				Reason: 1, // abstract_syntax_not_supported
				TransferSyntax: dcerpc.SyntaxId{
					UUID:    make([]byte, 16),
					Version: 0,
				},
			})
			continue
		}
		// Accept the first transfer syntax (NDR v2 in practice).
		syn := item.TransferSyntax[0]
		results = append(results, dcerpc.ContextResItem{
			Result:         0, // acceptance
			Reason:         0,
			TransferSyntax: syn,
		})
		h.contexts[item.Id] = &boundCtx{service: svc}
	}
	h.mu.Unlock()

	respType := dcerpc.PacketTypeBindAck
	if hdr.Type == dcerpc.PacketTypeAlterContext {
		respType = dcerpc.PacketTypeAlterContextResp
	}

	res := &dcerpc.BindRes{
		Header: dcerpc.Header{
			MajorVersion:   5,
			MinorVersion:   0,
			Type:           respType,
			Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
			Representation: 0x00000010,
			CallId:         hdr.CallId,
		},
		MaxSendFragSize: req.MaxSendFragSize,
		MaxRecvFragSize: req.MaxRecvFragSize,
		Association:     0x00000001,
		ResultList: dcerpc.ContextResList{
			Items: results,
		},
	}
	if h.pipeName != "" {
		// SecAddr = "\PIPE\<pipeName>\0" ASCII.
		secAddr := append([]byte("\\PIPE\\"+h.pipeName), 0)
		res.SecAddr = secAddr
	}
	return res.MarshalBinary()
}

// lookupServiceLocked returns the Service whose UUID matches abstractSyntax,
// or nil. Caller must hold h.mu.
func (h *PipeHandler) lookupServiceLocked(s dcerpc.SyntaxId) Service {
	if len(s.UUID) != 16 {
		return nil
	}
	for uuidStr, svc := range h.services {
		want, err := dcerpc.UUIDToBin(uuidStr)
		if err != nil {
			continue
		}
		if bytes.Equal(want, s.UUID) {
			major, _ := svc.InterfaceVersion()
			if uint16(s.Version&0xffff) == major {
				return svc
			}
		}
	}
	return nil
}

// handleRequest processes a Request PDU. Looks up the service for the
// negotiated context id, calls Dispatch, and builds a Response PDU. Errors
// are reported as fault PDUs.
func (h *PipeHandler) handleRequest(ctx context.Context, in []byte, hdr *dcerpc.Header) ([]byte, error) {
	// Require the request to be unfragmented: both first- and last-frag
	// flags set. Multi-fragment requests fault with proto_error.
	if hdr.Flags&(dcerpc.PfcFirstFrag|dcerpc.PfcLastFrag) != (dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag) {
		return h.buildFault(hdr, 0, NCAStatusProtoError)
	}
	var req dcerpc.RequestReq
	if err := req.UnmarshalBinary(in); err != nil {
		return h.buildFault(hdr, 0, NCAStatusProtoError)
	}

	h.mu.Lock()
	bc, ok := h.contexts[req.ContextId]
	h.mu.Unlock()
	if !ok {
		return h.buildFault(hdr, req.ContextId, dcerpc.ErrorContextMismatch)
	}

	out, err := bc.service.Dispatch(ctx, req.Opnum, req.Buffer)
	if err != nil {
		log.Debugf("service Dispatch opnum=%d: %v", req.Opnum, err)
		return h.buildFault(hdr, req.ContextId, NCAStatusOpRngError)
	}

	res := &dcerpc.RequestRes{
		Header: dcerpc.Header{
			MajorVersion:   5,
			MinorVersion:   0,
			Type:           dcerpc.PacketTypeResponse,
			Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
			Representation: 0x00000010,
			CallId:         hdr.CallId,
		},
		AllocHint: uint32(len(out)),
		ContextId: req.ContextId,
		Buffer:    out,
	}
	return res.MarshalBinary()
}

// buildFault assembles a fault PDU for the given call/context, with the
// given NCA status code in the body.
func (h *PipeHandler) buildFault(hdr *dcerpc.Header, contextId uint16, status uint32) ([]byte, error) {
	const bodyLen = 16 // alloc_hint(4) + ctx_id(2) + cc(1) + rsvd(1) + status(4) + rsvd2(4)
	buf := make([]byte, dcerpc.PDUHeaderCommonSize+bodyLen)
	fhdr := dcerpc.Header{
		MajorVersion:   5,
		MinorVersion:   0,
		Type:           dcerpc.PacketTypeFault,
		Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
		Representation: 0x00000010,
		FragLength:     uint16(len(buf)),
		CallId:         hdr.CallId,
	}
	hb, err := fhdr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(buf, hb)
	off := dcerpc.PDUHeaderCommonSize
	binary.LittleEndian.PutUint32(buf[off:], 0) // alloc_hint
	off += 4
	binary.LittleEndian.PutUint16(buf[off:], contextId)
	off += 2
	buf[off] = 0 // cancel_count
	off++
	buf[off] = 0 // reserved
	off++
	binary.LittleEndian.PutUint32(buf[off:], status)
	off += 4
	// reserved2 4 bytes left zero
	return buf, nil
}

// buildBindNak assembles a bind_nak PDU with no supported-versions list.
func (h *PipeHandler) buildBindNak(hdr *dcerpc.Header, reason uint16) ([]byte, error) {
	const bodyLen = 3 // reject_reason(2) + n_protocols(1)
	buf := make([]byte, dcerpc.PDUHeaderCommonSize+bodyLen)
	fhdr := dcerpc.Header{
		MajorVersion:   5,
		MinorVersion:   0,
		Type:           dcerpc.PacketTypeBindNak,
		Flags:          dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag,
		Representation: 0x00000010,
		FragLength:     uint16(len(buf)),
		CallId:         hdr.CallId,
	}
	hb, err := fhdr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(buf, hb)
	binary.LittleEndian.PutUint16(buf[dcerpc.PDUHeaderCommonSize:], reason)
	// n_protocols = 0; nothing more to write.
	return buf, nil
}
