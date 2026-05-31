// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	dcserver "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/smb"
	smbserver "github.com/jfjallid/go-smb/smb/server"
)

// buildBindPDU produces a Bind PDU offering the srvsvc abstract syntax.
func buildBindPDU(t *testing.T, callID uint32) []byte {
	t.Helper()
	abs, err := dcerpc.UUIDToBin(mssrvs.MSRPCUuidSrvSvc)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := dcerpc.UUIDToBin(dcerpc.MSRPCUuidNdr)
	if err != nil {
		t.Fatal(err)
	}
	req := dcerpc.BindReq{
		Header: dcerpc.Header{
			MajorVersion: 5, Type: dcerpc.PacketTypeBind,
			Flags: dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag, Representation: 0x10,
			CallId: callID,
		},
		MaxSendFragSize: 4280, MaxRecvFragSize: 4280,
		ContextList: dcerpc.ContextList{
			Items: []dcerpc.ContextItem{{
				Id: 0,
				AbstractSyntax: dcerpc.SyntaxId{
					UUID:    abs,
					Version: uint32(mssrvs.MSRPCSrvSvcMajorVersion),
				},
				TransferSyntax: []dcerpc.SyntaxId{{UUID: tx, Version: 2}},
			}},
		},
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))
	return buf
}

// buildEnumRequestPDU wraps a NetrShareEnumAll stub in a Request PDU.
func buildEnumRequestPDU(t *testing.T, callID uint32) []byte {
	t.Helper()
	stub, err := mssrvs.NewNetShareEnumAllRequest("\\\\test").Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req := dcerpc.RequestReq{
		Header: dcerpc.Header{
			MajorVersion: 5, Type: dcerpc.PacketTypeRequest,
			Flags: dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag, Representation: 0x10,
			CallId: callID,
		},
		AllocHint: uint32(len(stub)),
		ContextId: 0,
		Opnum:     mssrvs.SrvSvcOpNetShareEnumAll,
		Buffer:    stub,
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))
	return buf
}

func TestServiceNetShareEnumAllStaticList(t *testing.T) {
	svc := &Service{
		ServerName: "TESTHOST",
		Shares: []ShareEntry{
			{Name: "IPC$", Type: mssrvs.StypeIPC | mssrvs.StypeSpecial, Comment: "Remote IPC"},
			{Name: "public", Type: mssrvs.StypeDisktree, Comment: "Public share"},
			{Name: "secret", Type: mssrvs.StypeDisktree | mssrvs.StypeSpecial, Comment: ""},
		},
	}
	h := dcserver.NewPipeHandler("srvsvc", svc)

	// Bind the srvsvc interface.
	if _, _, err := h.Transceive(context.Background(), buildBindPDU(t, 1)); err != nil {
		t.Fatalf("Bind: %v", err)
	}

	// Send NetrShareEnumAll.
	resp, _, err := h.Transceive(context.Background(), buildEnumRequestPDU(t, 2))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	var rr dcerpc.RequestRes
	if err := rr.UnmarshalBinary(resp); err != nil {
		t.Fatalf("RequestRes parse: %v", err)
	}
	if rr.Header.Type != dcerpc.PacketTypeResponse {
		t.Fatalf("expected Response, got type %d", rr.Header.Type)
	}

	var enumRes mssrvs.NetShareEnumAllResponse
	if err := enumRes.Unmarshal(rr.Buffer); err != nil {
		t.Fatalf("NetShareEnumAllResponse parse: %v", err)
	}
	if enumRes.WindowsError != 0 {
		t.Fatalf("WindowsError = 0x%x", enumRes.WindowsError)
	}
	if enumRes.TotalEntries != 3 {
		t.Fatalf("TotalEntries = %d", enumRes.TotalEntries)
	}
	ctr := enumRes.InfoStruct.Level1
	if ctr == nil || len(ctr.Buffer) != 3 {
		t.Fatalf("expected 3 entries, got %+v", ctr)
	}
	wantNames := []string{"IPC$", "public", "secret"}
	for i, want := range wantNames {
		if ctr.Buffer[i].Name != want {
			t.Errorf("Buffer[%d].Name = %q, want %q", i, ctr.Buffer[i].Name, want)
		}
	}
	if ctr.Buffer[0].Type != mssrvs.StypeIPC|mssrvs.StypeSpecial {
		t.Errorf("Buffer[0].Type = 0x%x", ctr.Buffer[0].Type)
	}
	if ctr.Buffer[1].Comment != "Public share" {
		t.Errorf("Buffer[1].Comment = %q", ctr.Buffer[1].Comment)
	}
	if enumRes.ResumeHandle == nil || *enumRes.ResumeHandle != 0 {
		t.Errorf("ResumeHandle = %v", enumRes.ResumeHandle)
	}
}

func TestServiceNetShareEnumAllCallbackOverride(t *testing.T) {
	staticDefaults := []ShareEntry{
		{Name: "default-only", Type: mssrvs.StypeDisktree},
	}
	called := false
	svc := &Service{
		Shares: staticDefaults,
		OnShareEnumAll: func(req *mssrvs.NetShareEnumAllRequest, defaults []ShareEntry) ([]ShareEntry, uint32) {
			called = true
			if len(defaults) != 1 || defaults[0].Name != "default-only" {
				t.Errorf("callback defaults wrong: %+v", defaults)
			}
			if req.ServerName == nil {
				t.Errorf("expected non-nil ServerName in request")
			}
			return []ShareEntry{
				{Name: "callback-share", Type: mssrvs.StypeDisktree, Comment: "from-cb"},
			}, mssrvs.ErrorSuccess
		},
	}
	h := dcserver.NewPipeHandler("", svc)
	if _, _, err := h.Transceive(context.Background(), buildBindPDU(t, 1)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	resp, _, err := h.Transceive(context.Background(), buildEnumRequestPDU(t, 2))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	var rr dcerpc.RequestRes
	if err := rr.UnmarshalBinary(resp); err != nil {
		t.Fatalf("RequestRes parse: %v", err)
	}
	var enumRes mssrvs.NetShareEnumAllResponse
	if err := enumRes.Unmarshal(rr.Buffer); err != nil {
		t.Fatalf("NetShareEnumAllResponse parse: %v", err)
	}
	if !called {
		t.Fatal("callback was not invoked")
	}
	if enumRes.TotalEntries != 1 {
		t.Fatalf("TotalEntries = %d", enumRes.TotalEntries)
	}
	if enumRes.InfoStruct.Level1.Buffer[0].Name != "callback-share" {
		t.Fatalf("got name %q", enumRes.InfoStruct.Level1.Buffer[0].Name)
	}
}

func TestServiceUnsupportedOpnumFaults(t *testing.T) {
	svc := &Service{}
	h := dcserver.NewPipeHandler("", svc)
	if _, _, err := h.Transceive(context.Background(), buildBindPDU(t, 1)); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	// Build a Request with a known-unsupported opnum (NetSessionEnum=12 is
	// declared but not yet implemented).
	stub := []byte{}
	req := dcerpc.RequestReq{
		Header: dcerpc.Header{
			MajorVersion: 5, Type: dcerpc.PacketTypeRequest,
			Flags: dcerpc.PfcFirstFrag | dcerpc.PfcLastFrag, Representation: 0x10,
			CallId: 5,
		},
		ContextId: 0,
		Opnum:     mssrvs.SrvSvcOpNetrSessionEnum,
		Buffer:    stub,
	}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))

	resp, _, err := h.Transceive(context.Background(), buf)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	var hdr dcerpc.Header
	if err := hdr.UnmarshalBinary(resp[:16]); err != nil {
		t.Fatal(err)
	}
	if hdr.Type != dcerpc.PacketTypeFault {
		t.Fatalf("expected Fault PDU, got type %d", hdr.Type)
	}
}

func TestFromConfig(t *testing.T) {
	cfg := &smbserver.ServerConfig{
		Shares: map[string]smbserver.Share{
			"public":  {Name: "public", Type: smb.ShareTypeDisk, Remark: "Pub"},
			"alias":   {Name: "alias", Type: smb.ShareTypeDisk, Remark: ""},
			"ipc$":    {Name: "IPC$", Type: smb.ShareTypePipe},  // duplicate IPC$ ignored
		},
	}
	got := FromConfig(cfg)
	if len(got) < 3 {
		t.Fatalf("expected at least IPC$ + 2 disk shares, got %d (%+v)", len(got), got)
	}
	if got[0].Name != "IPC$" {
		t.Fatalf("expected IPC$ first, got %q", got[0].Name)
	}
	if got[0].Type != mssrvs.StypeIPC|mssrvs.StypeSpecial {
		t.Fatalf("IPC$ type = 0x%x", got[0].Type)
	}
	hasPublic, hasAlias := false, false
	ipcCount := 0
	for _, e := range got {
		switch e.Name {
		case "public":
			hasPublic = true
			if e.Type != mssrvs.StypeDisktree {
				t.Errorf("public type = 0x%x", e.Type)
			}
			if e.Comment != "Pub" {
				t.Errorf("public comment = %q", e.Comment)
			}
		case "alias":
			hasAlias = true
		case "IPC$":
			ipcCount++
		}
	}
	if !hasPublic || !hasAlias {
		t.Fatalf("missing entries: hasPublic=%v hasAlias=%v (%+v)", hasPublic, hasAlias, got)
	}
	if ipcCount != 1 {
		t.Fatalf("expected exactly 1 IPC$ entry, got %d", ipcCount)
	}
}
