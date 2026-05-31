// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"sort"
	"testing"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	srvsvcsrv "github.com/jfjallid/go-smb/dcerpc/mssrvs/server"
	dcserver "github.com/jfjallid/go-smb/dcerpc/server"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
)

// TestSrvSvcShareEnumEndToEnd boots an in-process Server with two disk
// shares (sharing one VFS via aliasing) and a srvsvc-backed IPC$ pipe,
// then drives the in-tree client through TreeConnect IPC$ -> OpenFile
// srvsvc -> Bind -> NetShareEnumAll and asserts the returned share list.
func TestSrvSvcShareEnumEndToEnd(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}

	// One VFS instance backing two share names — exercises the
	// "expose a single backend under multiple names" requirement.
	vfs := memvfs.New(memvfs.Options{})
	srv.RegisterAliasedShares([]string{"public", "docs"}, server.Share{
		Type: smb.ShareTypeDisk,
		VFS:  vfs,
	})

	srvsvc := &srvsvcsrv.Service{
		ServerName: "GO-SMB-TEST",
		Shares:     srvsvcsrv.FromConfig(srv.Config),
	}
	srv.Config.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return dcserver.NewPipeHandler("srvsvc", srvsvc), nil
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	if err := c.TreeConnect("IPC$"); err != nil {
		t.Fatalf("TreeConnect IPC$: %v", err)
	}
	defer c.TreeDisconnect("IPC$")

	f, err := c.OpenFile("IPC$", mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		t.Fatalf("OpenFile srvsvc: %v", err)
	}
	defer f.CloseFile()

	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		t.Fatalf("NewSMBTransport: %v", err)
	}
	bind, err := dcerpc.Bind(tr, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		t.Fatalf("dcerpc.Bind: %v", err)
	}
	rpc := mssrvs.NewRPCCon(bind)

	got, err := rpc.NetShareEnumAll("")
	if err != nil {
		t.Fatalf("NetShareEnumAll: %v", err)
	}

	names := make([]string, 0, len(got))
	for _, s := range got {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	want := []string{"IPC$", "docs", "public"}
	if len(names) != len(want) {
		t.Fatalf("share count: got %d (%v), want %d (%v)", len(names), names, len(want), want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("share[%d] = %q, want %q (full list: %v)", i, names[i], want[i], names)
		}
	}

	// Sanity-check the IPC$ entry surfaces as IPC type with the special bit.
	var ipc *mssrvs.NetShare
	for i := range got {
		if got[i].Name == "IPC$" {
			ipc = &got[i]
			break
		}
	}
	if ipc == nil {
		t.Fatal("IPC$ missing from response")
	}
	if !ipc.Hidden {
		t.Errorf("IPC$ should be marked Hidden, got %+v", ipc)
	}
	if ipc.TypeId != mssrvs.StypeIPC {
		t.Errorf("IPC$ TypeId = 0x%x, want StypeIPC (0x%x)", ipc.TypeId, mssrvs.StypeIPC)
	}
}

// TestSrvSvcShareEnumCallbackOverride exercises the OnShareEnumAll hook
// end-to-end so callers can confirm the per-call override path works
// over the real SMB+DCERPC stack (not just the in-package unit test).
func TestSrvSvcShareEnumCallbackOverride(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}

	srvsvc := &srvsvcsrv.Service{
		OnShareEnumAll: func(_ *mssrvs.NetShareEnumAllRequest, _ []srvsvcsrv.ShareEntry) ([]srvsvcsrv.ShareEntry, uint32) {
			return []srvsvcsrv.ShareEntry{
				{Name: "BAIT", Type: mssrvs.StypeDisktree, Comment: "honeypot"},
			}, 0
		},
	}
	srv.Config.PipeOpener = &server.MapPipeOpener{
		Pipes: map[string]func(*server.Session) (server.PipeBackend, error){
			"srvsvc": func(_ *server.Session) (server.PipeBackend, error) {
				return dcserver.NewPipeHandler("srvsvc", srvsvc), nil
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	if err := c.TreeConnect("IPC$"); err != nil {
		t.Fatalf("TreeConnect IPC$: %v", err)
	}
	defer c.TreeDisconnect("IPC$")

	f, err := c.OpenFile("IPC$", mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		t.Fatalf("OpenFile srvsvc: %v", err)
	}
	defer f.CloseFile()

	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		t.Fatalf("NewSMBTransport: %v", err)
	}
	bind, err := dcerpc.Bind(tr, mssrvs.MSRPCUuidSrvSvc,
		mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		t.Fatalf("dcerpc.Bind: %v", err)
	}
	rpc := mssrvs.NewRPCCon(bind)
	got, err := rpc.NetShareEnumAll("")
	if err != nil {
		t.Fatalf("NetShareEnumAll: %v", err)
	}
	if len(got) != 1 || got[0].Name != "BAIT" || got[0].Comment != "honeypot" {
		t.Fatalf("unexpected enum result: %+v", got)
	}
}
