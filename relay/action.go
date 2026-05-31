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

package relay

import (
	"context"
	"fmt"
	"io"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// PostAuthAction is run by RelayServer against each upstream connection
// immediately after a successful relay. Implementations should respect ctx for
// cancellation and tolerate partial failure (RelayServer logs errors but does
// not propagate them out).
type PostAuthAction interface {
	Name() string
	Run(ctx context.Context, conn *smb.Connection, cred *Credential, logger server.Logger) error
}

// EnumSharesAction calls NetShareEnumAll over the upstream's IPC$ named pipe
// and writes a one-line-per-share summary to Out (or the logger if Out is
// nil). Useful as a quick smoke test that the relayed session is usable.
type EnumSharesAction struct {
	Out io.Writer
}

func (EnumSharesAction) Name() string { return "EnumShares" }

func (a EnumSharesAction) Run(ctx context.Context, conn *smb.Connection, cred *Credential, logger server.Logger) error {
	const share = "IPC$"
	if err := conn.TreeConnect(share); err != nil {
		return fmt.Errorf("EnumShares: TreeConnect %s: %w", share, err)
	}
	defer conn.TreeDisconnect(share)

	f, err := conn.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
	if err != nil {
		return fmt.Errorf("EnumShares: open srvsvc pipe: %w", err)
	}
	defer f.CloseFile()

	tr, err := smbtransport.NewSMBTransport(f)
	if err != nil {
		return fmt.Errorf("EnumShares: NewSMBTransport: %w", err)
	}
	bind, err := dcerpc.Bind(tr, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return fmt.Errorf("EnumShares: bind srvsvc: %w", err)
	}
	rpc := mssrvs.NewRPCCon(bind)

	host := ""
	if cred != nil && cred.Workstation != "" {
		host = cred.Workstation
	}
	shares, err := rpc.NetShareEnumAll(host)
	if err != nil {
		return fmt.Errorf("EnumShares: NetShareEnumAll: %w", err)
	}

	header := fmt.Sprintf("EnumShares result for %s (%d shares):", credLabel(cred), len(shares))
	if a.Out != nil {
		fmt.Fprintln(a.Out, header)
		for _, s := range shares {
			fmt.Fprintf(a.Out, "  %-20s  %-10s  %s\n", s.Name, s.Type, s.Comment)
		}
	} else if logger != nil {
		logger.Noticef("%s", header)
		for _, s := range shares {
			logger.Noticef("  %-20s  %-10s  %s", s.Name, s.Type, s.Comment)
		}
	}
	return nil
}

// DropFileAction writes Content to RemotePath on the named Share. Existing
// files are overwritten.
type DropFileAction struct {
	Share      string
	RemotePath string // backslash-separated, no leading slash (e.g. "Users\\Public\\readme.txt")
	Content    []byte
}

func (a DropFileAction) Name() string { return "DropFile:" + a.Share + "\\" + a.RemotePath }

func (a DropFileAction) Run(ctx context.Context, conn *smb.Connection, cred *Credential, logger server.Logger) error {
	if a.Share == "" || a.RemotePath == "" {
		return fmt.Errorf("DropFile: Share and RemotePath are required")
	}
	if err := conn.TreeConnect(a.Share); err != nil {
		return fmt.Errorf("DropFile: TreeConnect %s: %w", a.Share, err)
	}
	defer conn.TreeDisconnect(a.Share)

	off := 0
	if err := conn.PutFile(a.Share, a.RemotePath, 0, func(buf []byte) (int, error) {
		if off >= len(a.Content) {
			return 0, io.EOF
		}
		n := copy(buf, a.Content[off:])
		off += n
		return n, nil
	}); err != nil {
		return fmt.Errorf("DropFile: PutFile %s\\%s: %w", a.Share, a.RemotePath, err)
	}
	if logger != nil {
		logger.Noticef("DropFile: wrote %d bytes to %s\\%s as %s",
			len(a.Content), a.Share, a.RemotePath, credLabel(cred))
	}
	return nil
}

// FuncAction adapts a free function to the PostAuthAction interface. Useful
// for ad-hoc actions in tests or callers that don't want to declare a type.
type FuncAction struct {
	NameStr string
	Fn      func(ctx context.Context, conn *smb.Connection, cred *Credential, logger server.Logger) error
}

func (f FuncAction) Name() string {
	if f.NameStr == "" {
		return "Func"
	}
	return f.NameStr
}

func (f FuncAction) Run(ctx context.Context, conn *smb.Connection, cred *Credential, logger server.Logger) error {
	if f.Fn == nil {
		return nil
	}
	return f.Fn(ctx, conn, cred, logger)
}

func credLabel(cred *Credential) string {
	if cred == nil {
		return "unknown"
	}
	if cred.Domain == "" {
		return cred.Username
	}
	return cred.Domain + "\\" + cred.Username
}
