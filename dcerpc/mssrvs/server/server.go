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

// Package server provides a configurable server-side handler for the
// Server Service (srvsvc) RPC interface (MS-SRVS). It plugs into
// dcerpc/server.PipeHandler as a Service implementation.
//
// The current opcode coverage is intentionally narrow:
//
//   - NetrShareEnumAll (opnum 15) — answer share-enumeration requests
//     ("net view \\host", smbclient -L).
//
// Other opcodes fault with nca_op_rng_error. Hooks for them can be added
// to the Service struct as the need arises.
package server

import (
	"context"
	"fmt"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/mssrvs/server").SetDisplayName("mssrvs_server")

// ShareEntry is one share returned by NetrShareEnumAll. Type is one of
// the mssrvs.Stype* constants, typically OR'd with StypeSpecial for
// admin/hidden shares.
type ShareEntry struct {
	Name    string
	Type    uint32
	Comment string
}

// Service implements dcerpc/server.Service for srvsvc. Configure it with a
// static share list (Shares) and/or an OnShareEnumAll callback for full
// programmatic control. ServerName is currently unused — reserved for
// NetrServerGetInfo, which is on the roadmap.
type Service struct {
	// ServerName is the name reported by NetrServerGetInfo (not yet
	// implemented). Optional.
	ServerName string

	// Shares is the static list returned by NetrShareEnumAll when
	// OnShareEnumAll is nil. Use FromConfig(cfg) to seed it from a live
	// smb/server config; the result is a plain []ShareEntry the caller
	// can append to or rewrite before assignment.
	Shares []ShareEntry

	// OnShareEnumAll, when non-nil, replaces the static Shares list. The
	// callback receives the parsed request and a copy of Service.Shares
	// so it can filter / augment per-call. The returned status is the
	// Win32 error reported in NetShareEnumAllResponse.WindowsError; use 0
	// for success.
	OnShareEnumAll func(req *mssrvs.NetShareEnumAllRequest, defaults []ShareEntry) ([]ShareEntry, uint32)
}

// InterfaceUUID implements dcerpc/server.Service.
func (s *Service) InterfaceUUID() string { return mssrvs.MSRPCUuidSrvSvc }

// InterfaceVersion implements dcerpc/server.Service.
func (s *Service) InterfaceVersion() (uint16, uint16) {
	return mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion
}

// Dispatch implements dcerpc/server.Service. Switch on opnum; unsupported
// opnums return an error so the dispatcher generates a fault PDU. The
// dcerpc dispatcher logs the error before turning it into a fault, so we
// don't duplicate-log here.
func (s *Service) Dispatch(_ context.Context, opnum uint16, in []byte) ([]byte, error) {
	switch opnum {
	case mssrvs.SrvSvcOpNetShareEnumAll:
		return s.handleNetShareEnumAll(in)
	default:
		return nil, fmt.Errorf("srvsvc: unsupported opnum %d", opnum)
	}
}

// handleNetShareEnumAll resolves the share list (callback if set, else the
// static Shares slice) and marshals a NetShareEnumAllResponse using the
// existing client-side mssrvs structures.
func (s *Service) handleNetShareEnumAll(in []byte) ([]byte, error) {
	var req mssrvs.NetShareEnumAllRequest
	if err := req.Unmarshal(in); err != nil {
		return nil, fmt.Errorf("srvsvc NetShareEnumAll decode: %w", err)
	}

	defaults := append([]ShareEntry(nil), s.Shares...)
	entries := defaults
	status := mssrvs.ErrorSuccess
	if s.OnShareEnumAll != nil {
		entries, status = s.OnShareEnumAll(&req, defaults)
	}

	buf := make([]mssrvs.ShareInfo1, len(entries))
	for i, e := range entries {
		buf[i] = mssrvs.ShareInfo1{
			Name:    e.Name,
			Type:    e.Type,
			Comment: e.Comment,
		}
	}
	ctr := &mssrvs.ShareInfoContainer1{
		EntriesRead: uint32(len(buf)),
		Buffer:      buf,
	}
	resume := uint32(0)
	res := mssrvs.NetShareEnumAllResponse{
		InfoStruct: mssrvs.ShareEnumStruct{
			Level:  1,
			Level1: ctr,
		},
		TotalEntries: uint32(len(buf)),
		ResumeHandle: &resume,
		WindowsError: status,
	}
	out, err := res.Marshal()
	if err != nil {
		return nil, fmt.Errorf("srvsvc NetShareEnumAll encode: %w", err)
	}
	log.Debugf("srvsvc NetShareEnumAll: returning %d shares (status=0x%x)", len(buf), status)
	return out, nil
}

// FromConfig walks cfg.Shares and returns one ShareEntry per registered
// share, with the standard IPC$ entry prepended. Disk shares get
// StypeDisktree; explicit Pipe shares get StypeIPC. Comment is taken from
// Share.Remark.
//
// The returned slice is the caller's to mutate — append entries that
// don't correspond to real shares (honeypot scenarios), reorder, etc.
func FromConfig(cfg *server.ServerConfig) []ShareEntry {
	out := []ShareEntry{
		{Name: "IPC$", Type: mssrvs.StypeIPC | mssrvs.StypeSpecial, Comment: "Remote IPC"},
	}
	if cfg == nil {
		return out
	}
	for _, share := range cfg.Shares {
		if share.Name == "" {
			continue
		}
		// Skip the IPC$ alias if the user explicitly registered it — we
		// already added it above.
		if equalFold(share.Name, "IPC$") {
			continue
		}
		entry := ShareEntry{
			Name:    share.Name,
			Comment: share.Remark,
		}
		switch share.Type {
		case smb.ShareTypePipe:
			entry.Type = mssrvs.StypeIPC
		default:
			entry.Type = mssrvs.StypeDisktree
		}
		out = append(out, entry)
	}
	return out
}

// equalFold is the ASCII case-insensitive equality test used for share
// names. Avoids pulling in strings just for this one call.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
