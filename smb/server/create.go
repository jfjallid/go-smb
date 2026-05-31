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

package server

import (
	"context"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// File attribute bits used by the Create/QueryInfo handlers. Only those
// needed for memvfs and round-trip tests are listed; callers may OR in any bit.
const (
	FileAttributeReadonly  uint32 = 0x00000001
	FileAttributeHidden    uint32 = 0x00000002
	FileAttributeSystem    uint32 = 0x00000004
	FileAttributeDirectory uint32 = 0x00000010
	FileAttributeArchive   uint32 = 0x00000020
	FileAttributeNormal    uint32 = 0x00000080
)

// timeToFileTime converts a time.Time to a Windows FILETIME (100ns
// intervals since 1601-01-01 UTC). Returns 0 for the zero value.
func timeToFileTime(t time.Time) uint64 {
	if t.IsZero() {
		return 0
	}
	return ntlmssp.ConvertToFileTime(t)
}

// handleCreate parses an inbound Create request, looks up the share's VFS,
// invokes it, registers the resulting handle, and replies with a CreateRes.
func (c *Conn) handleCreate(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("Create from %s: session %d not authenticated -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("Create from %s: unknown TreeID %d on session %d -> StatusNetworkNameDeleted", c.RemoteAddr, h.TreeID, sess.ID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}

	var req smb.CreateReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("Create from %s: decode CreateReq: %v", c.RemoteAddr, err)
		return formatErr("decode CreateReq", err)
	}

	nameBytes, err := req.CreateReqName()
	if err != nil {
		logger.Errorf("Create from %s: CreateReqName: %v", c.RemoteAddr, err)
		return formatErr("CreateReq name", err)
	}
	name, err := encoder.FromUnicodeString(nameBytes)
	if err != nil {
		logger.Errorf("Create from %s: decode name: %v", c.RemoteAddr, err)
		return formatErr("CreateReq decode name", err)
	}
	name = normalizeSMBPath(name)

	logger.Debugf("Create from %s: tree=%d share=%q path=%q disposition=%d options=0x%08x desiredAccess=0x%08x",
		c.RemoteAddr, tree.ID, tree.Share.Name, name, req.CreateDisposition, req.CreateOptions, req.DesiredAccess)

	if tree.Share.Type == smb.ShareTypePipe {
		return c.handleCreatePipe(ctx, h, tree, name)
	}
	if tree.Share.Type != smb.ShareTypeDisk || tree.Share.VFS == nil {
		// Print shares are not supported in v1; misconfigured Disk shares
		// (no VFS) fail loudly so callers notice.
		logger.Debugf("Create from %s: share %q has unsupported type=%d or nil VFS -> StatusNotSupported",
			c.RemoteAddr, tree.Share.Name, tree.Share.Type)
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}

	// Per-account write gate: refuse dispositions that imply mutation and
	// any FileDeleteOnClose for users without write access on this share.
	// FileOpen/FileOpenIf-existing are read-style and pass through to the
	// VFS; FileOpenIf is denied because the handler can't tell at this
	// point whether the file already exists.
	if !tree.Share.UserCanWrite(sess) {
		switch req.CreateDisposition {
		case smb.FileSupersede, smb.FileOverwrite, smb.FileOverwriteIf, smb.FileCreate, smb.FileOpenIf:
			logger.Debugf("Create from %s: user=%q has no write access on share %q (disposition=%d) -> StatusAccessDenied",
				c.RemoteAddr, sess.Username, tree.Share.Name, req.CreateDisposition)
			return c.writeRawError(ctx, h, smb.StatusAccessDenied)
		}
		if req.CreateOptions&smb.FileDeleteOnClose != 0 {
			logger.Debugf("Create from %s: user=%q has no write access on share %q (FileDeleteOnClose) -> StatusAccessDenied",
				c.RemoteAddr, sess.Username, tree.Share.Name)
			return c.writeRawError(ctx, h, smb.StatusAccessDenied)
		}
	}

	creq := CreateRequest{
		Path:              name,
		DesiredAccess:     req.DesiredAccess,
		FileAttributes:    req.FileAttributes,
		ShareAccess:       req.ShareAccess,
		CreateDisposition: req.CreateDisposition,
		CreateOptions:     req.CreateOptions,
	}

	result, status, vfsErr := tree.Share.VFS.Create(context.Background(), sess, creq)
	if vfsErr != nil {
		logger.Errorf("VFS.Create %q: %v", name, vfsErr)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	if status != smb.StatusOk {
		logger.Debugf("Create from %s: VFS.Create %q returned status=0x%08x", c.RemoteAddr, name, status)
		return c.writeRawError(ctx, h, status)
	}

	volatile := tree.addHandle(result.Handle)
	logger.Debugf("Create from %s: tree=%d path=%q action=%d -> volatileFID=%d",
		c.RemoteAddr, tree.ID, name, result.CreateAction, volatile)

	res := smb.CreateRes{
		Header:         buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandCreate),
		StructureSize:  89,
		OplockLevel:    0,
		Flags:          0,
		CreateAction:   result.CreateAction,
		CreationTime:   timeToFileTime(result.Info.CreationTime),
		LastAccessTime: timeToFileTime(result.Info.LastAccessTime),
		LastWriteTime:  timeToFileTime(result.Info.LastWriteTime),
		ChangeTime:     timeToFileTime(result.Info.ChangeTime),
		AllocationSize: uint64(result.Info.AllocationSize),
		EndOfFile:      uint64(result.Info.Size),
		FileAttributes: result.Info.Attributes,
		FileId:         fileIDBytes(volatile),
		Buffer:         []byte{},
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}

// handleCreatePipe services a Create against a Pipe-typed share (typically
// IPC$). The pipe name is the Create's filename (e.g. "srvsvc"). The
// configured PipeOpener decides whether the pipe exists; on success the
// returned PipeBackend is wrapped in a pipeHandle and registered on the
// tree's handle table.
func (c *Conn) handleCreatePipe(ctx pduCtx, h *smb.Header, tree *Tree, name string) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	if cfg.PipeOpener == nil {
		logger.Debugf("Create pipe %q from %s: no PipeOpener configured -> StatusObjectNameNotFound", name, c.RemoteAddr)
		return c.writeRawError(ctx, h, smb.StatusObjectNameNotFound)
	}
	sess := c.session(h.SessionID)
	backend, status, err := cfg.PipeOpener.OpenPipe(context.Background(), sess, name)
	if err != nil {
		logger.Errorf("PipeOpener.OpenPipe %q: %v", name, err)
		return formatErr("PipeOpener.OpenPipe", err)
	}
	if status != smb.StatusOk {
		logger.Debugf("Create pipe %q from %s: PipeOpener returned status=0x%08x", name, c.RemoteAddr, status)
		return c.writeRawError(ctx, h, status)
	}

	ph := &pipeHandle{name: name, backend: backend}
	volatile := tree.addHandle(ph)
	logger.Debugf("Create pipe from %s: tree=%d pipe=%q -> volatileFID=%d",
		c.RemoteAddr, tree.ID, name, volatile)

	res := smb.CreateRes{
		Header:         buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandCreate),
		StructureSize:  89,
		OplockLevel:    0,
		Flags:          0,
		CreateAction:   1, // FILE_OPENED
		FileAttributes: FileAttributeNormal,
		FileId:         fileIDBytes(volatile),
		Buffer:         []byte{},
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}

// handleClose tears down an open file handle. CloseRes carries the final
// stat snapshot when SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB is set; otherwise the
// snapshot fields are zero per spec.
func (c *Conn) handleClose(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("Close from %s: session %d not authenticated -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("Close from %s: unknown TreeID %d -> StatusNetworkNameDeleted", c.RemoteAddr, h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}

	var req smb.CloseReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("Close from %s: decode CloseReq: %v", c.RemoteAddr, err)
		return formatErr("decode CloseReq", err)
	}
	volatile := volatileFromFileID(req.FileId)
	hndl := tree.evictHandle(volatile)
	if hndl == nil {
		logger.Debugf("Close from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed", c.RemoteAddr, tree.ID, volatile)
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	// Snapshot stat for POSTQUERY_ATTRIB before Close (Close may invalidate
	// the handle's underlying resource). Best effort.
	var info FileInfo
	if req.Flags&0x0001 != 0 {
		var statErr error
		if info, statErr = hndl.Stat(); statErr != nil {
			logger.Debugf("Close from %s: Stat for POSTQUERY_ATTRIB failed: %v", c.RemoteAddr, statErr)
		}
	}

	if ph, ok := hndl.(*pipeHandle); ok {
		if err := ph.closeOnce(context.Background()); err != nil {
			cfg.logger().Debugf("pipe Close: %v", err)
		}
	} else if tree.Share.VFS != nil {
		if err := tree.Share.VFS.Close(context.Background(), hndl); err != nil {
			cfg.logger().Debugf("VFS.Close: %v", err)
		}
	}

	res := smb.CloseRes{
		Header:         buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandClose),
		StructureSize:  60,
		Flags:          req.Flags,
		CreationTime:   timeToFileTime(info.CreationTime),
		LastAccessTime: timeToFileTime(info.LastAccessTime),
		LastWriteTime:  timeToFileTime(info.LastWriteTime),
		ChangeTime:     timeToFileTime(info.ChangeTime),
		AllocationSize: uint64(info.AllocationSize),
		EndOfFile:      uint64(info.Size),
		FileAttributes: info.Attributes,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}

// normalizeSMBPath collapses a wire path to the form expected by VFS impls:
// no leading or trailing backslash, no double-backslashes. The empty string
// represents the share root.
func normalizeSMBPath(p string) string {
	p = strings.Trim(p, "\\")
	for strings.Contains(p, "\\\\") {
		p = strings.ReplaceAll(p, "\\\\", "\\")
	}
	return p
}
