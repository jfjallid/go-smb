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

package server

import (
	"context"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// defaultMaximalAccess advertised when Share.MaximalAccess is zero. This is
// FILE_ALL_ACCESS (the value Windows servers return for an unrestricted
// share). Tighter caller-supplied values are honored.
const defaultMaximalAccess uint32 = 0x001f01ff

// handleTreeConnect parses an inbound TreeConnectReq, looks up the share by
// the trailing path component, allocates a Tree on the session, and replies
// with a populated TreeConnectRes.
func (c *Conn) handleTreeConnect(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("TreeConnect from %s: session %d missing or not authenticated -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}

	var req smb.TreeConnectReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("TreeConnect from %s: decode TreeConnectReq: %v", c.RemoteAddr, err)
		return formatErr("decode TreeConnectReq", err)
	}

	pathStr, err := encoder.FromUnicodeString(req.Path)
	if err != nil {
		logger.Errorf("TreeConnect: decode path: %v", err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	shareName := shareNameFromPath(pathStr)
	if shareName == "" {
		logger.Errorf("TreeConnect: empty share name in %q", pathStr)
		return c.writeRawError(ctx, h, smb.StatusBadNetworkName)
	}

	share, ok := cfg.lookupShare(shareName)
	if !ok {
		logger.Debugf("TreeConnect: unknown share %q from %s", shareName, c.RemoteAddr)
		return c.writeRawError(ctx, h, smb.StatusBadNetworkName)
	}

	// Allocate tree first so a hook can mutate state if it wants to.
	t := sess.addTree(share)

	res := smb.TreeConnectRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandTreeConnect),
		StructureSize: 16,
		ShareType:     share.Type,
		ShareFlags:    shareFlagsFor(share),
		Capabilities:  share.Capabilities,
		MaximalAccess: share.MaximalAccess,
	}
	if res.MaximalAccess == 0 {
		res.MaximalAccess = defaultMaximalAccess
	}
	res.Header.TreeID = t.ID

	if cb := cfg.OnTreeConnect; cb != nil {
		st, err := cb(c, sess, shareName, &req, &res)
		if err != nil {
			sess.removeTree(t.ID)
			return err
		}
		if st != nil {
			sess.removeTree(t.ID)
			return c.writeRawError(ctx, h, st.Code)
		}
	}

	logger.Debugf("TreeConnect from %s: SessionID=%d share=%q -> TreeID=%d",
		c.RemoteAddr, sess.ID, shareName, t.ID)

	return c.writeReply(ctx, &res)
}

// handleTreeDisconnect tears down the tree referenced by the request header.
// Open handles registered on the tree are closed via VFS.Close.
func (c *Conn) handleTreeDisconnect(ctx pduCtx, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil {
		logger.Debugf("TreeDisconnect from %s: unknown SessionID %d -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	t := sess.removeTree(h.TreeID)
	if t == nil {
		logger.Debugf("TreeDisconnect from %s: unknown TreeID %d on session %d -> StatusNetworkNameDeleted", c.RemoteAddr, h.TreeID, sess.ID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}

	if cb := cfg.OnTreeDisconnect; cb != nil {
		cb(c, sess, t)
	}

	t.closeOpenHandles(context.Background(), logger)

	logger.Debugf("TreeDisconnect from %s: SessionID=%d TreeID=%d", c.RemoteAddr, sess.ID, t.ID)

	res := smb.TreeDisconnectRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandTreeDisconnect),
		StructureSize: 4,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}

// shareNameFromPath returns the trailing component of an SMB path like
// "\\server\share" — i.e. "share". Inputs are case-preserved; lookup is
// case-insensitive elsewhere.
func shareNameFromPath(p string) string {
	p = strings.TrimRight(p, "\\")
	idx := strings.LastIndex(p, "\\")
	if idx < 0 {
		return p
	}
	return p[idx+1:]
}

// shareFlagsFor returns the ShareFlags bits for the configured share. The
// default caching mode is ShareFlagManualCaching (zero) which is the most
// conservative; callers can override by setting Share.Capabilities (used as
// a free-form bag of flags is overkill — keep this simple for now).
func shareFlagsFor(s Share) uint32 {
	flags := smb.ShareFlagManualCaching
	if s.EncryptData {
		flags |= smb.ShareFlagEncryptData
	}
	return flags
}
