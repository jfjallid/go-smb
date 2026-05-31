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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// handleSetInfo processes SMB2 SET_INFO. The handler hands raw bytes to the
// VFS so implementations can choose their own deserializer per file-info
// class.
func (c *Conn) handleSetInfo(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("SetInfo from %s: session %d not authenticated -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("SetInfo from %s: unknown TreeID %d -> StatusNetworkNameDeleted", c.RemoteAddr, h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}
	if tree.Share.Type == smb.ShareTypeDisk && !tree.Share.UserCanWrite(sess) {
		logger.Debugf("SetInfo from %s: user=%q has no write access on share %q -> StatusAccessDenied",
			c.RemoteAddr, sess.Username, tree.Share.Name)
		return c.writeRawError(ctx, h, smb.StatusAccessDenied)
	}
	var req smb.SetInfoReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("SetInfo from %s: decode SetInfoReq: %v", c.RemoteAddr, err)
		return formatErr("decode SetInfoReq", err)
	}
	hndl := tree.lookupHandle(volatileFromFileID(req.FileId))
	if hndl == nil {
		logger.Debugf("SetInfo from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed",
			c.RemoteAddr, tree.ID, volatileFromFileID(req.FileId))
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	switch req.InfoType {
	case smb.OInfoFile:
		status, err := tree.Share.VFS.SetFileInfo(context.Background(), hndl, req.FileInfoClass, req.Buffer)
		if err != nil {
			logger.Errorf("VFS.SetFileInfo class=0x%02x: %v", req.FileInfoClass, err)
			return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
		if status != smb.StatusOk {
			logger.Debugf("SetInfo from %s: VFS.SetFileInfo class=0x%02x returned status=0x%08x",
				c.RemoteAddr, req.FileInfoClass, status)
			return c.writeRawError(ctx, h, status)
		}
	default:
		logger.Debugf("SetInfo from %s: unsupported InfoType=0x%02x -> StatusNotSupported",
			c.RemoteAddr, req.InfoType)
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}

	res := smb.SetInfoRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandSetInfo),
		StructureSize: 2,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}
