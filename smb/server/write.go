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

// handleWrite processes an SMB2 WRITE.
func (c *Conn) handleWrite(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("Write from %s: session %d not authenticated -> StatusUserSessionDeleted", c.RemoteAddr, h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("Write from %s: unknown TreeID %d -> StatusNetworkNameDeleted", c.RemoteAddr, h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}
	if !tree.Share.UserCanWrite(sess) && tree.Share.Type == smb.ShareTypeDisk {
		logger.Debugf("Write from %s: user=%q has no write access on share %q -> StatusAccessDenied",
			c.RemoteAddr, sess.Username, tree.Share.Name)
		return c.writeRawError(ctx, h, smb.StatusAccessDenied)
	}
	var req smb.WriteReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("Write from %s: decode WriteReq: %v", c.RemoteAddr, err)
		return formatErr("decode WriteReq", err)
	}
	hndl := tree.lookupHandle(volatileFromFileID(req.FileId))
	if hndl == nil {
		logger.Debugf("Write from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed",
			c.RemoteAddr, tree.ID, volatileFromFileID(req.FileId))
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	// Match the buffer-size limit we advertised in Negotiate. When the
	// dialect supports LargeMTU we advertise 1 MiB by default; bound the
	// per-Write length to that ceiling so we accept what we advertised.
	max := cfg.MaxWriteSize
	if max == 0 {
		if c.Dialect >= smb.DialectSmb_2_1 {
			max = 1 << 20
		} else {
			max = 65536
		}
	}
	data := req.Buffer
	if uint32(len(data)) > max {
		logger.Debugf("Write from %s: payload size %d exceeds MaxWriteSize %d -> StatusInvalidParameter",
			c.RemoteAddr, len(data), max)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}

	var (
		n      int
		status uint32
		err    error
	)
	if ph, ok := hndl.(*pipeHandle); ok {
		n, status, err = ph.backend.Write(context.Background(), data)
	} else if tree.Share.VFS != nil {
		n, status, err = tree.Share.VFS.Write(context.Background(), hndl, int64(req.Offset), data)
	} else {
		logger.Debugf("Write from %s: tree=%d share=%q has nil VFS and handle is not pipe -> StatusNotSupported",
			c.RemoteAddr, tree.ID, tree.Share.Name)
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}
	if err != nil {
		logger.Errorf("Write from %s: backend error: %v", c.RemoteAddr, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	if status != smb.StatusOk {
		logger.Debugf("Write from %s: backend returned status=0x%08x", c.RemoteAddr, status)
		return c.writeRawError(ctx, h, status)
	}

	res := smb.WriteRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandWrite),
		StructureSize: 17,
		Count:         uint32(n),
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}
