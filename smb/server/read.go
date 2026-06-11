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

// handleRead processes an SMB2 READ. The data is bounded by the negotiated
// MaxReadSize.
func (c *Conn) handleRead(ctx pduCtx, raw []byte, h *smb.Header) error {
	cfg := c.Server.Config
	logger := c.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("Read: session %d not authenticated -> StatusUserSessionDeleted", h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("Read: unknown TreeID %d -> StatusNetworkNameDeleted", h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}
	var req smb.ReadReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("Read: decode ReadReq: %v", err)
		return formatErr("decode ReadReq", err)
	}
	hndl := tree.lookupHandle(volatileFromFileID(req.FileId))
	if hndl == nil {
		logger.Debugf("Read from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed",
			c.RemoteAddr, tree.ID, volatileFromFileID(req.FileId))
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	// Match the buffer-size limit we advertised in Negotiate. When the
	// dialect supports LargeMTU we advertise 1 MiB by default; bound the
	// per-Read length to that ceiling so we accept what we advertised.
	max := cfg.MaxReadSize
	if max == 0 {
		if c.Dialect >= smb.DialectSmb_2_1 {
			max = 1 << 20
		} else {
			max = 65536
		}
	}
	length := req.Length
	if length > max {
		length = max
	}

	var (
		out    []byte
		n      int
		status uint32
		err    error
	)
	if ph, ok := hndl.(*pipeHandle); ok {
		out, status, err = ph.backend.Read(context.Background(), int(length))
		if err == nil && status == smb.StatusOk {
			n = len(out)
		}
	} else if tree.Share.VFS != nil {
		buf := make([]byte, length)
		n, status, err = tree.Share.VFS.Read(context.Background(), hndl, int64(req.Offset), buf)
		out = buf[:n]
	} else {
		logger.Debugf("Read from %s: tree=%d share=%q has nil VFS and handle is not pipe -> StatusNotSupported",
			c.RemoteAddr, tree.ID, tree.Share.Name)
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}
	if err != nil {
		logger.Errorf("Read: backend error: %v", err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	if status != smb.StatusOk {
		logger.Debugf("Read: backend returned status=0x%08x", status)
		return c.writeRawError(ctx, h, status)
	}
	if n == 0 {
		return c.writeRawError(ctx, h, smb.StatusEndOfFile)
	}

	res := smb.ReadRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandRead),
		StructureSize: 17,
		DataOffset:    80, // 64 (header) + 16 (fixed body before Buffer)
		DataLength:    uint32(n),
		Buffer:        out,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}
