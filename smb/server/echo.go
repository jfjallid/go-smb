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

import "github.com/jfjallid/go-smb/smb"

// handleEcho replies to an inbound SMB2 Echo (keepalive) request. The Echo
// PDU body is a fixed 4-byte StructureSize+Reserved shape; we don't bother
// decoding the request body since there's nothing meaningful in it.
//
// Echo is allowed before SessionSetup completes (per MS-SMB2 3.3.5.16) and
// requires no TreeID — it's purely connection-level. The OnEcho hook can
// abort the connection by returning a non-nil error.
func (c *Conn) handleEcho(ctx pduCtx, h *smb.Header) error {
	if cb := c.Server.Config.OnEcho; cb != nil {
		if err := cb(c); err != nil {
			return err
		}
	}
	res := smb.EchoRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandEcho),
		StructureSize: 4,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}
