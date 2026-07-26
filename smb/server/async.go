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
)

// Asynchronous request handling (MS-SMB2 §3.3.4.2).
//
// Most requests are answered inline on the connection's serve goroutine. A few
// — CHANGE_NOTIFY above all — are long-running by design: the client asks to be
// told when something happens and expects the server to hold the request open,
// possibly for minutes. Answering those inline would block every other request
// on the connection.
//
// The protocol's answer is the async pattern: the server immediately sends an
// interim response carrying STATUS_PENDING and a server-assigned AsyncId, which
// releases the client to send more requests. When the operation eventually
// completes, the server sends the final response reusing the same MessageId and
// AsyncId. A CANCEL naming that MessageId (or AsyncId) aborts it with
// STATUS_CANCELLED.

// maxAsyncOps caps concurrently outstanding async operations per connection.
// Each one costs a goroutine and a watch registration, so an unbounded count
// would let a client with a valid session exhaust server memory simply by
// issuing CHANGE_NOTIFY in a loop. Beyond the cap requests are answered
// synchronously with STATUS_INSUFFICIENT_RESOURCES.
const maxAsyncOps = 64

// asyncOp is one in-flight asynchronous request.
type asyncOp struct {
	msgID   uint64
	asyncID uint64
	cancel  context.CancelFunc
}

// nextAsyncOpID allocates an AsyncId for a new operation. AsyncIds only have to
// be unique among the operations currently outstanding on this connection; a
// simple per-connection counter satisfies that and makes the value easy to
// correlate in packet captures.
func (c *Conn) nextAsyncOpID() uint64 {
	c.asyncMu.Lock()
	defer c.asyncMu.Unlock()
	c.nextAsyncID++
	return c.nextAsyncID
}

// registerAsync records an outstanding async operation so a later CANCEL (or
// connection teardown) can abort it. It reports false when the per-connection
// cap is already reached, in which case the caller must answer synchronously
// and must not have started any work.
func (c *Conn) registerAsync(op *asyncOp) bool {
	c.asyncMu.Lock()
	defer c.asyncMu.Unlock()
	if c.asyncOps == nil {
		c.asyncOps = make(map[uint64]*asyncOp)
	}
	if len(c.asyncOps) >= maxAsyncOps {
		return false
	}
	c.asyncOps[op.msgID] = op
	return true
}

// completeAsync removes an operation from the outstanding set. Safe to call
// more than once for the same id.
func (c *Conn) completeAsync(msgID uint64) {
	c.asyncMu.Lock()
	defer c.asyncMu.Unlock()
	delete(c.asyncOps, msgID)
}

// cancelAsync aborts the operation registered for msgID, if any, and reports
// whether one was found. The op stays registered: its own goroutine removes it
// after emitting the STATUS_CANCELLED final response, so the cancel path never
// races the completion path into a double reply.
func (c *Conn) cancelAsync(msgID uint64) bool {
	c.asyncMu.Lock()
	op, ok := c.asyncOps[msgID]
	c.asyncMu.Unlock()
	if !ok {
		return false
	}
	op.cancel()
	return true
}

// cancelAllAsync aborts every outstanding operation. Called during connection
// teardown so no watcher goroutine outlives the connection it belongs to.
func (c *Conn) cancelAllAsync() {
	c.asyncMu.Lock()
	ops := make([]*asyncOp, 0, len(c.asyncOps))
	for _, op := range c.asyncOps {
		ops = append(ops, op)
	}
	c.asyncOps = nil
	c.asyncMu.Unlock()
	for _, op := range ops {
		op.cancel()
	}
}

// asyncHeader builds a response header in the asynchronous form (MS-SMB2
// §2.2.1.2): SMB2_FLAGS_ASYNC_COMMAND is set and the 8-byte AsyncId overlays
// the Reserved+TreeId fields, which therefore carry no TreeId.
func asyncHeader(reqHdr *smb.Header, status uint32, sessionID, asyncID uint64, command uint16) smb.Header {
	h := buildResponseHeader(reqHdr, status, sessionID, command)
	h.Flags |= smb.SMB2_FLAGS_ASYNC_COMMAND
	h.Reserved = uint32(asyncID & 0xffffffff)
	h.TreeID = uint32(asyncID >> 32)
	return h
}

// sendInterimResponse emits the STATUS_PENDING interim reply that moves a
// request onto the async path (MS-SMB2 §3.3.4.2). It carries no body beyond the
// 9-byte error-response shape and must reach the client before any final
// response for the same MessageId.
func (c *Conn) sendInterimResponse(ctx pduCtx, reqHdr *smb.Header, sessionID, asyncID uint64) error {
	h := asyncHeader(reqHdr, smb.StatusPending, sessionID, asyncID, reqHdr.Command)
	return c.writeErrorHeader(ctx, &h)
}

// startAsync moves a request onto the asynchronous path: it allocates an
// AsyncId, registers the operation, sends the interim STATUS_PENDING response,
// and runs work on its own goroutine. work receives a context cancelled by
// CANCEL or connection teardown, and returns the final response to send.
//
// It reports false when the connection is at its async cap, leaving the caller
// to answer synchronously; in that case nothing has been sent and no goroutine
// started.
func (c *Conn) startAsync(
	ctx pduCtx,
	reqHdr *smb.Header,
	sessionID uint64,
	work func(context.Context) (any, error),
) (bool, error) {
	opCtx, cancel := context.WithCancel(context.Background())
	op := &asyncOp{msgID: reqHdr.MessageID, asyncID: c.nextAsyncOpID(), cancel: cancel}

	if !c.registerAsync(op) {
		cancel()
		return false, nil
	}

	// The interim response must go out before the goroutine can produce a final
	// one, so it is sent here on the dispatch goroutine rather than inside the
	// worker. If it fails there is nothing to complete: unwind fully.
	if err := c.sendInterimResponse(ctx, reqHdr, sessionID, op.asyncID); err != nil {
		c.completeAsync(op.msgID)
		cancel()
		return true, err
	}

	// The worker must write detached from the compound-chain buffer. ctx.chain
	// belongs to the inbound PDU currently being dispatched and is flushed the
	// moment that dispatch returns — which happens long before this goroutine
	// produces anything. Appending the final response to it would silently drop
	// the reply into a dead chain. Encryption/signing state is carried over
	// unchanged so the reply still mirrors the request's protection.
	replyCtx := pduCtx{signed: ctx.signed, encrypted: ctx.encrypted}

	hdrCopy := *reqHdr
	go func() {
		defer cancel()
		defer c.completeAsync(op.msgID)
		defer func() {
			// This goroutine is outside serve()'s recover scope, so a panic in a
			// VFS notifier would otherwise take the process down.
			if r := recover(); r != nil {
				c.logger().Errorf("recovered from panic in async operation: %v", r)
			}
		}()

		res, err := work(opCtx)
		if err != nil {
			c.logger().Debugf("async operation for message %d failed: %v", hdrCopy.MessageID, err)
			return
		}
		if res == nil {
			return
		}
		if err := c.writeReply(replyCtx, res); err != nil {
			c.logger().Debugf("failed to send async response for message %d: %v", hdrCopy.MessageID, err)
		}
	}()

	return true, nil
}
