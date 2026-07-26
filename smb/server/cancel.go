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
	"github.com/jfjallid/go-smb/smb"
)

// handleCancel replies to an SMB2 CANCEL request with a STATUS_CANCELLED
// error frame. Per MS-SMB2 §3.3.5.16 the server should respond gracefully
// even when there's nothing to cancel — our dispatcher is synchronous so
// every request has already completed by the time the cancel arrives, but
// returning STATUS_NOT_SUPPORTED would be needlessly hostile.
//
// The reply is a header-only error PDU. MessageID is echoed; clients
// correlate the cancel reply back to their pending request via MessageID,
// not AsyncID (we don't issue interim async responses).
func (c *Conn) handleCancel(ctx pduCtx, h *smb.Header) error {
	// An outstanding asynchronous operation (CHANGE_NOTIFY) is the one case
	// where there is something real to cancel. Its own goroutine emits the
	// STATUS_CANCELLED final response once the context takes effect, so
	// nothing is sent from here — replying now would put two responses on the
	// wire for one MessageId.
	if c.cancelAsync(h.MessageID) {
		return nil
	}
	return c.writeRawError(ctx, h, smb.StatusCancelled)
}
