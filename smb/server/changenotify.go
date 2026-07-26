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
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// SMB2 CHANGE_NOTIFY (MS-SMB2 §2.2.35 / §2.2.36 / §3.3.5.19).
//
// Windows Explorer issues a CHANGE_NOTIFY on every directory it displays and
// reissues it as soon as one completes. A server that answers with
// STATUS_NOT_SUPPORTED is answered once and left alone; a server that does not
// answer the command at all leaves Explorer retrying indefinitely. Either way
// the request must not block the connection, which is why this is the server's
// first user of the asynchronous path (see async.go).

// Change-notify CompletionFilter bits (MS-SMB2 §2.2.35).
const (
	FileNotifyChangeFileName    uint32 = 0x00000001
	FileNotifyChangeDirName     uint32 = 0x00000002
	FileNotifyChangeAttributes  uint32 = 0x00000004
	FileNotifyChangeSize        uint32 = 0x00000008
	FileNotifyChangeLastWrite   uint32 = 0x00000010
	FileNotifyChangeLastAccess  uint32 = 0x00000020
	FileNotifyChangeCreation    uint32 = 0x00000040
	FileNotifyChangeEA          uint32 = 0x00000080
	FileNotifyChangeSecurity    uint32 = 0x00000100
	FileNotifyChangeStreamName  uint32 = 0x00000200
	FileNotifyChangeStreamSize  uint32 = 0x00000400
	FileNotifyChangeStreamWrite uint32 = 0x00000800
)

// SMB2_WATCH_TREE requests notifications for the whole subtree, not just the
// immediate directory (MS-SMB2 §2.2.35 Flags).
const smb2WatchTree uint16 = 0x0001

// FileAction values for FILE_NOTIFY_INFORMATION (MS-FSCC §2.7.1).
const (
	FileActionAdded           uint32 = 0x00000001
	FileActionRemoved         uint32 = 0x00000002
	FileActionModified        uint32 = 0x00000003
	FileActionRenamedOldName  uint32 = 0x00000004
	FileActionRenamedNewName  uint32 = 0x00000005
	FileActionAddedStream     uint32 = 0x00000006
	FileActionRemovedStream   uint32 = 0x00000007
	FileActionModifiedStream  uint32 = 0x00000008
	FileActionRemovedByDelete uint32 = 0x00000009
)

// NTSTATUS values specific to change-notify.
const (
	// StatusNotifyCleanup terminates a watch because the handle was closed.
	StatusNotifyCleanup uint32 = 0x0000010B
	// StatusNotifyEnumDir tells the client too many changes occurred to
	// enumerate; it must re-scan the directory itself. Returning it with an
	// empty buffer is always a valid answer to a change-notify.
	StatusNotifyEnumDir uint32 = 0x0000010C
	// StatusInsufficientResources is returned when the async-operation cap is
	// reached.
	StatusInsufficientResources uint32 = 0xC000009A
)

// FileNotifyChange is a single change event. The server serializes these into
// the FILE_NOTIFY_INFORMATION list the client expects.
type FileNotifyChange struct {
	// Action is one of the FileAction* constants.
	Action uint32
	// Name is the changed item's path relative to the watched directory,
	// "\"-separated.
	Name string
}

// ChangeNotifier is the optional VFS extension that backs SMB2 CHANGE_NOTIFY.
// A VFS that does not implement it still works: the server answers change
// notifications with STATUS_NOT_SUPPORTED, which clients (including Explorer)
// accept as "this server does not do notifications" and stop asking.
//
// WatchChanges must block until at least one change matching completionFilter
// occurs beneath h, or ctx is cancelled. Returning (nil, nil) is allowed and is
// treated as "watch ended without changes". Implementations must honor ctx
// promptly — it is cancelled when the client cancels the request, when the
// handle is closed, and when the connection goes away.
type ChangeNotifier interface {
	WatchChanges(ctx context.Context, h Handle, completionFilter uint32, watchTree bool) ([]FileNotifyChange, error)
}

// changeNotifyReq is the parsed SMB2 CHANGE_NOTIFY request body (MS-SMB2
// §2.2.35). The body is a fixed 32 bytes following the 64-byte header.
type changeNotifyReq struct {
	Flags            uint16
	OutputBufferLen  uint32
	FileID           []byte
	CompletionFilter uint32
}

func parseChangeNotifyReq(raw []byte) (*changeNotifyReq, error) {
	// 64 header + 32 body.
	if len(raw) < 96 {
		return nil, fmt.Errorf("CHANGE_NOTIFY request too short (%d bytes)", len(raw))
	}
	b := raw[64:]
	structureSize := binary.LittleEndian.Uint16(b[0:2])
	if structureSize != 32 {
		return nil, fmt.Errorf("CHANGE_NOTIFY StructureSize is %d, want 32", structureSize)
	}
	return &changeNotifyReq{
		Flags:            binary.LittleEndian.Uint16(b[2:4]),
		OutputBufferLen:  binary.LittleEndian.Uint32(b[4:8]),
		FileID:           append([]byte(nil), b[8:24]...),
		CompletionFilter: binary.LittleEndian.Uint32(b[24:28]),
	}, nil
}

// marshalFileNotifyInformation serializes changes into the
// FILE_NOTIFY_INFORMATION list of MS-FSCC §2.7.1:
//
//	NextEntryOffset(4) Action(4) FileNameLength(4) FileName(variable, UTF-16)
//
// Entries are 4-byte aligned and the last carries NextEntryOffset 0. It returns
// (nil, false) when the encoded list would exceed maxLen, which the caller
// reports as STATUS_NOTIFY_ENUM_DIR — the protocol's "too much changed, go look
// yourself" answer.
func marshalFileNotifyInformation(changes []FileNotifyChange, maxLen uint32) ([]byte, bool) {
	var out []byte
	for i, ch := range changes {
		name := encoder.ToUnicode(ch.Name)
		entry := make([]byte, 12+len(name))
		binary.LittleEndian.PutUint32(entry[4:8], ch.Action)
		binary.LittleEndian.PutUint32(entry[8:12], uint32(len(name)))
		copy(entry[12:], name)

		// Every entry but the last is padded to a 4-byte boundary and points at
		// its successor.
		if i < len(changes)-1 {
			if pad := len(entry) % 4; pad != 0 {
				entry = append(entry, make([]byte, 4-pad)...)
			}
			binary.LittleEndian.PutUint32(entry[0:4], uint32(len(entry)))
		}
		out = append(out, entry...)
		if uint32(len(out)) > maxLen {
			return nil, false
		}
	}
	return out, true
}

// buildChangeNotifyRes assembles a CHANGE_NOTIFY response (MS-SMB2 §2.2.36).
// The response reuses the generic QueryDirectory-shaped body: StructureSize 9,
// a 2-byte OutputBufferOffset and a 4-byte OutputBufferLength followed by the
// buffer.
func buildChangeNotifyRes(hdr smb.Header, buf []byte) *smb.QueryDirectoryRes {
	res := &smb.QueryDirectoryRes{
		Header:        hdr,
		StructureSize: 9,
		Buffer:        buf,
	}
	if len(buf) > 0 {
		res.OutputBufferOffset = 72 // 64-byte header + 8-byte fixed body
		res.OutputBufferLength = uint32(len(buf))
	}
	return res
}

// handleChangeNotify serves SMB2 CHANGE_NOTIFY. When the share's VFS implements
// ChangeNotifier the request goes asynchronous: an interim STATUS_PENDING reply
// releases the client, and the final response follows whenever a change arrives
// or the request is cancelled. Without a notifier the answer is an immediate
// STATUS_NOT_SUPPORTED.
func (c *Conn) handleChangeNotify(ctx pduCtx, raw []byte, h *smb.Header) error {
	logger := c.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}

	req, err := parseChangeNotifyReq(raw)
	if err != nil {
		logger.Debugf("change notify: %v", err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}

	handle := tree.lookupHandle(volatileFromFileID(req.FileID))
	if handle == nil {
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}
	// CHANGE_NOTIFY is only meaningful on a directory handle.
	if !handle.IsDir() {
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}

	notifier, ok := tree.Share.VFS.(ChangeNotifier)
	if !ok {
		// No notification source. STATUS_NOT_SUPPORTED is a legitimate answer
		// and, unlike silence, stops clients from reissuing the request.
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}

	watchTree := req.Flags&smb2WatchTree != 0
	outMax := req.OutputBufferLen

	started, err := c.startAsync(ctx, h, h.SessionID, func(opCtx context.Context) (any, error) {
		changes, werr := notifier.WatchChanges(opCtx, handle, req.CompletionFilter, watchTree)

		// Cancellation wins over whatever the notifier returned: the client is
		// no longer waiting for data, only for the terminal status.
		if opCtx.Err() != nil {
			hdr := asyncHeader(h, smb.StatusCancelled, h.SessionID, c.asyncIDFor(h.MessageID), smb.CommandChangeNotify)
			return buildChangeNotifyRes(hdr, nil), nil
		}
		if werr != nil {
			logger.Debugf("change notify watcher failed: %v", werr)
			hdr := asyncHeader(h, StatusNotifyCleanup, h.SessionID, c.asyncIDFor(h.MessageID), smb.CommandChangeNotify)
			return buildChangeNotifyRes(hdr, nil), nil
		}

		buf, fits := marshalFileNotifyInformation(changes, outMax)
		status := smb.StatusOk
		if !fits {
			// Too many changes for the client's buffer: tell it to re-enumerate
			// rather than truncating the list into something misleading.
			buf, status = nil, StatusNotifyEnumDir
		} else if len(buf) == 0 {
			status = StatusNotifyEnumDir
		}
		hdr := asyncHeader(h, status, h.SessionID, c.asyncIDFor(h.MessageID), smb.CommandChangeNotify)
		return buildChangeNotifyRes(hdr, buf), nil
	})
	if err != nil {
		return err
	}
	if !started {
		// At the async cap. Refuse this one rather than growing without bound.
		logger.Debugf("change notify refused: %d async operations already outstanding", maxAsyncOps)
		return c.writeRawError(ctx, h, StatusInsufficientResources)
	}
	return nil
}

// asyncIDFor returns the AsyncId assigned to the outstanding operation for
// msgID, or 0 if it is no longer registered. The final response must echo the
// same AsyncId the interim response advertised so the client can correlate it.
func (c *Conn) asyncIDFor(msgID uint64) uint64 {
	c.asyncMu.Lock()
	defer c.asyncMu.Unlock()
	if op, ok := c.asyncOps[msgID]; ok {
		return op.asyncID
	}
	return 0
}
