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
)

// fileIDBytes returns the 16-byte SMB2 FileId for the given volatile id.
// Wire format: 8 bytes persistent (LE) || 8 bytes volatile (LE). The
// persistent half is left zero in v1 — tolerated by Linux mount.cifs and by
// Windows clients on a single-session connection.
func fileIDBytes(volatile uint64) []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint64(out[8:], volatile)
	return out
}

// volatileFromFileID extracts the volatile half of a 16-byte SMB2 FileId.
func volatileFromFileID(id []byte) uint64 {
	if len(id) < 16 {
		return 0
	}
	return binary.LittleEndian.Uint64(id[8:])
}

// addHandle registers a VFS handle on the tree and returns its volatile id.
func (t *Tree) addHandle(h Handle) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.handles == nil {
		t.handles = make(map[uint64]Handle)
		t.nextHandleID = 1
	}
	id := t.nextHandleID
	t.nextHandleID++
	t.handles[id] = h
	return id
}

// lookupHandle returns the registered VFS handle for the given volatile id.
func (t *Tree) lookupHandle(volatile uint64) Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.handles == nil {
		return nil
	}
	return t.handles[volatile]
}

// evictHandle removes the handle with the given volatile id and returns it.
// Any cached directory-enumeration state for the same id is also dropped.
func (t *Tree) evictHandle(volatile uint64) Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.handles == nil {
		return nil
	}
	h := t.handles[volatile]
	delete(t.handles, volatile)
	if t.dirEnums != nil {
		delete(t.dirEnums, volatile)
	}
	return h
}

// drainHandles removes every open handle and returns them. Used by tree
// teardown paths to call VFS.Close on each. Also drops any cached
// directory-enumeration state.
func (t *Tree) drainHandles() []Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.handles == nil {
		return nil
	}
	out := make([]Handle, 0, len(t.handles))
	for _, h := range t.handles {
		out = append(out, h)
	}
	t.handles = nil
	t.dirEnums = nil
	return out
}

// closeOpenHandles releases every still-open handle on the tree, routing
// pipe handles through their backend Close and file handles through the
// share's VFS.Close. Errors are logged and otherwise swallowed —
// teardown is best-effort.
func (t *Tree) closeOpenHandles(ctx context.Context, log Logger) {
	t.closeOpenHandlesExcept(ctx, log, nil)
}

// closeOpenHandlesExcept is closeOpenHandles with a skip set. Handles in
// skip have been parked as durable — they must stay open for a reconnect, so
// the teardown path releases the tree's reference without closing the
// underlying resource. The durable table owns them from that point and its
// reaper closes them when the grant expires.
func (t *Tree) closeOpenHandlesExcept(ctx context.Context, log Logger, skip map[Handle]bool) {
	for _, h := range t.drainHandles() {
		if skip[h] {
			continue
		}
		if ph, ok := h.(*pipeHandle); ok {
			if err := ph.closeOnce(ctx); err != nil {
				log.Debugf("pipe Close on teardown: %v", err)
			}
			continue
		}
		if t.Share.VFS == nil {
			continue
		}
		if err := t.Share.VFS.Close(ctx, h); err != nil {
			log.Debugf("VFS.Close on teardown: %v", err)
		}
	}
}

// openHandles snapshots the tree's currently-open handles without removing
// them. Used to decide which are durable before teardown drains the table.
func (t *Tree) openHandles() []Handle {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Handle, 0, len(t.handles))
	for _, h := range t.handles {
		out = append(out, h)
	}
	return out
}
