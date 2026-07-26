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
	"sync"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// Durable handles (MS-SMB2 §3.3.5.9.6 / §3.3.5.9.7 / §3.3.5.9.12).
//
// A durable handle survives the loss of the TCP connection that opened it: the
// server keeps the underlying VFS handle open for a bounded period, and a
// client that reconnects and presents the right identity gets its handle back
// with file position, locks, and delete-on-close intent intact. Without it,
// every transient network blip aborts an in-progress copy.
//
// The lifecycle here is:
//
//	CREATE with DHnQ/DH2Q  -> handle is marked durable, response echoes a grant
//	connection lost        -> handle is parked in Server.durables with a deadline
//	CREATE with DHnC/DH2C  -> handle is re-attached to the new tree
//	deadline passes        -> reaper closes it through the VFS
//
// Ownership is enforced on reconnect: a parked handle is only returned to the
// same user@domain and the same share it was opened on. Without that check any
// authenticated user could reclaim another's handle by guessing a FileId.

// DefaultDurableTimeout is how long a parked handle is retained when the client
// does not request a specific timeout (or requests 0). Windows uses 60s for
// durable handles; matching it keeps client-side expectations sane.
const DefaultDurableTimeout = 60 * time.Second

// MaxDurableTimeout caps what a client may ask for. A handle parked forever is
// a resource leak an unauthenticated-then-disconnected client could trigger at
// will, so the request is clamped rather than honored blindly.
const MaxDurableTimeout = 10 * time.Minute

// durableHandle is a VFS handle parked across a connection loss, or marked
// durable while still attached to a live tree.
type durableHandle struct {
	// CreateGuid identifies the handle for v2 reconnect. Zero for v1 grants,
	// which are keyed only by FileID.
	CreateGuid [16]byte
	// FileID is the 16-byte SMB2 FileId the client was given. It is the v1
	// reconnect key and is also validated on v2 reconnect.
	FileID [16]byte

	Handle Handle
	VFS    VFS
	// Share, Username and Domain scope who may reclaim this handle.
	Share    string
	Username string
	Domain   string

	Timeout    time.Duration
	Persistent bool

	// parked is true once the owning connection has gone away and the handle is
	// waiting to be reclaimed. expiresAt is only meaningful while parked.
	parked    bool
	expiresAt time.Time
}

// durableKey identifies a parked handle. A v2 grant is looked up by CreateGuid,
// a v1 grant by FileId; keying on both in one map keeps a single table and one
// lock.
type durableKey struct {
	guid   [16]byte
	fileID [16]byte
}

// durableTable holds every durable handle known to a Server.
type durableTable struct {
	mu      sync.Mutex
	byKey   map[durableKey]*durableHandle
	stop    chan struct{}
	started bool
}

// durableSupported reports whether the server is configured to grant durable
// handles at all.
func (cfg *ServerConfig) durableSupported() bool {
	return cfg.DurableHandles
}

// durableTimeout clamps a client-requested timeout (in milliseconds) into the
// range the server is willing to hold a handle for.
func (cfg *ServerConfig) durableTimeout(requestedMS uint32) time.Duration {
	max := cfg.MaxDurableHandleTimeout
	if max <= 0 {
		max = MaxDurableTimeout
	}
	if requestedMS == 0 {
		d := cfg.DurableHandleTimeout
		if d <= 0 {
			d = DefaultDurableTimeout
		}
		if d > max {
			d = max
		}
		return d
	}
	d := time.Duration(requestedMS) * time.Millisecond
	if d > max {
		d = max
	}
	return d
}

// register records a durable grant for a handle that is still attached to a
// live tree. Parking happens later, on connection teardown.
func (s *Server) registerDurable(d *durableHandle) {
	s.durables.mu.Lock()
	defer s.durables.mu.Unlock()
	if s.durables.byKey == nil {
		s.durables.byKey = make(map[durableKey]*durableHandle)
	}
	s.durables.byKey[durableKey{guid: d.CreateGuid, fileID: d.FileID}] = d
	s.startDurableReaperLocked()
}

// unregisterDurable drops a grant, e.g. because the client closed the handle
// explicitly. The handle itself is closed by the normal Close path.
func (s *Server) unregisterDurable(guid, fileID [16]byte) {
	s.durables.mu.Lock()
	defer s.durables.mu.Unlock()
	delete(s.durables.byKey, durableKey{guid: guid, fileID: fileID})
}

// findDurableForHandle locates the grant covering a live handle, if any. Used
// on Close and on teardown to decide between "release" and "park".
func (s *Server) findDurableForHandle(h Handle) *durableHandle {
	s.durables.mu.Lock()
	defer s.durables.mu.Unlock()
	for _, d := range s.durables.byKey {
		if d.Handle == h {
			return d
		}
	}
	return nil
}

// parkDurable marks a grant as awaiting reconnect and starts its expiry clock.
func (s *Server) parkDurable(d *durableHandle) {
	s.durables.mu.Lock()
	defer s.durables.mu.Unlock()
	d.parked = true
	d.expiresAt = time.Now().Add(d.Timeout)
	s.startDurableReaperLocked()
}

// reclaimDurable looks up a parked handle for reconnect and, on a match,
// removes the parked state and returns it. guid is the zero value for a v1
// reconnect, in which case only FileId is matched.
//
// Identity is checked here, not by the caller: a parked handle may only be
// reclaimed by the same principal on the same share it was opened with.
func (s *Server) reclaimDurable(guid, fileID [16]byte, share, username, domain string) (*durableHandle, bool) {
	s.durables.mu.Lock()
	defer s.durables.mu.Unlock()

	key := durableKey{guid: guid, fileID: fileID}
	d, ok := s.durables.byKey[key]
	if !ok {
		return nil, false
	}
	if !d.parked || time.Now().After(d.expiresAt) {
		// Either still attached to a live connection (reconnecting onto an
		// active handle is not something we support) or already expired.
		return nil, false
	}
	if !strings.EqualFold(d.Share, share) ||
		!strings.EqualFold(d.Username, username) ||
		!strings.EqualFold(d.Domain, domain) {
		return nil, false
	}
	d.parked = false
	return d, true
}

// startDurableReaperLocked starts the expiry goroutine on first use. Caller
// must hold durables.mu.
func (s *Server) startDurableReaperLocked() {
	if s.durables.started {
		return
	}
	s.durables.started = true
	s.durables.stop = make(chan struct{})
	stop := s.durables.stop
	go s.durableReaper(stop)
}

// durableReaper closes parked handles whose deadline has passed. It runs until
// the Server is shut down.
func (s *Server) durableReaper(stop <-chan struct{}) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			s.expireDurables(time.Now())
		}
	}
}

// expireDurables closes and removes every parked handle past its deadline.
// Split out from the reaper loop so tests can drive it directly.
func (s *Server) expireDurables(now time.Time) {
	s.durables.mu.Lock()
	var expired []*durableHandle
	for k, d := range s.durables.byKey {
		if d.parked && now.After(d.expiresAt) {
			expired = append(expired, d)
			delete(s.durables.byKey, k)
		}
	}
	s.durables.mu.Unlock()

	logger := s.Config.logger()
	for _, d := range expired {
		logger.Debugf("durable handle for %s\\%s on share %q expired after %v", d.Domain, d.Username, d.Share, d.Timeout)
		if d.VFS == nil {
			continue
		}
		if err := d.VFS.Close(context.Background(), d.Handle); err != nil {
			logger.Debugf("VFS.Close on durable expiry: %v", err)
		}
	}
}

// stopDurables halts the reaper and closes every remaining parked handle.
// Called from Server shutdown so a durable grant cannot outlive its Server.
func (s *Server) stopDurables() {
	s.durables.mu.Lock()
	if s.durables.started {
		close(s.durables.stop)
		s.durables.started = false
	}
	remaining := make([]*durableHandle, 0, len(s.durables.byKey))
	for _, d := range s.durables.byKey {
		if d.parked {
			remaining = append(remaining, d)
		}
	}
	s.durables.byKey = nil
	s.durables.mu.Unlock()

	logger := s.Config.logger()
	for _, d := range remaining {
		if d.VFS == nil {
			continue
		}
		if err := d.VFS.Close(context.Background(), d.Handle); err != nil {
			logger.Debugf("VFS.Close on shutdown: %v", err)
		}
	}
}

// grantDurable inspects a CREATE's context list for a durable-handle request
// and, when the server is configured to allow it, records a grant and returns
// the response contexts that tell the client the grant was made. A client that
// does not receive the matching response context treats the handle as
// non-durable and will not attempt reconnect, so silence is the correct way to
// decline.
func (c *Conn) grantDurable(sess *Session, tree *Tree, handle Handle, fileID []byte, reqCtxs []createContext) []createContext {
	cfg := c.Server.Config
	if !cfg.durableSupported() || len(reqCtxs) == 0 || tree.Share.VFS == nil {
		return nil
	}

	var fid [16]byte
	copy(fid[:], fileID)

	d := &durableHandle{
		FileID:   fid,
		Handle:   handle,
		VFS:      tree.Share.VFS,
		Share:    tree.Share.Name,
		Username: sess.Username,
		Domain:   sess.Domain,
	}

	// v2 is preferred when offered: it carries a CreateGuid, which is what makes
	// reconnect safe to key on across a FileId the server is free to reassign.
	if cc, ok := findCreateContext(reqCtxs, createContextDurableRequestV2); ok {
		req, err := parseDurableRequestV2(cc.Data)
		if err != nil {
			c.logger().Debugf("durable: malformed DH2Q, declining: %v", err)
			return nil
		}
		d.CreateGuid = req.CreateGuid
		d.Timeout = cfg.durableTimeout(req.Timeout)
		// Persistent handles additionally survive server restart, which we
		// cannot honor without durable storage. Grant the durable part and
		// leave the persistent flag clear so the client knows.
		d.Persistent = false
		c.Server.registerDurable(d)
		c.logger().Debugf("durable: granted v2 handle to %s\\%s on %q for %v",
			d.Domain, d.Username, d.Share, d.Timeout)
		return []createContext{{
			Name: createContextDurableRequestV2,
			Data: durableResponseV2(uint32(d.Timeout/time.Millisecond), d.Persistent),
		}}
	}

	if _, ok := findCreateContext(reqCtxs, createContextDurableRequest); ok {
		d.Timeout = cfg.durableTimeout(0)
		c.Server.registerDurable(d)
		c.logger().Debugf("durable: granted v1 handle to %s\\%s on %q for %v",
			d.Domain, d.Username, d.Share, d.Timeout)
		return []createContext{{
			Name: createContextDurableRequest,
			Data: durableResponseV1(),
		}}
	}

	return nil
}

// tryDurableReconnect handles a CREATE carrying DHnC/DH2C. It reports whether
// the request was a reconnect attempt (and so fully handled here), along with
// any error from sending the reply. A reconnect that cannot be satisfied is
// answered with STATUS_OBJECT_NAME_NOT_FOUND per MS-SMB2 §3.3.5.9.7 — the
// client then falls back to a fresh CREATE.
func (c *Conn) tryDurableReconnect(ctx pduCtx, h *smb.Header, sess *Session, tree *Tree, reqCtxs []createContext) (bool, error) {
	if len(reqCtxs) == 0 {
		return false, nil
	}
	logger := c.logger()

	var (
		guid   [16]byte
		fileID [16]byte
	)
	switch {
	case hasCreateContext(reqCtxs, createContextDurableReconnectV2):
		cc, _ := findCreateContext(reqCtxs, createContextDurableReconnectV2)
		req, err := parseDurableReconnectV2(cc.Data)
		if err != nil {
			logger.Debugf("durable: malformed DH2C: %v", err)
			return true, c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
		guid, fileID = req.CreateGuid, req.FileID
	case hasCreateContext(reqCtxs, createContextDurableReconnect):
		cc, _ := findCreateContext(reqCtxs, createContextDurableReconnect)
		id, err := parseDurableReconnect(cc.Data)
		if err != nil {
			logger.Debugf("durable: malformed DHnC: %v", err)
			return true, c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
		fileID = id
	default:
		return false, nil
	}

	if !c.Server.Config.durableSupported() {
		return true, c.writeRawError(ctx, h, smb.StatusObjectNameNotFound)
	}

	d, ok := c.Server.reclaimDurable(guid, fileID, tree.Share.Name, sess.Username, sess.Domain)
	if !ok {
		logger.Debugf("durable: no reclaimable handle for %s\\%s on %q", sess.Domain, sess.Username, tree.Share.Name)
		return true, c.writeRawError(ctx, h, smb.StatusObjectNameNotFound)
	}

	// Re-attach under a fresh volatile id on the new tree, and re-key the grant
	// so a later reconnect (or teardown) finds it under the id the client now
	// holds.
	volatile := tree.addHandle(d.Handle)
	newFileID := fileIDBytes(volatile)
	c.Server.unregisterDurable(d.CreateGuid, d.FileID)
	copy(d.FileID[:], newFileID)
	c.Server.registerDurable(d)

	logger.Debugf("durable: reclaimed handle for %s\\%s on %q -> volatileFID=%d",
		d.Domain, d.Username, d.Share, volatile)

	info, err := d.Handle.Stat()
	if err != nil {
		logger.Debugf("durable: Stat on reclaimed handle: %v", err)
	}

	res := smb.CreateRes{
		Header:         buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandCreate),
		StructureSize:  89,
		CreateAction:   smb.FileOpened,
		CreationTime:   timeToFileTime(info.CreationTime),
		LastAccessTime: timeToFileTime(info.LastAccessTime),
		LastWriteTime:  timeToFileTime(info.LastWriteTime),
		ChangeTime:     timeToFileTime(info.ChangeTime),
		AllocationSize: uint64(info.AllocationSize),
		EndOfFile:      uint64(info.Size),
		FileAttributes: info.Attributes,
		FileId:         newFileID,
		Buffer:         []byte{},
	}
	res.Header.TreeID = h.TreeID
	return true, c.writeReply(ctx, &res)
}

// hasCreateContext reports whether the list contains a context with the name.
func hasCreateContext(ctxs []createContext, name string) bool {
	_, ok := findCreateContext(ctxs, name)
	return ok
}

// releaseDurableForHandle drops any durable grant covering h. Called from the
// explicit Close path: a client that closes a handle has relinquished it, so it
// must not linger in the durable table waiting for a reconnect that will never
// come.
func (c *Conn) releaseDurableForHandle(h Handle) {
	if !c.Server.Config.durableSupported() {
		return
	}
	if d := c.Server.findDurableForHandle(h); d != nil {
		c.Server.unregisterDurable(d.CreateGuid, d.FileID)
	}
}

// parkDurableHandles is the teardown counterpart: for each handle the tree is
// about to release, a live durable grant means "park it" rather than "close
// it". It returns the handles that were parked so the caller can skip closing
// them.
func (c *Conn) parkDurableHandles(handles []Handle) map[Handle]bool {
	if !c.Server.Config.durableSupported() || len(handles) == 0 {
		return nil
	}
	parked := make(map[Handle]bool)
	for _, h := range handles {
		d := c.Server.findDurableForHandle(h)
		if d == nil {
			continue
		}
		c.Server.parkDurable(d)
		parked[h] = true
		c.logger().Debugf("durable: parked handle for %s\\%s on %q for %v",
			d.Domain, d.Username, d.Share, d.Timeout)
	}
	return parked
}
