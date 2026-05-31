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
	"strings"
	"sync"

	"github.com/jfjallid/go-smb/smb"
)

// Share is one offered SMB share. Disk shares require VFS to be non-nil; for
// Pipe shares VFS is ignored (named-pipe traffic flows over CreateContexts /
// IoCtl, handled separately). Print shares are not supported.
type Share struct {
	// Name is the wire-visible share name (case-insensitive at lookup).
	Name string
	// Type is one of smb.ShareTypeDisk / ShareTypePipe / ShareTypePrint.
	Type byte
	// Remark is a free-form description (not currently advertised; reserved
	// for future use by share-enumeration RPCs).
	Remark string
	// VFS is the pluggable filesystem for Disk shares. Required for Disk;
	// must be nil for Pipe.
	VFS VFS
	// EncryptData advertises ShareFlagEncryptData on this share. After the
	// TreeConnect reply lands, the server rejects every plaintext PDU
	// against the tree with STATUS_ACCESS_DENIED (MS-SMB2 §3.3.5.2.11).
	// The TreeConnect itself is permitted plaintext — the client uses the
	// flag in the reply to switch to encrypted operation. Requires the
	// server config to have EncryptionSupported (or RequireEncryption) and
	// the negotiated dialect ≥ 3.0; otherwise this flag is meaningless.
	EncryptData bool
	// Capabilities is OR'd into TreeConnectRes.Capabilities. The server will
	// add ShareCap defaults (e.g. nothing) on top.
	Capabilities uint32
	// MaximalAccess is the access mask returned in TreeConnectRes. Clients
	// (notably Windows Explorer) inspect this to gate UI affordances. Default
	// to FILE_ALL_ACCESS / 0x001f01ff if zero.
	MaximalAccess uint32

	// WritableUsers, when non-nil, restricts write access on this share to
	// the lower-cased usernames mapped to true. A nil map means every
	// authenticated (non-guest, non-null) user has write access — the
	// historical default. An empty (non-nil) map disables write for every
	// authenticated user, which combined with the anonymous/guest flags
	// below yields a fully read-only share.
	//
	// Guest and null (anonymous) sessions ignore this map and consult
	// GuestWritable / AnonymousWritable instead.
	WritableUsers map[string]bool

	// AnonymousWritable allows null sessions (SessionFlagIsNull, established
	// via ServerConfig.AllowAnonymous) to write. Default false: anonymous
	// users get read-only access on shares that grant them tree-connect.
	AnonymousWritable bool

	// GuestWritable allows guest sessions (SessionFlagIsGuest, established
	// via ServerConfig.AllowGuest) to write. Default false: guests get
	// read-only access.
	GuestWritable bool
}

// UserCanWrite reports whether sess has write access on this share. The
// rules are:
//   - null (anonymous) session: AnonymousWritable
//   - guest session: GuestWritable
//   - authenticated session, WritableUsers == nil: true (default)
//   - authenticated session, WritableUsers != nil: WritableUsers[lower(user)]
func (sh *Share) UserCanWrite(sess *Session) bool {
	if sess == nil {
		return false
	}
	if sess.Flags&smb.SessionFlagIsNull != 0 {
		return sh.AnonymousWritable
	}
	if sess.Flags&smb.SessionFlagIsGuest != 0 {
		return sh.GuestWritable
	}
	if sh.WritableUsers == nil {
		return true
	}
	return sh.WritableUsers[strings.ToLower(sess.Username)]
}

// RegisterShare adds or replaces a share in Config.Shares. Convenience for
// callers who don't want to allocate the map themselves.
func (s *Server) RegisterShare(name string, share Share) {
	if s.Config == nil {
		s.Config = &ServerConfig{}
	}
	if s.Config.Shares == nil {
		s.Config.Shares = make(map[string]Share)
	}
	share.Name = name
	s.Config.Shares[strings.ToLower(name)] = share
}

// RegisterAliasedShares registers the same Share under multiple names so
// one VFS instance is exposed under each alias. Each registration gets its
// own Share value (Name is set per-alias), but VFS / Capabilities /
// MaximalAccess / EncryptData are shared by reference.
func (s *Server) RegisterAliasedShares(names []string, share Share) {
	for _, n := range names {
		s.RegisterShare(n, share)
	}
}

// lookupShare returns the configured Share for name (case-insensitive). The
// IPC$ share is auto-provided as a Pipe if not explicitly registered, since
// most clients open it before the user-facing share for SRVSVC / WKSSVC.
func (cfg *ServerConfig) lookupShare(name string) (Share, bool) {
	if cfg != nil && cfg.Shares != nil {
		if s, ok := cfg.Shares[strings.ToLower(name)]; ok {
			return s, true
		}
	}
	if strings.EqualFold(name, "IPC$") {
		return Share{Name: "IPC$", Type: smb.ShareTypePipe}, true
	}
	return Share{}, false
}

// Tree is the per-(SMB)session-per-share state established by TreeConnect.
// A successful TreeConnect adds a Tree to Session.trees; TreeDisconnect (or
// session/connection teardown) removes it after closing any open handles.
type Tree struct {
	ID    uint32
	Share Share

	mu      sync.Mutex
	handles map[uint64]Handle // volatile FileId -> handle
	// nextHandleID is allocated lazily as Create assigns volatile IDs.
	nextHandleID uint64
	// dirEnums caches the directory listing and cursor for each open
	// directory handle so successive QueryDirectory calls (including those
	// with SMB2_RETURN_SINGLE_ENTRY) can paginate without re-asking the VFS.
	// Keyed by the same volatile FileId as handles. See querydir.go.
	dirEnums map[uint64]*dirEnum
}

// addTree allocates a new Tree on the session and returns it. Tree IDs start
// at 1; zero is reserved for "no tree" (e.g. Negotiate / SessionSetup PDUs).
func (s *Session) addTree(share Share) *Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trees == nil {
		s.trees = make(map[uint32]*Tree)
		s.nextTreeID = 1
	}
	id := s.nextTreeID
	s.nextTreeID++
	t := &Tree{ID: id, Share: share}
	s.trees[id] = t
	return t
}

func (s *Session) tree(id uint32) *Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trees == nil {
		return nil
	}
	return s.trees[id]
}

func (s *Session) removeTree(id uint32) *Tree {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trees == nil {
		return nil
	}
	t := s.trees[id]
	delete(s.trees, id)
	return t
}
