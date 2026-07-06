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

// Package memvfs provides a reference in-memory implementation of the
// smb/server VFS interface. It is intended for tests and small honeypot
// deployments — not as a production file backend.
package memvfs

import (
	"context"
	"encoding/binary"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/server/memvfs").SetDisplayName("memvfs")

// Options configures a new in-memory FS.
type Options struct {
	// ReadOnly causes any mutating operation (Create-of-new, Write,
	// truncate, rename, delete-on-close, timestamp updates) to fail with
	// STATUS_ACCESS_DENIED. The seeded contents (populated directly via
	// FS internals or by tests) remain readable.
	ReadOnly bool
}

// FS is an in-memory filesystem. The zero value is not usable; use New().
type FS struct {
	mu       sync.RWMutex
	nodes    map[string]*node // key: lower-cased "\"-separated path; "" is root.
	now      func() time.Time // override for tests
	readOnly bool
}

// New returns a fresh, empty filesystem with a single root directory.
func New(opts Options) *FS {
	fs := &FS{
		nodes:    make(map[string]*node),
		readOnly: opts.ReadOnly,
	}
	now := time.Now()
	fs.nodes[""] = &node{
		name:           "",
		isDir:          true,
		creationTime:   now,
		lastAccessTime: now,
		lastWriteTime:  now,
		changeTime:     now,
	}
	return fs
}

type node struct {
	name           string // case-preserving display name
	isDir          bool
	data           []byte
	creationTime   time.Time
	lastAccessTime time.Time
	lastWriteTime  time.Time
	changeTime     time.Time
	deletePending  bool
}

func (fs *FS) clock() time.Time {
	if fs.now != nil {
		return fs.now()
	}
	return time.Now()
}

// normPath returns the lower-cased canonical key for a wire-style path.
func normPath(p server.Path) string {
	p = strings.Trim(p, "\\")
	for strings.Contains(p, "\\\\") {
		p = strings.ReplaceAll(p, "\\\\", "\\")
	}
	return strings.ToLower(p)
}

// parentOf returns the directory key containing key, or "" for top-level keys.
func parentOf(key string) string {
	idx := strings.LastIndex(key, "\\")
	if idx < 0 {
		return ""
	}
	return key[:idx]
}

// handle is the in-tree implementation of server.Handle.
type handle struct {
	fs      *FS
	key     string
	display string // case-preserving relative path
	dir     bool

	// dirScanned tracks whether QueryDirectory has been called on this
	// handle since open / RestartScans. Stateful enumeration so the client
	// terminates the "loop until empty" scan after the first batch.
	dirScanned bool
}

func (h *handle) Path() server.Path { return h.display }
func (h *handle) IsDir() bool       { return h.dir }
func (h *handle) Stat() (server.FileInfo, error) {
	h.fs.mu.RLock()
	defer h.fs.mu.RUnlock()
	n, ok := h.fs.nodes[h.key]
	if !ok {
		return server.FileInfo{}, nil
	}
	return n.fileInfo(), nil
}

func (n *node) fileInfo() server.FileInfo {
	attrs := uint32(0x00000080) // FILE_ATTRIBUTE_NORMAL
	if n.isDir {
		attrs = 0x00000010 // FILE_ATTRIBUTE_DIRECTORY
	}
	return server.FileInfo{
		Name:           n.name,
		Size:           int64(len(n.data)),
		AllocationSize: int64(len(n.data)),
		Attributes:     attrs,
		CreationTime:   n.creationTime,
		LastAccessTime: n.lastAccessTime,
		LastWriteTime:  n.lastWriteTime,
		ChangeTime:     n.changeTime,
	}
}

// Create implements server.VFS.
func (fs *FS) Create(ctx context.Context, sess *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	key := normPath(req.Path)
	display := strings.Trim(req.Path, "\\")

	log.Debugf("memvfs Create: path=%q disposition=%d options=0x%08x readOnly=%v",
		display, req.CreateDisposition, req.CreateOptions, fs.readOnly)

	// Reject names that traverse out of the share via "..".
	for _, part := range strings.Split(key, "\\") {
		if part == ".." {
			log.Debugf("memvfs Create %q: contains '..' -> StatusObjectNameInvalid", display)
			return server.CreateResult{}, smb.StatusObjectNameInvalid, nil
		}
	}

	wantDir := req.CreateOptions&smb.FileDirectoryFile != 0
	wantFile := req.CreateOptions&smb.FileNonDirectoryFile != 0

	existing, exists := fs.nodes[key]
	switch req.CreateDisposition {
	case smb.FileOpen:
		if !exists {
			log.Debugf("memvfs Create %q: FileOpen but path does not exist -> StatusObjectNameNotFound", display)
			return server.CreateResult{}, smb.StatusObjectNameNotFound, nil
		}
	case smb.FileCreate:
		if exists {
			log.Debugf("memvfs Create %q: FileCreate but path exists -> StatusObjectNameCollision", display)
			return server.CreateResult{}, smb.StatusObjectNameCollision, nil
		}
	case smb.FileOpenIf:
		// open if exists, create otherwise — fine either way
	case smb.FileSupersede, smb.FileOverwriteIf:
		// create or overwrite
	case smb.FileOverwrite:
		if !exists {
			log.Debugf("memvfs Create %q: FileOverwrite but path does not exist -> StatusObjectNameNotFound", display)
			return server.CreateResult{}, smb.StatusObjectNameNotFound, nil
		}
	default:
		log.Debugf("memvfs Create %q: unknown disposition=%d -> StatusInvalidParameter", display, req.CreateDisposition)
		return server.CreateResult{}, smb.StatusInvalidParameter, nil
	}

	if fs.readOnly {
		switch req.CreateDisposition {
		case smb.FileSupersede, smb.FileOverwrite, smb.FileOverwriteIf, smb.FileCreate:
			log.Debugf("memvfs Create %q: read-only FS rejects mutating disposition=%d -> StatusAccessDenied",
				display, req.CreateDisposition)
			return server.CreateResult{}, smb.StatusAccessDenied, nil
		case smb.FileOpenIf:
			if !exists {
				log.Debugf("memvfs Create %q: read-only FS, FileOpenIf would create -> StatusAccessDenied", display)
				return server.CreateResult{}, smb.StatusAccessDenied, nil
			}
		}
		if req.CreateOptions&smb.FileDeleteOnClose != 0 {
			log.Debugf("memvfs Create %q: read-only FS rejects FileDeleteOnClose -> StatusAccessDenied", display)
			return server.CreateResult{}, smb.StatusAccessDenied, nil
		}
	}

	if exists {
		if wantDir && !existing.isDir {
			log.Debugf("memvfs Create %q: caller wants directory but node is a file -> StatusNotADirectory", display)
			return server.CreateResult{}, smb.StatusNotADirectory, nil
		}
		if wantFile && existing.isDir {
			log.Debugf("memvfs Create %q: caller wants file but node is a directory -> StatusFileIsADirectory", display)
			return server.CreateResult{}, smb.StatusFileIsADirectory, nil
		}
		var action uint32
		switch req.CreateDisposition {
		case smb.FileSupersede:
			existing.data = nil
			existing.lastWriteTime = fs.clock()
			existing.changeTime = existing.lastWriteTime
			action = smb.FileSuperseded
		case smb.FileOverwrite, smb.FileOverwriteIf:
			existing.data = nil
			existing.lastWriteTime = fs.clock()
			existing.changeTime = existing.lastWriteTime
			action = smb.FileOverwritten
		default:
			action = smb.FileOpened
		}
		if req.CreateOptions&smb.FileDeleteOnClose == smb.FileDeleteOnClose {
			existing.deletePending = true
		}
		h := &handle{fs: fs, key: key, display: display, dir: existing.isDir}
		return server.CreateResult{Handle: h, CreateAction: action, Info: existing.fileInfo()}, smb.StatusOk, nil
	}

	// Need to create. Verify parent exists & is a dir.
	parent := parentOf(key)
	if parent != "" {
		p, ok := fs.nodes[parent]
		if !ok {
			log.Debugf("memvfs Create %q: parent %q does not exist -> StatusObjectPathNotFound", display, parent)
			return server.CreateResult{}, smb.StatusObjectPathNotFound, nil
		}
		if !p.isDir {
			log.Debugf("memvfs Create %q: parent %q is not a directory -> StatusNotADirectory", display, parent)
			return server.CreateResult{}, smb.StatusNotADirectory, nil
		}
	}

	now := fs.clock()
	n := &node{
		name:           baseOfDisplay(display),
		isDir:          wantDir,
		creationTime:   now,
		lastAccessTime: now,
		lastWriteTime:  now,
		changeTime:     now,
	}
	fs.nodes[key] = n
	h := &handle{fs: fs, key: key, display: display, dir: n.isDir}
	return server.CreateResult{Handle: h, CreateAction: smb.FileCreated, Info: n.fileInfo()}, smb.StatusOk, nil
}

func baseOfDisplay(display string) string {
	idx := strings.LastIndex(display, "\\")
	if idx < 0 {
		return display
	}
	return display[idx+1:]
}

// Close implements server.VFS. Honors delete-pending if set via SetFileInfo.
func (fs *FS) Close(ctx context.Context, h server.Handle) error {
	hd, ok := h.(*handle)
	if !ok {
		return nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.nodes[hd.key]
	if !ok {
		return nil
	}
	if n.deletePending {
		delete(fs.nodes, hd.key)
	}
	return nil
}

// Read implements server.VFS.
func (fs *FS) Read(ctx context.Context, h server.Handle, offset int64, buf []byte) (int, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("memvfs Read: handle is not a memvfs handle (%T) -> StatusInvalidParameter", h)
		return 0, smb.StatusInvalidParameter, nil
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()
	n, ok := fs.nodes[hd.key]
	if !ok {
		log.Debugf("memvfs Read %q: node disappeared -> StatusObjectNameNotFound", hd.display)
		return 0, smb.StatusObjectNameNotFound, nil
	}
	if n.isDir {
		log.Debugf("memvfs Read %q: handle is directory -> StatusFileIsADirectory", hd.display)
		return 0, smb.StatusFileIsADirectory, nil
	}
	if offset < 0 || offset >= int64(len(n.data)) {
		return 0, smb.StatusOk, nil
	}
	copied := copy(buf, n.data[offset:])
	return copied, smb.StatusOk, nil
}

// Write implements server.VFS.
func (fs *FS) Write(ctx context.Context, h server.Handle, offset int64, data []byte) (int, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("memvfs Write: handle is not a memvfs handle (%T) -> StatusInvalidParameter", h)
		return 0, smb.StatusInvalidParameter, nil
	}
	if fs.readOnly {
		log.Debugf("memvfs Write %q: read-only FS -> StatusAccessDenied", hd.display)
		return 0, smb.StatusAccessDenied, nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.nodes[hd.key]
	if !ok {
		log.Debugf("memvfs Write %q: node disappeared -> StatusObjectNameNotFound", hd.display)
		return 0, smb.StatusObjectNameNotFound, nil
	}
	if n.isDir {
		log.Debugf("memvfs Write %q: handle is directory -> StatusFileIsADirectory", hd.display)
		return 0, smb.StatusFileIsADirectory, nil
	}
	end := offset + int64(len(data))
	if int64(len(n.data)) < end {
		grown := make([]byte, end)
		copy(grown, n.data)
		n.data = grown
	}
	copy(n.data[offset:], data)
	now := fs.clock()
	n.lastWriteTime = now
	n.changeTime = now
	return len(data), smb.StatusOk, nil
}

// Flush implements server.VFS — no-op for an in-memory backend.
func (fs *FS) Flush(ctx context.Context, h server.Handle) (uint32, error) {
	return smb.StatusOk, nil
}

// QueryFileInfo defers to the server's default Stat()-driven path for the
// classes the server understands.
func (fs *FS) QueryFileInfo(ctx context.Context, h server.Handle, infoClass byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// SetFileInfo handles a small set of SET_INFO classes:
//
//   - FileEndOfFileInformation (0x14): truncate or grow the file.
//   - FileDispositionInformation (0x0d): mark for delete-on-close.
//   - FileBasicInformation (0x04): update timestamps and attributes.
//   - FileRenameInformation (0x0a): atomic rename within the FS.
func (fs *FS) SetFileInfo(ctx context.Context, h server.Handle, infoClass byte, raw []byte) (uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("memvfs SetFileInfo: handle is not a memvfs handle (%T) -> StatusInvalidParameter", h)
		return smb.StatusInvalidParameter, nil
	}
	if fs.readOnly {
		log.Debugf("memvfs SetFileInfo %q class=0x%02x: read-only FS -> StatusAccessDenied", hd.display, infoClass)
		return smb.StatusAccessDenied, nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n, ok := fs.nodes[hd.key]
	if !ok {
		log.Debugf("memvfs SetFileInfo %q: node disappeared -> StatusObjectNameNotFound", hd.display)
		return smb.StatusObjectNameNotFound, nil
	}
	log.Debugf("memvfs SetFileInfo %q class=0x%02x rawLen=%d", hd.display, infoClass, len(raw))

	switch infoClass {
	case smb.FileEndOfFileInformation: // 0x14
		if len(raw) < 8 {
			return smb.StatusInfoLengthMismatch, nil
		}
		newSize := int64(binary.LittleEndian.Uint64(raw[:8]))
		if newSize < 0 {
			return smb.StatusInvalidParameter, nil
		}
		if int64(len(n.data)) == newSize {
			return smb.StatusOk, nil
		}
		grown := make([]byte, newSize)
		copy(grown, n.data)
		n.data = grown
		now := fs.clock()
		n.lastWriteTime = now
		n.changeTime = now
		return smb.StatusOk, nil

	case smb.FileDispositionInformation: // 0x0d
		if len(raw) < 1 {
			return smb.StatusInfoLengthMismatch, nil
		}
		n.deletePending = raw[0] != 0
		if n.isDir && n.deletePending {
			// Refuse to delete-on-close a non-empty directory.
			prefix := hd.key + "\\"
			for k := range fs.nodes {
				if strings.HasPrefix(k, prefix) {
					n.deletePending = false
					return smb.StatusDirectoryNotEmpty, nil
				}
			}
		}
		return smb.StatusOk, nil

	case smb.FileBasicInformation: // 0x04
		if len(raw) < 36 {
			return smb.StatusInfoLengthMismatch, nil
		}
		applyTime := func(off int, dst *time.Time) {
			ft := binary.LittleEndian.Uint64(raw[off:])
			if ft == 0 || ft == 0xFFFFFFFFFFFFFFFF {
				return // 0 / -1 mean "do not change" per MS-FSCC
			}
			*dst = fileTimeToTime(ft)
		}
		applyTime(0, &n.creationTime)
		applyTime(8, &n.lastAccessTime)
		applyTime(16, &n.lastWriteTime)
		applyTime(24, &n.changeTime)
		// Attributes at offset 32; ignore for now (memvfs tracks dir vs file)
		return smb.StatusOk, nil

	case smb.FileRenameInformation: // 0x0a
		// Layout: ReplaceIfExists(1) + Reserved(7) + RootDirectory(8)
		// + FileNameLength(4) + FileName(*)
		if len(raw) < 20 {
			return smb.StatusInfoLengthMismatch, nil
		}
		replace := raw[0] != 0
		nameLen := binary.LittleEndian.Uint32(raw[16:20])
		if int(nameLen)+20 > len(raw) {
			return smb.StatusInfoLengthMismatch, nil
		}
		newDisplay, err := encoder.FromUnicodeString(raw[20 : 20+nameLen])
		if err != nil {
			log.Debugf("memvfs SetFileInfo rename: decode new name: %v -> StatusInvalidParameter", err)
			return smb.StatusInvalidParameter, nil
		}
		newDisplay = strings.Trim(newDisplay, "\\")
		newKey := strings.ToLower(newDisplay)
		if _, exists := fs.nodes[newKey]; exists {
			if !replace {
				return smb.StatusObjectNameCollision, nil
			}
			delete(fs.nodes, newKey)
		}
		// Move all descendants if it's a directory.
		if n.isDir {
			oldPrefix := hd.key + "\\"
			newPrefix := newKey + "\\"
			for k, v := range fs.nodes {
				if strings.HasPrefix(k, oldPrefix) {
					fs.nodes[newPrefix+k[len(oldPrefix):]] = v
					delete(fs.nodes, k)
				}
			}
		}
		delete(fs.nodes, hd.key)
		n.name = baseOfDisplay(newDisplay)
		fs.nodes[newKey] = n
		hd.key = newKey
		hd.display = newDisplay
		now := fs.clock()
		n.changeTime = now
		return smb.StatusOk, nil
	}
	return smb.StatusNotSupported, nil
}

// fileTimeToTime converts a Windows FILETIME to a time.Time.
func fileTimeToTime(ft uint64) time.Time {
	// 100-nanosecond intervals since 1601-01-01 UTC.
	const epochDelta = 116444736000000000 // FILETIME ticks at Unix epoch
	if ft < epochDelta {
		return time.Time{}
	}
	unixNano := int64(ft-epochDelta) * 100
	return time.Unix(unixNano/1e9, unixNano%1e9).UTC()
}

// QueryDirectory enumerates direct children of the directory handle. The
// pattern argument is interpreted with simple "*" globbing; anything else is
// matched case-insensitively against the entry name.
func (fs *FS) QueryDirectory(ctx context.Context, h server.Handle, pattern string, restart bool) ([]server.DirEntry, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("memvfs QueryDirectory: handle is not a memvfs handle (%T) -> StatusInvalidParameter", h)
		return nil, smb.StatusInvalidParameter, nil
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	dirNode, ok := fs.nodes[hd.key]
	if !ok {
		log.Debugf("memvfs QueryDirectory %q: node disappeared -> StatusObjectNameNotFound", hd.display)
		return nil, smb.StatusObjectNameNotFound, nil
	}
	if !dirNode.isDir {
		log.Debugf("memvfs QueryDirectory %q: handle is not a directory -> StatusNotADirectory", hd.display)
		return nil, smb.StatusNotADirectory, nil
	}
	log.Debugf("memvfs QueryDirectory %q pattern=%q restart=%v", hd.display, pattern, restart)

	if restart {
		hd.dirScanned = false
	}
	if hd.dirScanned {
		return nil, smb.StatusOk, nil
	}
	hd.dirScanned = true

	prefix := hd.key
	if prefix != "" {
		prefix += "\\"
	}

	var entries []server.DirEntry
	addEntry := func(name string, n *node) {
		if !matchesPattern(name, pattern) {
			return
		}
		fi := n.fileInfo()
		fi.Name = name
		entries = append(entries, server.DirEntry{FileInfo: fi})
	}

	// Synthesize "." and ".." so Windows clients see a normal listing.
	dotInfo := server.FileInfo{
		Name:           ".",
		Attributes:     0x00000010,
		CreationTime:   dirNode.creationTime,
		LastAccessTime: dirNode.lastAccessTime,
		LastWriteTime:  dirNode.lastWriteTime,
		ChangeTime:     dirNode.changeTime,
	}
	if matchesPattern(".", pattern) {
		entries = append(entries, server.DirEntry{FileInfo: dotInfo})
	}
	if matchesPattern("..", pattern) {
		dotdot := dotInfo
		dotdot.Name = ".."
		entries = append(entries, server.DirEntry{FileInfo: dotdot})
	}

	// Direct children only.
	for k, n := range fs.nodes {
		if k == hd.key {
			continue
		}
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		rest := k[len(prefix):]
		if strings.Contains(rest, "\\") {
			continue
		}
		addEntry(n.name, n)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, smb.StatusOk, nil
}

// matchesPattern is a tiny case-insensitive glob: "*" matches anything,
// otherwise exact name match. Adequate for memvfs.
func matchesPattern(name, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return strings.EqualFold(name, pattern)
}

// QueryFSInfo defers to the server's default for now.
func (fs *FS) QueryFSInfo(ctx context.Context, infoClass byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// QuerySecurity returns world-readable via the server default.
func (fs *FS) QuerySecurity(ctx context.Context, h server.Handle, addInfo uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// Ioctl is unimplemented for memvfs.
func (fs *FS) Ioctl(ctx context.Context, h server.Handle, code uint32, in []byte, maxOut uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// Compile-time assertion that *FS satisfies server.VFS.
var _ server.VFS = (*FS)(nil)
