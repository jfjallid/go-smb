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

// Package filevfs is a file-backed implementation of the smb/server VFS
// interface. It serves a real directory tree from the host filesystem so
// SMB clients can read and write actual files.
//
// Path resolution is case-insensitive (a fallback ReadDir scans the parent
// when a literal lookup misses), traversal via ".." is rejected, and any
// resolved path that escapes the share root through symlinks is denied.
package filevfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/server/filevfs").SetDisplayName("filevfs")

// Options configures a new file-backed FS.
type Options struct {
	// Root is the host directory the share serves. It must exist and be a
	// directory. Relative paths are resolved against the current working
	// directory at New() time.
	Root string

	// ReadOnly causes any mutating operation (Create-of-new, Write,
	// truncate, rename, delete-on-close, timestamp updates) to fail with
	// STATUS_ACCESS_DENIED.
	ReadOnly bool
}

// FS is a file-backed filesystem rooted at a host directory.
type FS struct {
	root     string // absolute, cleaned host path of the share root
	rootEval string // EvalSymlinks(root); used for containment checks
	readOnly bool
}

// Default permission bits for files and directories the server creates.
// Group-readable but never world-accessible, matching a typical hardened
// share rather than the process umask default.
const (
	defaultFilePerm os.FileMode = 0o640
	defaultDirPerm  os.FileMode = 0o750
)

// New returns an FS rooted at opts.Root.
func New(opts Options) (*FS, error) {
	if opts.Root == "" {
		return nil, fmt.Errorf("root is required")
	}
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("abs %q: %w", opts.Root, err)
	}
	abs = filepath.Clean(abs)
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("stat root %q: %w", abs, err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("root %q is not a directory", abs)
	}
	eval, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("evalsymlinks %q: %w", abs, err)
	}
	return &FS{
		root:     abs,
		rootEval: filepath.Clean(eval),
		readOnly: opts.ReadOnly,
	}, nil
}

// handle is the in-tree implementation of server.Handle.
type handle struct {
	fs      *FS
	smbPath string // case-corrected, share-relative ("\"-separated)
	osPath  string // absolute host path
	isDir   bool
	file    *os.File // nil for directories

	deletePending bool
	dirScanned    bool
}

func (h *handle) Path() server.Path { return h.smbPath }
func (h *handle) IsDir() bool       { return h.isDir }
func (h *handle) Stat() (server.FileInfo, error) {
	st, err := os.Lstat(h.osPath)
	if err != nil {
		return server.FileInfo{}, err
	}
	return toFileInfo(baseSMB(h.smbPath), st), nil
}

// toFileInfo converts an os.FileInfo to a server.FileInfo. Linux exposes
// only ModTime through os.FileInfo; we reuse it for every timestamp slot
// as a best-effort fill (creation/access/change times are not reliably
// available without per-platform statx calls).
func toFileInfo(name string, st os.FileInfo) server.FileInfo {
	attrs := uint32(0x00000080) // FILE_ATTRIBUTE_NORMAL
	if st.IsDir() {
		attrs = 0x00000010 // FILE_ATTRIBUTE_DIRECTORY
	}
	mt := st.ModTime()
	return server.FileInfo{
		Name:           name,
		Size:           st.Size(),
		AllocationSize: st.Size(),
		Attributes:     attrs,
		CreationTime:   mt,
		LastAccessTime: mt,
		LastWriteTime:  mt,
		ChangeTime:     mt,
	}
}

func baseSMB(p string) string {
	if i := strings.LastIndex(p, "\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// resolved is the result of resolveSMB.
type resolved struct {
	osPath      string      // host path of the leaf (always populated, even if !exists)
	displayPath string      // case-corrected, share-relative SMB path
	exists      bool        // true if the leaf currently exists
	info        os.FileInfo // populated when exists==true
}

// resolveSMB walks an SMB-style "\"-separated path, doing a case-insensitive
// fallback at each component and enforcing share-root containment. The
// returned status is non-zero on rejection; err is reserved for fatal
// host-side failures (e.g. unexpected ReadDir/Lstat errors).
func (fs *FS) resolveSMB(smbPath string) (resolved, uint32, error) {
	clean := strings.Trim(smbPath, "\\")
	for strings.Contains(clean, "\\\\") {
		clean = strings.ReplaceAll(clean, "\\\\", "\\")
	}

	if clean == "" {
		st, err := os.Lstat(fs.root)
		if err != nil {
			log.Errorf("resolveSMB root: Lstat %q: %v", fs.root, err)
			return resolved{}, 0, err
		}
		return resolved{
			osPath:      fs.root,
			displayPath: "",
			exists:      true,
			info:        st,
		}, smb.StatusOk, nil
	}

	parts := strings.Split(clean, "\\")
	for _, p := range parts {
		if p == ".." || p == "" {
			log.Debugf("resolveSMB %q: contains empty or '..' component -> StatusObjectNameInvalid", smbPath)
			return resolved{}, smb.StatusObjectNameInvalid, nil
		}
		// An SMB path component must not embed a host path separator or NUL byte.
		// strings.Split on "\\" can't leave a backslash inside a component, but a
		// forward slash survives, and filepath.Join honours it on Unix — so a
		// single "component" like "a/../../../etc" is not literally ".." yet still
		// escapes the share root once joined. Reject it up front.
		if strings.ContainsAny(p, "/\\\x00") {
			log.Debugf("resolveSMB %q: component %q embeds a separator or NUL -> StatusObjectNameInvalid", smbPath, p)
			return resolved{}, smb.StatusObjectNameInvalid, nil
		}
	}

	currentOS := fs.root
	currentDisplay := ""
	var leafInfo os.FileInfo
	var leafExists bool

	for i, comp := range parts {
		candidate := filepath.Join(currentOS, comp)
		correctedName := comp

		// Use Stat (follows symlinks) so within-root symlinks are
		// transparently traversable. Containment is enforced separately
		// via EvalSymlinks at the end.
		st, err := os.Stat(candidate)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Errorf("resolveSMB: Stat %q: %v", candidate, err)
				return resolved{}, 0, err
			}
			// Case-insensitive scan of parent.
			entries, rderr := os.ReadDir(currentOS)
			if rderr != nil {
				log.Errorf("resolveSMB: ReadDir %q: %v", currentOS, rderr)
				return resolved{}, 0, rderr
			}
			var found os.DirEntry
			for _, e := range entries {
				if strings.EqualFold(e.Name(), comp) {
					found = e
					break
				}
			}
			if found != nil {
				correctedName = found.Name()
				candidate = filepath.Join(currentOS, correctedName)
				st, err = os.Stat(candidate)
				if err != nil {
					log.Errorf("resolveSMB: Stat case-corrected %q: %v", candidate, err)
					return resolved{}, 0, err
				}
			} else {
				// Missing.
				if i == len(parts)-1 {
					if currentDisplay == "" {
						currentDisplay = correctedName
					} else {
						currentDisplay = currentDisplay + "\\" + correctedName
					}
					if status, err := fs.checkContained(currentOS); status != smb.StatusOk || err != nil {
						log.Debugf("resolveSMB %q: parent %q failed containment check status=0x%08x err=%v",
							smbPath, currentOS, status, err)
						return resolved{}, status, err
					}
					// Defense in depth: the leaf does not exist yet (so it can't be
					// symlink-evaluated by checkContained), but it must be a direct
					// child of the already-contained parent. The separator rejection
					// above guarantees this; assert it so a future change can't
					// silently reintroduce an escaping candidate.
					if filepath.Dir(candidate) != currentOS {
						log.Debugf("resolveSMB %q: missing-leaf candidate %q is not a direct child of %q -> StatusObjectNameInvalid",
							smbPath, candidate, currentOS)
						return resolved{}, smb.StatusObjectNameInvalid, nil
					}
					return resolved{
						osPath:      candidate,
						displayPath: currentDisplay,
						exists:      false,
					}, smb.StatusOk, nil
				}
				log.Debugf("resolveSMB %q: intermediate component %q missing -> StatusObjectPathNotFound",
					smbPath, comp)
				return resolved{}, smb.StatusObjectPathNotFound, nil
			}
		}

		if i < len(parts)-1 && !st.IsDir() {
			log.Debugf("resolveSMB %q: component %q is not a directory -> StatusNotADirectory",
				smbPath, comp)
			return resolved{}, smb.StatusNotADirectory, nil
		}

		currentOS = candidate
		if currentDisplay == "" {
			currentDisplay = correctedName
		} else {
			currentDisplay = currentDisplay + "\\" + correctedName
		}
		leafInfo = st
		leafExists = true
	}

	if status, err := fs.checkContained(currentOS); status != smb.StatusOk || err != nil {
		return resolved{}, status, err
	}

	return resolved{
		osPath:      currentOS,
		displayPath: currentDisplay,
		exists:      leafExists,
		info:        leafInfo,
	}, smb.StatusOk, nil
}

// checkContained verifies that hostPath, after symlink evaluation, still
// resides under the share root. hostPath may be an existing leaf or an
// existing directory (e.g. the parent when the leaf doesn't exist yet).
func (fs *FS) checkContained(hostPath string) (uint32, error) {
	eval, err := filepath.EvalSymlinks(hostPath)
	if err != nil {
		log.Errorf("checkContained: EvalSymlinks %q: %v", hostPath, err)
		return 0, err
	}
	eval = filepath.Clean(eval)
	if eval == fs.rootEval {
		return smb.StatusOk, nil
	}
	if !strings.HasPrefix(eval, fs.rootEval+string(filepath.Separator)) {
		log.Debugf("checkContained: %q (eval=%q) escapes share root %q -> StatusAccessDenied",
			hostPath, eval, fs.rootEval)
		return smb.StatusAccessDenied, nil
	}
	return smb.StatusOk, nil
}

// mapOSError best-effort maps a host filesystem error to an NTSTATUS.
func mapOSError(err error) uint32 {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return smb.StatusObjectNameNotFound
	case errors.Is(err, os.ErrExist):
		return smb.StatusObjectNameCollision
	case errors.Is(err, os.ErrPermission):
		return smb.StatusAccessDenied
	default:
		return smb.StatusInvalidParameter
	}
}

// Create implements server.VFS.
func (fs *FS) Create(ctx context.Context, sess *server.Session, req server.CreateRequest) (server.CreateResult, uint32, error) {
	log.Debugf("Create: path=%q disposition=%d options=0x%08x readOnly=%v root=%q",
		req.Path, req.CreateDisposition, req.CreateOptions, fs.readOnly, fs.root)

	res, status, err := fs.resolveSMB(req.Path)
	if err != nil {
		mapped := mapOSError(err)
		log.Debugf("Create %q: resolveSMB error: %v -> 0x%08x", req.Path, err, mapped)
		return server.CreateResult{}, mapped, nil
	}
	if status != smb.StatusOk {
		log.Debugf("Create %q: resolveSMB returned status=0x%08x", req.Path, status)
		return server.CreateResult{}, status, nil
	}

	wantDir := req.CreateOptions&smb.FileDirectoryFile != 0
	wantFile := req.CreateOptions&smb.FileNonDirectoryFile != 0

	switch req.CreateDisposition {
	case smb.FileOpen:
		if !res.exists {
			log.Debugf("Create %q: FileOpen but path does not exist -> StatusObjectNameNotFound", req.Path)
			return server.CreateResult{}, smb.StatusObjectNameNotFound, nil
		}
	case smb.FileCreate:
		if res.exists {
			log.Debugf("Create %q: FileCreate but path exists -> StatusObjectNameCollision", req.Path)
			return server.CreateResult{}, smb.StatusObjectNameCollision, nil
		}
	case smb.FileOpenIf:
	case smb.FileSupersede, smb.FileOverwriteIf:
	case smb.FileOverwrite:
		if !res.exists {
			log.Debugf("Create %q: FileOverwrite but path does not exist -> StatusObjectNameNotFound", req.Path)
			return server.CreateResult{}, smb.StatusObjectNameNotFound, nil
		}
	default:
		log.Debugf("Create %q: unknown disposition=%d -> StatusInvalidParameter", req.Path, req.CreateDisposition)
		return server.CreateResult{}, smb.StatusInvalidParameter, nil
	}

	if fs.readOnly {
		switch req.CreateDisposition {
		case smb.FileSupersede, smb.FileOverwrite, smb.FileOverwriteIf, smb.FileCreate:
			log.Debugf("Create %q: read-only FS rejects mutating disposition=%d -> StatusAccessDenied",
				req.Path, req.CreateDisposition)
			return server.CreateResult{}, smb.StatusAccessDenied, nil
		case smb.FileOpenIf:
			if !res.exists {
				log.Debugf("Create %q: read-only FS, FileOpenIf would create -> StatusAccessDenied", req.Path)
				return server.CreateResult{}, smb.StatusAccessDenied, nil
			}
		}
		if req.CreateOptions&smb.FileDeleteOnClose != 0 {
			log.Debugf("Create %q: read-only FS rejects FileDeleteOnClose -> StatusAccessDenied", req.Path)
			return server.CreateResult{}, smb.StatusAccessDenied, nil
		}
	}

	if res.exists {
		isDir := res.info.IsDir()
		if wantDir && !isDir {
			log.Debugf("Create %q: caller wants directory but %q is a file -> StatusNotADirectory",
				req.Path, res.osPath)
			return server.CreateResult{}, smb.StatusNotADirectory, nil
		}
		if wantFile && isDir {
			log.Debugf("Create %q: caller wants file but %q is a directory -> StatusFileIsADirectory",
				req.Path, res.osPath)
			return server.CreateResult{}, smb.StatusFileIsADirectory, nil
		}

		var action uint32
		switch req.CreateDisposition {
		case smb.FileSupersede:
			action = smb.FileSuperseded
		case smb.FileOverwrite, smb.FileOverwriteIf:
			action = smb.FileOverwritten
		default:
			action = smb.FileOpened
		}

		var f *os.File
		if !isDir {
			flag := os.O_RDWR
			if fs.readOnly {
				flag = os.O_RDONLY
			}
			if action == smb.FileSuperseded || action == smb.FileOverwritten {
				flag |= os.O_TRUNC
			}
			f, err = os.OpenFile(res.osPath, flag, defaultFilePerm)
			if err != nil {
				mapped := mapOSError(err)
				log.Debugf("Create %q: OpenFile %q flag=0x%x: %v -> 0x%08x",
					req.Path, res.osPath, flag, err, mapped)
				return server.CreateResult{}, mapped, nil
			}
		}
		h := &handle{
			fs:      fs,
			smbPath: res.displayPath,
			osPath:  res.osPath,
			isDir:   isDir,
			file:    f,
		}
		if req.CreateOptions&smb.FileDeleteOnClose != 0 {
			h.deletePending = true
		}
		st, err := os.Lstat(res.osPath)
		if err != nil {
			if f != nil {
				f.Close()
			}
			mapped := mapOSError(err)
			log.Debugf("Create %q: post-open Lstat %q: %v -> 0x%08x", req.Path, res.osPath, err, mapped)
			return server.CreateResult{}, mapped, nil
		}
		return server.CreateResult{
			Handle:       h,
			CreateAction: action,
			Info:         toFileInfo(baseSMB(res.displayPath), st),
		}, smb.StatusOk, nil
	}

	// New entry. Parent already verified to exist by resolveSMB.
	var f *os.File
	if wantDir {
		if err = os.Mkdir(res.osPath, defaultDirPerm); err != nil {
			mapped := mapOSError(err)
			log.Debugf("Create %q: Mkdir %q: %v -> 0x%08x", req.Path, res.osPath, err, mapped)
			return server.CreateResult{}, mapped, nil
		}
	} else {
		f, err = os.OpenFile(res.osPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, defaultFilePerm)
		if err != nil {
			mapped := mapOSError(err)
			log.Debugf("Create %q: OpenFile new %q: %v -> 0x%08x", req.Path, res.osPath, err, mapped)
			return server.CreateResult{}, mapped, nil
		}
	}
	h := &handle{
		fs:      fs,
		smbPath: res.displayPath,
		osPath:  res.osPath,
		isDir:   wantDir,
		file:    f,
	}
	if req.CreateOptions&smb.FileDeleteOnClose != 0 {
		h.deletePending = true
	}
	st, err := os.Lstat(res.osPath)
	if err != nil {
		if f != nil {
			f.Close()
		}
		mapped := mapOSError(err)
		log.Debugf("Create %q: post-create Lstat %q: %v -> 0x%08x", req.Path, res.osPath, err, mapped)
		return server.CreateResult{}, mapped, nil
	}
	return server.CreateResult{
		Handle:       h,
		CreateAction: smb.FileCreated,
		Info:         toFileInfo(baseSMB(res.displayPath), st),
	}, smb.StatusOk, nil
}

// Close implements server.VFS. Honors delete-pending if set.
func (fs *FS) Close(ctx context.Context, h server.Handle) error {
	hd, ok := h.(*handle)
	if !ok {
		return nil
	}
	if hd.file != nil {
		if err := hd.file.Close(); err != nil {
			log.Debugf("Close %q: underlying file close: %v", hd.smbPath, err)
		}
		hd.file = nil
	}
	if hd.deletePending {
		// Remove() handles both files and (empty) directories. Non-empty
		// dirs error naturally — matches memvfs's earlier rejection in
		// SetFileInfo.
		if err := os.Remove(hd.osPath); err != nil {
			log.Debugf("Close %q: delete-on-close Remove %q: %v", hd.smbPath, hd.osPath, err)
		}
	}
	return nil
}

// Read implements server.VFS.
func (fs *FS) Read(ctx context.Context, h server.Handle, offset int64, buf []byte) (int, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("Read: handle is not a filevfs handle (%T) -> StatusInvalidParameter", h)
		return 0, smb.StatusInvalidParameter, nil
	}
	if hd.isDir {
		log.Debugf("Read %q: handle is directory -> StatusFileIsADirectory", hd.smbPath)
		return 0, smb.StatusFileIsADirectory, nil
	}
	if hd.file == nil {
		log.Debugf("Read %q: file already closed -> StatusFileClosed", hd.smbPath)
		return 0, smb.StatusFileClosed, nil
	}
	if offset < 0 {
		log.Debugf("Read %q: negative offset %d -> StatusInvalidParameter", hd.smbPath, offset)
		return 0, smb.StatusInvalidParameter, nil
	}
	n, err := hd.file.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		mapped := mapOSError(err)
		log.Debugf("Read %q offset=%d len=%d: %v -> 0x%08x", hd.smbPath, offset, len(buf), err, mapped)
		return n, mapped, nil
	}
	return n, smb.StatusOk, nil
}

// Write implements server.VFS.
func (fs *FS) Write(ctx context.Context, h server.Handle, offset int64, data []byte) (int, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("Write: handle is not a filevfs handle (%T) -> StatusInvalidParameter", h)
		return 0, smb.StatusInvalidParameter, nil
	}
	if fs.readOnly {
		log.Debugf("Write %q: read-only FS -> StatusAccessDenied", hd.smbPath)
		return 0, smb.StatusAccessDenied, nil
	}
	if hd.isDir {
		log.Debugf("Write %q: handle is directory -> StatusFileIsADirectory", hd.smbPath)
		return 0, smb.StatusFileIsADirectory, nil
	}
	if hd.file == nil {
		log.Debugf("Write %q: file already closed -> StatusFileClosed", hd.smbPath)
		return 0, smb.StatusFileClosed, nil
	}
	if offset < 0 {
		log.Debugf("Write %q: negative offset %d -> StatusInvalidParameter", hd.smbPath, offset)
		return 0, smb.StatusInvalidParameter, nil
	}
	n, err := hd.file.WriteAt(data, offset)
	if err != nil {
		mapped := mapOSError(err)
		log.Debugf("Write %q offset=%d len=%d: %v -> 0x%08x", hd.smbPath, offset, len(data), err, mapped)
		return n, mapped, nil
	}
	return n, smb.StatusOk, nil
}

// Flush implements server.VFS.
func (fs *FS) Flush(ctx context.Context, h server.Handle) (uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		return smb.StatusInvalidParameter, nil
	}
	if hd.file == nil {
		return smb.StatusOk, nil
	}
	if err := hd.file.Sync(); err != nil {
		return mapOSError(err), nil
	}
	return smb.StatusOk, nil
}

// QueryFileInfo defers to the server's default Stat()-driven path.
func (fs *FS) QueryFileInfo(ctx context.Context, h server.Handle, infoClass byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// SetFileInfo handles the same classes as memvfs:
//
//   - FileEndOfFileInformation (0x14): truncate or grow the file.
//   - FileDispositionInformation (0x0d): mark for delete-on-close.
//   - FileBasicInformation (0x04): update timestamps.
//   - FileRenameInformation (0x0a): rename within the share.
func (fs *FS) SetFileInfo(ctx context.Context, h server.Handle, infoClass byte, raw []byte) (uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("SetFileInfo: handle is not a filevfs handle (%T) -> StatusInvalidParameter", h)
		return smb.StatusInvalidParameter, nil
	}
	if fs.readOnly {
		log.Debugf("SetFileInfo %q class=0x%02x: read-only FS -> StatusAccessDenied", hd.smbPath, infoClass)
		return smb.StatusAccessDenied, nil
	}
	log.Debugf("SetFileInfo %q class=0x%02x rawLen=%d", hd.smbPath, infoClass, len(raw))

	switch infoClass {
	case smb.FileEndOfFileInformation: // 0x14
		if len(raw) < 8 {
			return smb.StatusInfoLengthMismatch, nil
		}
		newSize := int64(binary.LittleEndian.Uint64(raw[:8]))
		if newSize < 0 {
			return smb.StatusInvalidParameter, nil
		}
		if hd.file == nil {
			return smb.StatusInvalidParameter, nil
		}
		if err := hd.file.Truncate(newSize); err != nil {
			return mapOSError(err), nil
		}
		return smb.StatusOk, nil

	case smb.FileDispositionInformation: // 0x0d
		if len(raw) < 1 {
			return smb.StatusInfoLengthMismatch, nil
		}
		want := raw[0] != 0
		if want && hd.isDir {
			entries, err := os.ReadDir(hd.osPath)
			if err != nil {
				return mapOSError(err), nil
			}
			if len(entries) > 0 {
				return smb.StatusDirectoryNotEmpty, nil
			}
		}
		hd.deletePending = want
		return smb.StatusOk, nil

	case smb.FileBasicInformation: // 0x04
		if len(raw) < 36 {
			return smb.StatusInfoLengthMismatch, nil
		}
		// FILETIME slots: creation(0), lastAccess(8), lastWrite(16), change(24).
		// Linux only supports atime + mtime via Chtimes; the others are silently ignored.
		st, err := os.Lstat(hd.osPath)
		if err != nil {
			return mapOSError(err), nil
		}
		atime := st.ModTime()
		mtime := st.ModTime()
		applyTime := func(off int, dst *time.Time) {
			ft := binary.LittleEndian.Uint64(raw[off:])
			if ft == 0 || ft == 0xFFFFFFFFFFFFFFFF {
				return
			}
			*dst = fileTimeToTime(ft)
		}
		applyTime(8, &atime)
		applyTime(16, &mtime)
		if err := os.Chtimes(hd.osPath, atime, mtime); err != nil {
			return mapOSError(err), nil
		}
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
			return smb.StatusInvalidParameter, nil
		}
		newDisplay = strings.Trim(newDisplay, "\\")
		newRes, status, rerr := fs.resolveSMB(newDisplay)
		if rerr != nil {
			return mapOSError(rerr), nil
		}
		if status != smb.StatusOk {
			return status, nil
		}
		if newRes.exists {
			if !replace {
				return smb.StatusObjectNameCollision, nil
			}
			if err := os.Remove(newRes.osPath); err != nil {
				return mapOSError(err), nil
			}
		}
		if err := os.Rename(hd.osPath, newRes.osPath); err != nil {
			return mapOSError(err), nil
		}
		hd.osPath = newRes.osPath
		hd.smbPath = newRes.displayPath
		return smb.StatusOk, nil
	}
	return smb.StatusNotSupported, nil
}

// fileTimeToTime converts a Windows FILETIME to a time.Time.
func fileTimeToTime(ft uint64) time.Time {
	const epochDelta = 116444736000000000 // FILETIME ticks at the Unix epoch
	if ft < epochDelta {
		return time.Time{}
	}
	unixNano := int64(ft-epochDelta) * 100
	return time.Unix(unixNano/1e9, unixNano%1e9).UTC()
}

// QueryDirectory enumerates direct children of the directory handle.
func (fs *FS) QueryDirectory(ctx context.Context, h server.Handle, pattern string, restart bool) ([]server.DirEntry, uint32, error) {
	hd, ok := h.(*handle)
	if !ok {
		log.Debugf("QueryDirectory: handle is not a filevfs handle (%T) -> StatusInvalidParameter", h)
		return nil, smb.StatusInvalidParameter, nil
	}
	if !hd.isDir {
		log.Debugf("QueryDirectory %q: handle is not a directory -> StatusNotADirectory", hd.smbPath)
		return nil, smb.StatusNotADirectory, nil
	}
	log.Debugf("QueryDirectory %q pattern=%q restart=%v", hd.smbPath, pattern, restart)
	if restart {
		hd.dirScanned = false
	}
	if hd.dirScanned {
		return nil, smb.StatusOk, nil
	}
	hd.dirScanned = true

	dirSt, err := os.Lstat(hd.osPath)
	if err != nil {
		mapped := mapOSError(err)
		log.Debugf("QueryDirectory %q: Lstat %q: %v -> 0x%08x", hd.smbPath, hd.osPath, err, mapped)
		return nil, mapped, nil
	}

	rawEntries, err := os.ReadDir(hd.osPath)
	if err != nil {
		mapped := mapOSError(err)
		log.Debugf("QueryDirectory %q: ReadDir %q: %v -> 0x%08x", hd.smbPath, hd.osPath, err, mapped)
		return nil, mapped, nil
	}

	var entries []server.DirEntry
	if matchesPattern(".", pattern) {
		fi := toFileInfo(".", dirSt)
		entries = append(entries, server.DirEntry{FileInfo: fi})
	}
	if matchesPattern("..", pattern) {
		fi := toFileInfo("..", dirSt)
		entries = append(entries, server.DirEntry{FileInfo: fi})
	}
	for _, e := range rawEntries {
		name := e.Name()
		if !matchesPattern(name, pattern) {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		entries = append(entries, server.DirEntry{FileInfo: toFileInfo(name, st)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, smb.StatusOk, nil
}

// matchesPattern: "*" matches anything, otherwise case-insensitive exact match.
func matchesPattern(name, pattern string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return strings.EqualFold(name, pattern)
}

// QueryFSInfo defers to the server's default.
func (fs *FS) QueryFSInfo(ctx context.Context, infoClass byte) (any, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// QuerySecurity defers to the server's world-readable default.
func (fs *FS) QuerySecurity(ctx context.Context, h server.Handle, addInfo uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

// Ioctl is not implemented for filevfs.
func (fs *FS) Ioctl(ctx context.Context, h server.Handle, code uint32, in []byte, maxOut uint32) ([]byte, uint32, error) {
	return nil, smb.StatusNotSupported, nil
}

var _ server.VFS = (*FS)(nil)
