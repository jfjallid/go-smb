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
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// handleQueryDirectory enumerates a directory handle. Supported info classes
// cover what Windows clients request via the various Find/Enumerate APIs.
// Any other class returns StatusInvalidParameter rather than silently emitting
// the wrong layout.
func (c *Conn) handleQueryDirectory(ctx pduCtx, raw []byte, h *smb.Header) error {
	logger := c.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("QueryDirectory: session %d not authenticated -> StatusUserSessionDeleted", h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("QueryDirectory: unknown TreeID %d -> StatusNetworkNameDeleted", h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}
	var req smb.QueryDirectoryReq
	if err := req.UnmarshalBinary(raw); err != nil {
		logger.Errorf("QueryDirectory: decode QueryDirectoryReq: %v", err)
		return formatErr("decode QueryDirectoryReq", err)
	}
	hndl := tree.lookupHandle(volatileFromFileID(req.FileID))
	if hndl == nil {
		logger.Debugf("QueryDirectory from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed",
			c.RemoteAddr, tree.ID, volatileFromFileID(req.FileID))
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	pattern, err := encoder.FromUnicodeString(req.Buffer)
	if err != nil {
		logger.Debugf("QueryDirectory: decode search pattern: %v (defaulting to *)", err)
	}
	if pattern == "" {
		pattern = "*"
	}
	restart := req.Flags&smb.RestartScans != 0
	singleEntry := req.Flags&smb.ReturnSingleEntry != 0
	volatile := volatileFromFileID(req.FileID)
	logger.Debugf("QueryDirectory from %s: class=0x%02x flags=0x%02x pattern=%q outBuf=%d fileIndex=%d",
		c.RemoteAddr, req.FileInformationClass, req.Flags, pattern, req.OutputBufferLength, req.FileIndex)

	// Iteration state lives on the Tree, not in the VFS, so that
	// SMB2_RETURN_SINGLE_ENTRY (and any future small-batch enumeration)
	// works against any VFS that just snapshots a full listing.
	dEnum := tree.getDirEnum(volatile)
	if restart || dEnum == nil {
		// Force a fresh snapshot from the VFS. Pass restart=true so VFSes
		// that maintain their own dirScanned flag re-emit entries.
		entries, status, err := tree.Share.VFS.QueryDirectory(context.Background(), hndl, pattern, true)
		if err != nil {
			logger.Errorf("VFS.QueryDirectory pattern=%q: %v", pattern, err)
			return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
		if status != smb.StatusOk {
			logger.Debugf("QueryDirectory from %s: VFS returned status=0x%08x for pattern=%q",
				c.RemoteAddr, status, pattern)
			return c.writeRawError(ctx, h, status)
		}
		dEnum = &dirEnum{entries: entries}
		tree.setDirEnum(volatile, dEnum)
	}

	if dEnum.cursor >= len(dEnum.entries) {
		logger.Debugf("QueryDirectory from %s: cursor=%d at end of %d entries -> StatusNoMoreFiles",
			c.RemoteAddr, dEnum.cursor, len(dEnum.entries))
		return c.writeRawError(ctx, h, smb.StatusNoMoreFiles)
	}

	// Slice the cached entries from the cursor; SMB2_RETURN_SINGLE_ENTRY
	// caps the slice to one. serializeDirEntries then bounds further by
	// OutputBufferLength and reports how many actually fit.
	slice := dEnum.entries[dEnum.cursor:]
	if singleEntry && len(slice) > 1 {
		slice = slice[:1]
	}

	buf, consumed, err := serializeDirEntries(req.FileInformationClass, slice, req.OutputBufferLength)
	if err != nil {
		logger.Errorf("QueryDirectory: serializeDirEntries class=0x%02x: %v", req.FileInformationClass, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	if consumed == 0 {
		// Nothing fit in the buffer — this is an error condition the client
		// can recover from by sending a larger OutputBufferLength.
		return c.writeRawError(ctx, h, smb.StatusInfoLengthMismatch)
	}
	dEnum.cursor += consumed

	res := smb.QueryDirectoryRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandQueryDirectory),
		StructureSize: 9,
		Buffer:        buf,
	}
	res.Header.TreeID = h.TreeID
	return c.writeReply(ctx, &res)
}

// dirEnum holds the cached directory listing and current cursor for a single
// open directory handle. Iteration is server-side so it works against any VFS
// that just snapshots a full listing.
type dirEnum struct {
	entries []DirEntry
	cursor  int
}

// getDirEnum returns the cached enumeration state for the volatile FileId, or
// nil if none has been established yet.
func (t *Tree) getDirEnum(volatile uint64) *dirEnum {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dirEnums == nil {
		return nil
	}
	return t.dirEnums[volatile]
}

// setDirEnum installs or replaces the cached enumeration state for the
// volatile FileId.
func (t *Tree) setDirEnum(volatile uint64, de *dirEnum) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dirEnums == nil {
		t.dirEnums = make(map[uint64]*dirEnum)
	}
	t.dirEnums[volatile] = de
}

// serializeDirEntries packs a list of DirEntry into the wire format for the
// requested file information class, returning the byte buffer plus the number
// of entries actually serialized. Truncated to outputMax bytes — the caller
// uses the consumed count to advance its cursor. Unknown classes return an
// error so the handler can reply with StatusInvalidParameter.
func serializeDirEntries(class byte, entries []DirEntry, outputMax uint32) ([]byte, int, error) {
	if !isSupportedDirInfoClass(class) {
		return nil, 0, fmt.Errorf("unsupported FileInformationClass 0x%02x", class)
	}
	var (
		buf       bytes.Buffer
		positions []int // start offset of each serialized entry within buf
	)
	for _, e := range entries {
		entryBytes := serializeDirEntry(class, e)
		if outputMax > 0 && uint32(buf.Len()+len(entryBytes)) > outputMax && buf.Len() > 0 {
			break
		}
		positions = append(positions, buf.Len())
		buf.Write(entryBytes)
	}
	// Fix up NextEntryOffset per MS-FSCC: each entry except the last in this
	// batch points at the next one; the last entry's NextEntryOffset is 0.
	out := buf.Bytes()
	for j := 0; j < len(positions)-1; j++ {
		next := uint32(positions[j+1] - positions[j])
		binary.LittleEndian.PutUint32(out[positions[j]:positions[j]+4], next)
	}
	return out, len(positions), nil
}

// isSupportedDirInfoClass reports whether serializeDirEntry handles the given
// FileInformationClass with the correct on-wire layout. Keep in sync with the
// switch in serializeDirEntry.
func isSupportedDirInfoClass(class byte) bool {
	switch class {
	case smb.FileDirectoryInformation,
		smb.FileFullDirectoryInformation,
		smb.FileBothDirectoryInformation,
		smb.FileNamesInformation,
		smb.FileIdBothDirectoryInformation,
		smb.FileIdFullDirectoryInformation:
		return true
	}
	return false
}

// serializeDirEntry returns the wire bytes for a single directory entry,
// padded to an 8-byte boundary. The leading 4 bytes are NextEntryOffset
// (filled in by the caller) followed by the class-specific fields.
func serializeDirEntry(class byte, e DirEntry) []byte {
	nameU := encoder.ToUnicode(e.Name)
	switch class {
	case smb.FileBothDirectoryInformation: // 0x03 — 94 bytes fixed + name + pad
		fixed := 94
		entry := make([]byte, fixed+len(nameU))
		// 0..4 NextEntryOffset (caller fills)
		// 4..8 FileIndex
		binary.LittleEndian.PutUint64(entry[8:], timeToFileTime(e.CreationTime))
		binary.LittleEndian.PutUint64(entry[16:], timeToFileTime(e.LastAccessTime))
		binary.LittleEndian.PutUint64(entry[24:], timeToFileTime(e.LastWriteTime))
		binary.LittleEndian.PutUint64(entry[32:], timeToFileTime(e.ChangeTime))
		binary.LittleEndian.PutUint64(entry[40:], uint64(e.Size))
		binary.LittleEndian.PutUint64(entry[48:], uint64(e.AllocationSize))
		binary.LittleEndian.PutUint32(entry[56:], e.Attributes)
		binary.LittleEndian.PutUint32(entry[60:], uint32(len(nameU)))
		// EaSize 64..68 zero
		// ShortNameLength 68 zero
		// Reserved1 69 zero
		// ShortName[24] 70..94 zero
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	case smb.FileIdBothDirectoryInformation: // 0x25 — 104 bytes fixed + name + pad
		fixed := 104
		entry := make([]byte, fixed+len(nameU))
		binary.LittleEndian.PutUint64(entry[8:], timeToFileTime(e.CreationTime))
		binary.LittleEndian.PutUint64(entry[16:], timeToFileTime(e.LastAccessTime))
		binary.LittleEndian.PutUint64(entry[24:], timeToFileTime(e.LastWriteTime))
		binary.LittleEndian.PutUint64(entry[32:], timeToFileTime(e.ChangeTime))
		binary.LittleEndian.PutUint64(entry[40:], uint64(e.Size))
		binary.LittleEndian.PutUint64(entry[48:], uint64(e.AllocationSize))
		binary.LittleEndian.PutUint32(entry[56:], e.Attributes)
		binary.LittleEndian.PutUint32(entry[60:], uint32(len(nameU)))
		// EaSize 64..68
		// ShortNameLength 68
		// Reserved1 69
		// ShortName[24] 70..94
		// Reserved2 94..96
		// FileId 96..104
		binary.LittleEndian.PutUint64(entry[96:], e.FileID)
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	case smb.FileDirectoryInformation: // 0x01 — 64 bytes fixed + name + pad
		fixed := 64
		entry := make([]byte, fixed+len(nameU))
		binary.LittleEndian.PutUint64(entry[8:], timeToFileTime(e.CreationTime))
		binary.LittleEndian.PutUint64(entry[16:], timeToFileTime(e.LastAccessTime))
		binary.LittleEndian.PutUint64(entry[24:], timeToFileTime(e.LastWriteTime))
		binary.LittleEndian.PutUint64(entry[32:], timeToFileTime(e.ChangeTime))
		binary.LittleEndian.PutUint64(entry[40:], uint64(e.Size))
		binary.LittleEndian.PutUint64(entry[48:], uint64(e.AllocationSize))
		binary.LittleEndian.PutUint32(entry[56:], e.Attributes)
		binary.LittleEndian.PutUint32(entry[60:], uint32(len(nameU)))
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	case smb.FileFullDirectoryInformation: // 0x02 — 68 bytes fixed + name + pad
		fixed := 68
		entry := make([]byte, fixed+len(nameU))
		binary.LittleEndian.PutUint64(entry[8:], timeToFileTime(e.CreationTime))
		binary.LittleEndian.PutUint64(entry[16:], timeToFileTime(e.LastAccessTime))
		binary.LittleEndian.PutUint64(entry[24:], timeToFileTime(e.LastWriteTime))
		binary.LittleEndian.PutUint64(entry[32:], timeToFileTime(e.ChangeTime))
		binary.LittleEndian.PutUint64(entry[40:], uint64(e.Size))
		binary.LittleEndian.PutUint64(entry[48:], uint64(e.AllocationSize))
		binary.LittleEndian.PutUint32(entry[56:], e.Attributes)
		binary.LittleEndian.PutUint32(entry[60:], uint32(len(nameU)))
		// EaSize 64..68 zero
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	case smb.FileIdFullDirectoryInformation: // 0x26 — 80 bytes fixed + name + pad
		fixed := 80
		entry := make([]byte, fixed+len(nameU))
		binary.LittleEndian.PutUint64(entry[8:], timeToFileTime(e.CreationTime))
		binary.LittleEndian.PutUint64(entry[16:], timeToFileTime(e.LastAccessTime))
		binary.LittleEndian.PutUint64(entry[24:], timeToFileTime(e.LastWriteTime))
		binary.LittleEndian.PutUint64(entry[32:], timeToFileTime(e.ChangeTime))
		binary.LittleEndian.PutUint64(entry[40:], uint64(e.Size))
		binary.LittleEndian.PutUint64(entry[48:], uint64(e.AllocationSize))
		binary.LittleEndian.PutUint32(entry[56:], e.Attributes)
		binary.LittleEndian.PutUint32(entry[60:], uint32(len(nameU)))
		// EaSize 64..68
		// Reserved 68..72
		binary.LittleEndian.PutUint64(entry[72:], e.FileID)
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	case smb.FileNamesInformation: // 0x0c — 12 bytes fixed + name + pad
		fixed := 12
		entry := make([]byte, fixed+len(nameU))
		// 0..4 NextEntryOffset (caller fills)
		// 4..8 FileIndex zero
		binary.LittleEndian.PutUint32(entry[8:], uint32(len(nameU)))
		copy(entry[fixed:], nameU)
		return alignTo8(entry)

	default:
		// Unknown class — serializeDirEntries should have rejected this
		// before reaching here. Return nil so the bug is loud rather than
		// silently emitting the wrong layout.
		return nil
	}
}

// alignTo8 pads the provided buffer to an 8-byte boundary so subsequent
// directory entries have aligned NextEntryOffsets.
func alignTo8(b []byte) []byte {
	pad := (8 - len(b)%8) % 8
	if pad == 0 {
		return b
	}
	out := make([]byte, len(b)+pad)
	copy(out, b)
	return out
}
