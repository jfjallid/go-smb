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
	"time"
)

// Path is an SMB-style, "\"-separated, share-relative path. The empty string
// or "\" denotes the share root.
type Path = string

// FileInfo describes a single VFS entry. Times are FILETIME (100ns since
// 1601), matching the SMB2 wire format directly to avoid repeated conversion.
type FileInfo struct {
	Name           string
	Size           int64
	AllocationSize int64
	Attributes     uint32 // FILE_ATTRIBUTE_*; FILE_ATTRIBUTE_DIRECTORY for dirs.
	CreationTime   time.Time
	LastAccessTime time.Time
	LastWriteTime  time.Time
	ChangeTime     time.Time
	FileID         uint64 // optional; some clients consume MS-FSCC FileId.
}

// Handle is an open VFS object. Implementations should be cheap to copy by
// pointer; the server tracks them in a per-Tree handle table.
type Handle interface {
	Stat() (FileInfo, error)
	Path() Path
	IsDir() bool
}

// CreateRequest mirrors the relevant fields of an SMB2 CREATE request.
// The server fills it from CreateReq before calling VFS.Create.
type CreateRequest struct {
	Path              Path
	DesiredAccess     uint32
	FileAttributes    uint32
	ShareAccess       uint32
	CreateDisposition uint32
	CreateOptions     uint32
}

// CreateResult is what VFS.Create returns on success.
type CreateResult struct {
	Handle       Handle
	CreateAction uint32 // FILE_SUPERSEDED / OPENED / CREATED / OVERWRITTEN.
	Info         FileInfo
}

// DirEntry is a single entry returned by VFS.QueryDirectory.
type DirEntry struct {
	FileInfo
	ShortName string // optional; filled if VFS supplies 8.3 names.
}

// VFS is the pluggable filesystem behind a Disk share. Methods return an
// NTSTATUS code as their second-to-last return value; non-zero short-circuits
// the default response builder. err is reserved for fatal/transport-level
// failures that should abort the connection.
//
// Optional methods (QuerySecurity, Ioctl) may return (nil, STATUS_NOT_SUPPORTED, nil)
// to delegate to the server's default behavior.
type VFS interface {
	Create(ctx context.Context, sess *Session, req CreateRequest) (CreateResult, uint32, error)
	Close(ctx context.Context, h Handle) error
	Read(ctx context.Context, h Handle, offset int64, buf []byte) (n int, status uint32, err error)
	Write(ctx context.Context, h Handle, offset int64, data []byte) (n int, status uint32, err error)
	Flush(ctx context.Context, h Handle) (uint32, error)
	QueryFileInfo(ctx context.Context, h Handle, infoClass byte) (interface{}, uint32, error)
	SetFileInfo(ctx context.Context, h Handle, infoClass byte, raw []byte) (uint32, error)
	QueryDirectory(ctx context.Context, h Handle, pattern string, restart bool) ([]DirEntry, uint32, error)
	QueryFSInfo(ctx context.Context, infoClass byte) (interface{}, uint32, error)
	QuerySecurity(ctx context.Context, h Handle, addInfo uint32) ([]byte, uint32, error)
	Ioctl(ctx context.Context, h Handle, code uint32, in []byte, maxOut uint32) ([]byte, uint32, error)
}
