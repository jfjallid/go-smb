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

	"github.com/jfjallid/go-smb/smb"
)

// PipeBackend is the per-open state for a named pipe (e.g. "srvsvc").
// Implementations service the three SMB operations a client may invoke on a
// pipe handle:
//
//   - Transceive: an FSCTL_PIPE_TRANSCEIVE round trip — the typical DCERPC
//     request/response. Most clients use this exclusively.
//   - Write / Read: separate WRITE then READ — used by some Linux clients
//     and for fragmented DCERPC PDUs. Implementations that only care about
//     Transceive may return STATUS_NOT_SUPPORTED here.
//   - Close: free per-open state.
type PipeBackend interface {
	Transceive(ctx context.Context, in []byte) (out []byte, status uint32, err error)
	Write(ctx context.Context, data []byte) (n int, status uint32, err error)
	Read(ctx context.Context, max int) (out []byte, status uint32, err error)
	Close(ctx context.Context) error
}

// PipeOpener routes a pipe-name (e.g. "srvsvc") to a fresh PipeBackend per
// open. Returning (nil, status, nil) rejects the open with that NTSTATUS.
// Returning (nil, _, err) aborts the connection.
type PipeOpener interface {
	OpenPipe(ctx context.Context, sess *Session, name string) (PipeBackend, uint32, error)
}

// MapPipeOpener is a trivial PipeOpener — a name->factory map. Names are
// matched case-insensitively and have any leading backslashes stripped.
// Concurrent reads are safe; mutate the map only before installing the
// opener on a Server.
type MapPipeOpener struct {
	Pipes map[string]func(*Session) (PipeBackend, error)
}

// OpenPipe implements PipeOpener.
func (m *MapPipeOpener) OpenPipe(_ context.Context, sess *Session, name string) (PipeBackend, uint32, error) {
	if m == nil || m.Pipes == nil {
		return nil, smb.StatusObjectNameNotFound, nil
	}
	key := strings.ToLower(strings.TrimLeft(name, "\\"))
	factory, ok := m.Pipes[key]
	if !ok {
		return nil, smb.StatusObjectNameNotFound, nil
	}
	pb, err := factory(sess)
	if err != nil {
		return nil, smb.StatusPipeNotAvailable, err
	}
	return pb, smb.StatusOk, nil
}

// pipeHandle adapts a PipeBackend into the per-tree Handle interface so the
// existing handle table (smb/server/handle.go) stores pipes alongside files.
type pipeHandle struct {
	name    string
	backend PipeBackend

	mu     sync.Mutex
	closed bool
}

func (h *pipeHandle) Stat() (FileInfo, error) {
	return FileInfo{Attributes: FileAttributeNormal}, nil
}

func (h *pipeHandle) Path() Path  { return h.name }
func (h *pipeHandle) IsDir() bool { return false }

// closeOnce ensures Close is only delegated to the backend once even if the
// tree teardown path and an explicit SMB2_CLOSE race.
func (h *pipeHandle) closeOnce(ctx context.Context) error {
	h.mu.Lock()
	already := h.closed
	h.closed = true
	h.mu.Unlock()
	if already {
		return nil
	}
	return h.backend.Close(ctx)
}
