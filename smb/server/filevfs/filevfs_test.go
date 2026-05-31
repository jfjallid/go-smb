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

package filevfs

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

func newFS(t *testing.T, ro bool) (*FS, string) {
	t.Helper()
	root := t.TempDir()
	fs, err := New(Options{Root: root, ReadOnly: ro})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return fs, root
}

func mustCreate(t *testing.T, fs *FS, name string, opts uint32, disp uint32) server.Handle {
	t.Helper()
	res, status, err := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              name,
		CreateOptions:     opts,
		CreateDisposition: disp,
	})
	if err != nil {
		t.Fatalf("Create %q: err=%v", name, err)
	}
	if status != smb.StatusOk {
		t.Fatalf("Create %q: status=0x%08x", name, status)
	}
	return res.Handle
}

func TestNewRejectsBadRoot(t *testing.T) {
	if _, err := New(Options{Root: ""}); err == nil {
		t.Fatal("expected error for empty root")
	}
	if _, err := New(Options{Root: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("expected error for missing root")
	}
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Root: f}); err == nil {
		t.Fatal("expected error for non-directory root")
	}
}

func TestCreateWriteReadRoundTrip(t *testing.T) {
	fs, root := newFS(t, false)
	h := mustCreate(t, fs, "hello.txt", smb.FileNonDirectoryFile, smb.FileCreate)

	payload := []byte("hello from filevfs")
	n, status, err := fs.Write(context.Background(), h, 0, payload)
	if err != nil || status != smb.StatusOk || n != len(payload) {
		t.Fatalf("Write: n=%d status=0x%08x err=%v", n, status, err)
	}
	if err := fs.Close(context.Background(), h); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(root, "hello.txt"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("disk mismatch: got %q want %q", got, payload)
	}

	h2 := mustCreate(t, fs, "hello.txt", smb.FileNonDirectoryFile, smb.FileOpen)
	defer fs.Close(context.Background(), h2)
	buf := make([]byte, len(payload))
	n, status, err = fs.Read(context.Background(), h2, 0, buf)
	if err != nil || status != smb.StatusOk || n != len(payload) {
		t.Fatalf("Read: n=%d status=0x%08x err=%v", n, status, err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("read mismatch: got %q want %q", buf, payload)
	}
}

func TestCreateCollision(t *testing.T) {
	fs, _ := newFS(t, false)
	h := mustCreate(t, fs, "a.txt", smb.FileNonDirectoryFile, smb.FileCreate)
	fs.Close(context.Background(), h)
	_, status, err := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "a.txt",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileCreate,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != smb.StatusObjectNameCollision {
		t.Fatalf("expected name collision, got 0x%08x", status)
	}
}

func TestOpenMissing(t *testing.T) {
	fs, _ := newFS(t, false)
	_, status, err := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "missing.txt",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileOpen,
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != smb.StatusObjectNameNotFound {
		t.Fatalf("expected not-found, got 0x%08x", status)
	}
}

func TestQueryDirectory(t *testing.T) {
	fs, root := newFS(t, false)
	if err := os.WriteFile(filepath.Join(root, "one"), []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	rh := mustCreate(t, fs, "", smb.FileDirectoryFile, smb.FileOpen)
	defer fs.Close(context.Background(), rh)

	entries, status, err := fs.QueryDirectory(context.Background(), rh, "*", false)
	if err != nil || status != smb.StatusOk {
		t.Fatalf("QueryDirectory: status=0x%08x err=%v", status, err)
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	for _, want := range []string{".", "..", "one", "sub"} {
		if !names[want] {
			t.Fatalf("missing %q in listing %v", want, names)
		}
	}
	// Stateful: second call returns empty.
	more, status, err := fs.QueryDirectory(context.Background(), rh, "*", false)
	if err != nil || status != smb.StatusOk || len(more) != 0 {
		t.Fatalf("expected empty second scan, got %d entries", len(more))
	}
	// restart=true rescans.
	again, status, err := fs.QueryDirectory(context.Background(), rh, "*", true)
	if err != nil || status != smb.StatusOk || len(again) == 0 {
		t.Fatalf("restart should rescan, got %d entries", len(again))
	}
}

func TestSetEndOfFileTruncate(t *testing.T) {
	fs, root := newFS(t, false)
	h := mustCreate(t, fs, "trunc.bin", smb.FileNonDirectoryFile, smb.FileCreate)
	defer fs.Close(context.Background(), h)
	if _, _, err := fs.Write(context.Background(), h, 0, []byte("0123456789")); err != nil {
		t.Fatal(err)
	}
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], 4)
	status, err := fs.SetFileInfo(context.Background(), h, smb.FileEndOfFileInformation, raw[:])
	if err != nil || status != smb.StatusOk {
		t.Fatalf("SetFileInfo trunc: status=0x%08x err=%v", status, err)
	}
	got, err := os.ReadFile(filepath.Join(root, "trunc.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "0123" {
		t.Fatalf("trunc mismatch: got %q", got)
	}

	// Grow.
	binary.LittleEndian.PutUint64(raw[:], 8)
	status, err = fs.SetFileInfo(context.Background(), h, smb.FileEndOfFileInformation, raw[:])
	if err != nil || status != smb.StatusOk {
		t.Fatalf("grow: status=0x%08x err=%v", status, err)
	}
	got, err = os.ReadFile(filepath.Join(root, "trunc.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 || string(got[:4]) != "0123" {
		t.Fatalf("grow mismatch: got %q", got)
	}
}

func TestDispositionDelete(t *testing.T) {
	fs, root := newFS(t, false)
	h := mustCreate(t, fs, "doomed", smb.FileNonDirectoryFile, smb.FileCreate)
	status, err := fs.SetFileInfo(context.Background(), h, smb.FileDispositionInformation, []byte{1})
	if err != nil || status != smb.StatusOk {
		t.Fatalf("disposition: status=0x%08x err=%v", status, err)
	}
	if err := fs.Close(context.Background(), h); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "doomed")); !os.IsNotExist(err) {
		t.Fatalf("expected file removed, stat err=%v", err)
	}
}

func TestRename(t *testing.T) {
	fs, root := newFS(t, false)
	h := mustCreate(t, fs, "before", smb.FileNonDirectoryFile, smb.FileCreate)
	if _, _, err := fs.Write(context.Background(), h, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}

	// Build a FileRenameInformation buffer: ReplaceIfExists(1) + Reserved(7)
	// + RootDirectory(8) + FileNameLength(4) + FileName(*).
	name := encoder.ToUnicode("after")
	buf := make([]byte, 20+len(name))
	buf[0] = 0
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(name)))
	copy(buf[20:], name)

	status, err := fs.SetFileInfo(context.Background(), h, smb.FileRenameInformation, buf)
	if err != nil || status != smb.StatusOk {
		t.Fatalf("rename: status=0x%08x err=%v", status, err)
	}
	fs.Close(context.Background(), h)

	if _, err := os.Stat(filepath.Join(root, "before")); !os.IsNotExist(err) {
		t.Fatalf("old name still exists: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(root, "after"))
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	if string(got) != "data" {
		t.Fatalf("contents lost: %q", got)
	}
}

func TestReadOnlyRejectsMutations(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "existing"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := New(Options{Root: root, ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}

	_, status, _ := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "newfile",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileCreate,
	})
	if status != smb.StatusAccessDenied {
		t.Fatalf("expected access denied for FileCreate, got 0x%08x", status)
	}

	h := mustCreate(t, fs, "existing", smb.FileNonDirectoryFile, smb.FileOpen)
	defer fs.Close(context.Background(), h)
	_, status, _ = fs.Write(context.Background(), h, 0, []byte("x"))
	if status != smb.StatusAccessDenied {
		t.Fatalf("expected access denied for Write, got 0x%08x", status)
	}
	status, _ = fs.SetFileInfo(context.Background(), h, smb.FileEndOfFileInformation, make([]byte, 8))
	if status != smb.StatusAccessDenied {
		t.Fatalf("expected access denied for truncate, got 0x%08x", status)
	}
}

func TestCaseInsensitiveLookup(t *testing.T) {
	fs, root := newFS(t, false)
	if err := os.WriteFile(filepath.Join(root, "README.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := mustCreate(t, fs, "readme.txt", smb.FileNonDirectoryFile, smb.FileOpen)
	defer fs.Close(context.Background(), h)
	if got := h.Path(); !strings.EqualFold(got, "README.txt") {
		t.Fatalf("Path: got %q", got)
	}
	// The display path should preserve the on-disk case.
	if got := h.Path(); got != "README.txt" {
		t.Fatalf("expected case-corrected path, got %q", got)
	}
}

func TestTraversalRejected(t *testing.T) {
	fs, _ := newFS(t, false)
	_, status, _ := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "..\\evil",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileCreate,
	})
	if status != smb.StatusObjectNameInvalid {
		t.Fatalf("expected name-invalid, got 0x%08x", status)
	}
}

func TestSymlinkEscapeRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("nope"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	fs, err := New(Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	_, status, _ := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "escape\\secret",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileOpen,
	})
	if status != smb.StatusAccessDenied {
		t.Fatalf("expected access denied through symlink escape, got 0x%08x", status)
	}
}
