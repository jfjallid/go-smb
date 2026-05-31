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

package memvfs

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

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

// TestReadOnlyRejectsMutations mirrors filevfs's coverage: every mutating
// path returns StatusAccessDenied while reads still succeed against any
// pre-seeded content.
func TestReadOnlyRejectsMutations(t *testing.T) {
	// Seed a file via a writable FS, then pivot to a read-only FS over the
	// same node map. memvfs has no on-disk state to share, so the test
	// constructs the read-only FS by populating its node map directly.
	fs := New(Options{ReadOnly: true})
	fs.mu.Lock()
	fs.nodes["existing"] = &node{
		name:           "existing",
		data:           []byte("hi"),
		creationTime:   fs.clock(),
		lastAccessTime: fs.clock(),
		lastWriteTime:  fs.clock(),
		changeTime:     fs.clock(),
	}
	fs.mu.Unlock()

	// FileCreate is rejected (would create a new file).
	_, status, _ := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "newfile",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileCreate,
	})
	if status != smb.StatusAccessDenied {
		t.Fatalf("FileCreate: expected access denied, got 0x%08x", status)
	}

	// FileOpen on an existing file still succeeds.
	h := mustCreate(t, fs, "existing", smb.FileNonDirectoryFile, smb.FileOpen)
	defer fs.Close(context.Background(), h)

	// Reads succeed.
	buf := make([]byte, 8)
	n, status, _ := fs.Read(context.Background(), h, 0, buf)
	if status != smb.StatusOk || n != 2 || string(buf[:n]) != "hi" {
		t.Fatalf("Read: status=0x%08x n=%d data=%q", status, n, buf[:n])
	}

	// Writes are denied.
	_, status, _ = fs.Write(context.Background(), h, 0, []byte("x"))
	if status != smb.StatusAccessDenied {
		t.Fatalf("Write: expected access denied, got 0x%08x", status)
	}

	// SetFileInfo (truncate) is denied.
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, 0)
	status, _ = fs.SetFileInfo(context.Background(), h, smb.FileEndOfFileInformation, raw)
	if status != smb.StatusAccessDenied {
		t.Fatalf("SetFileInfo truncate: expected access denied, got 0x%08x", status)
	}

	// FileOpenIf-when-not-exists is denied (would create).
	_, status, _ = fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "missing",
		CreateOptions:     smb.FileNonDirectoryFile,
		CreateDisposition: smb.FileOpenIf,
	})
	if status != smb.StatusAccessDenied {
		t.Fatalf("FileOpenIf missing: expected access denied, got 0x%08x", status)
	}

	// FileDeleteOnClose is denied even on FileOpen.
	_, status, _ = fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "existing",
		CreateOptions:     smb.FileNonDirectoryFile | smb.FileDeleteOnClose,
		CreateDisposition: smb.FileOpen,
	})
	if status != smb.StatusAccessDenied {
		t.Fatalf("FileDeleteOnClose: expected access denied, got 0x%08x", status)
	}
}

// TestReadOnlyAllowsReadOps confirms that a fresh ReadOnly FS still services
// directory listings and FileOpen for the auto-created root.
func TestReadOnlyAllowsReadOps(t *testing.T) {
	fs := New(Options{ReadOnly: true})
	rootHandle, status, err := fs.Create(context.Background(), nil, server.CreateRequest{
		Path:              "",
		CreateOptions:     smb.FileDirectoryFile,
		CreateDisposition: smb.FileOpen,
	})
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	if status != smb.StatusOk {
		t.Fatalf("open root: status=0x%08x", status)
	}
	defer fs.Close(context.Background(), rootHandle.Handle)

	entries, status, err := fs.QueryDirectory(context.Background(), rootHandle.Handle, "*", false)
	if err != nil {
		t.Fatalf("QueryDirectory: %v", err)
	}
	if status != smb.StatusOk {
		t.Fatalf("QueryDirectory: status=0x%08x", status)
	}
	// Should see "." and ".." for the root.
	if len(entries) < 2 {
		t.Fatalf("QueryDirectory: expected at least 2 entries, got %d", len(entries))
	}
}
