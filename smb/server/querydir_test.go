// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"io"
	"sort"
	"testing"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
)

// TestQueryDirectorySingleEntry covers the SMB2_RETURN_SINGLE_ENTRY path that
// PowerShell uses for `Get-ChildItem \\<ip>\<share>`. The server must
// (a) honor the flag by returning exactly one entry per call and
// (b) persist its enumeration cursor across calls so subsequent
// QueryDirectory requests serve the next entry — not "no more files" after
// the first. Exercised against both VFS backends.
func TestQueryDirectorySingleEntry(t *testing.T) {
	t.Run("memvfs", func(t *testing.T) {
		runSingleEntryEnumTest(t, memvfs.New(memvfs.Options{}))
	})
	t.Run("filevfs", func(t *testing.T) {
		root := t.TempDir()
		fs, err := filevfs.New(filevfs.Options{Root: root})
		if err != nil {
			t.Fatalf("filevfs.New: %v", err)
		}
		runSingleEntryEnumTest(t, fs)
	})
}

func runSingleEntryEnumTest(t *testing.T, vfs server.VFS) {
	t.Helper()
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: vfs})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c := dialClient(t, addr.Port, user, password, domain)
	defer c.Close()

	// Populate two files via the normal write path so both VFS backends
	// stay agnostic to test scaffolding.
	want := []string{"alpha.txt", "bravo.txt"}
	for _, name := range want {
		body := []byte("contents of " + name)
		src := bytes.NewReader(body)
		if err := c.PutFile(share, name, 0, func(buf []byte) (int, error) {
			n, err := src.Read(buf)
			if err == io.EOF && n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}); err != nil {
			t.Fatalf("PutFile %s: %v", name, err)
		}
	}

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}
	defer c.TreeDisconnect(share)

	// Open the share root as a directory handle so we can enumerate it.
	opts := smb.NewCreateReqOpts()
	opts.DesiredAccess = smb.DAccMaskFileListDirectory | smb.DAccMaskFileReadAttributes
	opts.FileAttr = smb.FileAttrDirectory
	opts.CreateOpts = smb.FileDirectoryFile
	dir, err := c.OpenFileExt(share, "", opts)
	if err != nil {
		t.Fatalf("OpenFileExt(dir): %v", err)
	}
	defer dir.CloseFile()

	// Iterate with SMB2_RETURN_SINGLE_ENTRY. The in-tree client maps both
	// StatusNoMoreFiles and the "." / ".." filter to an empty result, so
	// we can't distinguish "done" from "filtered" on a single call. Instead
	// bound the loop and stop once we've collected every expected entry —
	// broken pagination then fails loudly with a missing-file assertion.
	gotNames := map[string]bool{}
	const maxIters = 16
	for iter := 0; iter < maxIters; iter++ {
		files, qErr := dir.QueryDirectory("*", smb.ReturnSingleEntry, 0, 65536)
		if qErr != nil {
			t.Fatalf("QueryDirectory iter=%d: %v", iter, qErr)
		}
		if len(files) > 1 {
			t.Fatalf("QueryDirectory iter=%d returned %d entries — SMB2_RETURN_SINGLE_ENTRY ignored",
				iter, len(files))
		}
		for _, f := range files {
			gotNames[f.Name] = true
		}
		if haveAll(gotNames, want) {
			return
		}
	}
	got := make([]string, 0, len(gotNames))
	for n := range gotNames {
		got = append(got, n)
	}
	sort.Strings(got)
	t.Fatalf("single-entry enumeration missing files; want %v got %v", want, got)
}

func haveAll(have map[string]bool, want []string) bool {
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}
