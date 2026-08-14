// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb/unicode"
)

func TestParseChangeNotifyReq(t *testing.T) {
	raw := make([]byte, 96)
	b := raw[64:]
	binary.LittleEndian.PutUint16(b[0:2], 32) // StructureSize
	binary.LittleEndian.PutUint16(b[2:4], smb2WatchTree)
	binary.LittleEndian.PutUint32(b[4:8], 4096) // OutputBufferLength
	b[8+8] = 9                                  // volatile half of FileId
	binary.LittleEndian.PutUint32(b[24:28], FileNotifyChangeFileName|FileNotifyChangeLastWrite)

	req, err := parseChangeNotifyReq(raw)
	if err != nil {
		t.Fatalf("parseChangeNotifyReq: %v", err)
	}
	if req.Flags&smb2WatchTree == 0 {
		t.Error("watch-tree flag not decoded")
	}
	if req.OutputBufferLen != 4096 {
		t.Errorf("OutputBufferLen = %d, want 4096", req.OutputBufferLen)
	}
	if got := volatileFromFileID(req.FileID); got != 9 {
		t.Errorf("FileId volatile = %d, want 9", got)
	}
	if req.CompletionFilter != FileNotifyChangeFileName|FileNotifyChangeLastWrite {
		t.Errorf("CompletionFilter = 0x%08x", req.CompletionFilter)
	}
}

// TestParseChangeNotifyReqRejectsShort keeps a truncated or mis-shaped body
// from being read past its end.
func TestParseChangeNotifyReqRejectsShort(t *testing.T) {
	if _, err := parseChangeNotifyReq(make([]byte, 80)); err == nil {
		t.Error("accepted an 80-byte CHANGE_NOTIFY request")
	}
	bad := make([]byte, 96)
	binary.LittleEndian.PutUint16(bad[64:66], 33) // wrong StructureSize
	if _, err := parseChangeNotifyReq(bad); err == nil {
		t.Error("accepted a CHANGE_NOTIFY with StructureSize 33")
	}
}

// TestMarshalFileNotifyInformation pins the FILE_NOTIFY_INFORMATION layout of
// MS-FSCC §2.7.1: 4-byte-aligned chained entries with the last one carrying
// NextEntryOffset 0.
func TestMarshalFileNotifyInformation(t *testing.T) {
	changes := []FileNotifyChange{
		{Action: FileActionAdded, Name: "new.txt"},
		{Action: FileActionRemoved, Name: "old.txt"},
	}
	buf, ok := marshalFileNotifyInformation(changes, 4096)
	if !ok {
		t.Fatal("marshalFileNotifyInformation reported overflow for a small list")
	}

	// First entry.
	next := binary.LittleEndian.Uint32(buf[0:4])
	if next == 0 {
		t.Fatal("first entry has NextEntryOffset 0 but a second entry follows")
	}
	if next%4 != 0 {
		t.Errorf("NextEntryOffset %d is not 4-byte aligned", next)
	}
	if act := binary.LittleEndian.Uint32(buf[4:8]); act != FileActionAdded {
		t.Errorf("first Action = %d, want %d", act, FileActionAdded)
	}
	nameLen := binary.LittleEndian.Uint32(buf[8:12])
	name, err := unicode.FromUnicodeString(buf[12 : 12+nameLen])
	if err != nil {
		t.Fatalf("decode first name: %v", err)
	}
	if name != "new.txt" {
		t.Errorf("first name = %q, want %q", name, "new.txt")
	}

	// Second (last) entry terminates the chain.
	second := buf[next:]
	if got := binary.LittleEndian.Uint32(second[0:4]); got != 0 {
		t.Errorf("last entry NextEntryOffset = %d, want 0", got)
	}
	if act := binary.LittleEndian.Uint32(second[4:8]); act != FileActionRemoved {
		t.Errorf("second Action = %d, want %d", act, FileActionRemoved)
	}
}

// TestMarshalFileNotifyInformationOverflow checks the caller is told when the
// list will not fit, so it can answer STATUS_NOTIFY_ENUM_DIR rather than
// truncating into a misleading partial list.
func TestMarshalFileNotifyInformationOverflow(t *testing.T) {
	var changes []FileNotifyChange
	for i := 0; i < 100; i++ {
		changes = append(changes, FileNotifyChange{Action: FileActionModified, Name: "some-long-file-name.dat"})
	}
	if _, ok := marshalFileNotifyInformation(changes, 64); ok {
		t.Error("marshalFileNotifyInformation did not report overflow for a 64-byte budget")
	}
}

// TestAsyncOpRegistrationAndCancel covers the async bookkeeping: an operation
// can be found and cancelled by its MessageId, and teardown cancels everything
// left over so no watcher goroutine outlives its connection.
func TestAsyncOpRegistrationAndCancel(t *testing.T) {
	c := &Conn{Server: &Server{Config: &ServerConfig{}}}

	ctx1, cancel1 := context.WithCancel(context.Background())
	op := &asyncOp{msgID: 5, asyncID: c.nextAsyncOpID(), cancel: cancel1}
	if !c.registerAsync(op) {
		t.Fatal("registerAsync refused the first operation")
	}
	if got := c.asyncIDFor(5); got != op.asyncID {
		t.Errorf("asyncIDFor(5) = %d, want %d", got, op.asyncID)
	}

	if !c.cancelAsync(5) {
		t.Error("cancelAsync did not find message 5")
	}
	select {
	case <-ctx1.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelAsync did not cancel the operation context")
	}
	if c.cancelAsync(999) {
		t.Error("cancelAsync claimed to cancel an unknown message")
	}

	// Teardown must cancel whatever is still registered.
	ctx2, cancel2 := context.WithCancel(context.Background())
	c.registerAsync(&asyncOp{msgID: 6, asyncID: c.nextAsyncOpID(), cancel: cancel2})
	c.cancelAllAsync()
	select {
	case <-ctx2.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelAllAsync left an operation running")
	}
}

// TestAsyncOpCap bounds concurrent async operations. Each costs a goroutine and
// a watch registration, so without a cap an authenticated client could exhaust
// server memory by issuing CHANGE_NOTIFY in a loop.
func TestAsyncOpCap(t *testing.T) {
	c := &Conn{Server: &Server{Config: &ServerConfig{}}}
	var cancels []context.CancelFunc
	defer func() {
		for _, cancel := range cancels {
			cancel()
		}
	}()

	for i := 0; i < maxAsyncOps; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancels = append(cancels, cancel)
		if !c.registerAsync(&asyncOp{msgID: uint64(i), asyncID: c.nextAsyncOpID(), cancel: cancel}) {
			t.Fatalf("registerAsync refused operation %d, below the cap of %d", i, maxAsyncOps)
		}
		_ = ctx
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancels = append(cancels, cancel)
	if c.registerAsync(&asyncOp{msgID: 9999, asyncID: c.nextAsyncOpID(), cancel: cancel}) {
		t.Errorf("registerAsync accepted operation %d past the cap of %d", maxAsyncOps+1, maxAsyncOps)
	}
	_ = ctx
}

// TestAsyncIDsAreUnique guards the correlation key: the final response must
// echo the same AsyncId the interim response advertised, so ids handed out
// concurrently must not collide.
func TestAsyncIDsAreUnique(t *testing.T) {
	c := &Conn{Server: &Server{Config: &ServerConfig{}}}
	const n = 200

	var mu sync.Mutex
	seen := make(map[uint64]bool, n)

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := c.nextAsyncOpID()
			mu.Lock()
			defer mu.Unlock()
			if seen[id] {
				t.Errorf("AsyncId %d handed out twice", id)
			}
			seen[id] = true
		}()
	}
	wg.Wait()
	if len(seen) != n {
		t.Errorf("got %d distinct AsyncIds, want %d", len(seen), n)
	}
}
