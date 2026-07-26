// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// buildCreateContext encodes a single create-context element the way a client
// would, so the parser is exercised against foreign bytes rather than only its
// own writer.
func buildCreateContext(name string, data []byte, last bool) []byte {
	nameOff := 16
	dataOff := nameOff + len(name)
	if pad := dataOff % 8; pad != 0 {
		dataOff += 8 - pad
	}
	size := dataOff + len(data)
	if !last {
		if pad := size % 8; pad != 0 {
			size += 8 - pad
		}
	}
	e := make([]byte, size)
	if !last {
		binary.LittleEndian.PutUint32(e[0:4], uint32(size))
	}
	binary.LittleEndian.PutUint16(e[4:6], uint16(nameOff))
	binary.LittleEndian.PutUint16(e[6:8], uint16(len(name)))
	if len(data) > 0 {
		binary.LittleEndian.PutUint16(e[10:12], uint16(dataOff))
		binary.LittleEndian.PutUint32(e[12:16], uint32(len(data)))
		copy(e[dataOff:], data)
	}
	copy(e[nameOff:], name)
	return e
}

func TestParseCreateContexts(t *testing.T) {
	dh2q := make([]byte, 32)
	binary.LittleEndian.PutUint32(dh2q[0:4], 30000) // Timeout
	for i := range 16 {
		dh2q[16+i] = byte(i + 1) // CreateGuid
	}

	blob := append(
		buildCreateContext(createContextQueryMaximalAccess, nil, false),
		buildCreateContext(createContextDurableRequestV2, dh2q, true)...,
	)

	ctxs, err := parseCreateContexts(blob)
	if err != nil {
		t.Fatalf("parseCreateContexts: %v", err)
	}
	if len(ctxs) != 2 {
		t.Fatalf("got %d contexts, want 2", len(ctxs))
	}
	if ctxs[0].Name != createContextQueryMaximalAccess {
		t.Errorf("first context name = %q, want %q", ctxs[0].Name, createContextQueryMaximalAccess)
	}
	if ctxs[1].Name != createContextDurableRequestV2 {
		t.Errorf("second context name = %q, want %q", ctxs[1].Name, createContextDurableRequestV2)
	}

	req, err := parseDurableRequestV2(ctxs[1].Data)
	if err != nil {
		t.Fatalf("parseDurableRequestV2: %v", err)
	}
	if req.Timeout != 30000 {
		t.Errorf("Timeout = %d, want 30000", req.Timeout)
	}
	var wantGuid [16]byte
	for i := range 16 {
		wantGuid[i] = byte(i + 1)
	}
	if req.CreateGuid != wantGuid {
		t.Errorf("CreateGuid = % x, want % x", req.CreateGuid, wantGuid)
	}
}

// TestParseCreateContextsRejectsMalformed makes sure wire-controlled offsets
// cannot walk outside the buffer. Contexts drive handle semantics, so a bad
// list must be an error rather than a partial parse.
func TestParseCreateContextsRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"truncated header":   make([]byte, 8),
		"name beyond buffer": {0, 0, 0, 0, 0xff, 0xff, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"data beyond buffer": {0, 0, 0, 0, 16, 0, 4, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0},
	}
	for name, blob := range cases {
		if _, err := parseCreateContexts(blob); err == nil {
			t.Errorf("%s: parseCreateContexts accepted malformed input", name)
		}
	}

	// A Next pointer that loops back on itself must not hang the parser.
	loop := make([]byte, 32)
	binary.LittleEndian.PutUint32(loop[0:4], 0) // terminate
	binary.LittleEndian.PutUint16(loop[4:6], 16)
	binary.LittleEndian.PutUint16(loop[6:8], 4)
	copy(loop[16:], "DH2Q")
	done := make(chan struct{})
	go func() {
		_, _ = parseCreateContexts(loop)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("parseCreateContexts hung on a self-referential Next")
	}
}

// TestMarshalCreateContextsRoundTrip checks our writer against our reader.
func TestMarshalCreateContextsRoundTrip(t *testing.T) {
	in := []createContext{
		{Name: createContextDurableRequestV2, Data: durableResponseV2(60000, false)},
		{Name: createContextDurableRequest, Data: durableResponseV1()},
	}
	out, err := parseCreateContexts(marshalCreateContexts(in))
	if err != nil {
		t.Fatalf("round trip parse: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("round trip produced %d contexts, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Name != in[i].Name {
			t.Errorf("context %d name = %q, want %q", i, out[i].Name, in[i].Name)
		}
		if !bytes.Equal(out[i].Data, in[i].Data) {
			t.Errorf("context %d data = % x, want % x", i, out[i].Data, in[i].Data)
		}
	}
}

func TestDurableTimeoutClamping(t *testing.T) {
	cfg := &ServerConfig{}
	if got := cfg.durableTimeout(0); got != DefaultDurableTimeout {
		t.Errorf("durableTimeout(0) = %v, want %v", got, DefaultDurableTimeout)
	}
	if got := cfg.durableTimeout(5000); got != 5*time.Second {
		t.Errorf("durableTimeout(5000) = %v, want 5s", got)
	}
	// A client asking for far more than the cap is clamped, not honored: a
	// handle parked indefinitely is a resource leak triggerable at will.
	if got := cfg.durableTimeout(1 << 30); got != MaxDurableTimeout {
		t.Errorf("durableTimeout(huge) = %v, want %v", got, MaxDurableTimeout)
	}

	cfg2 := &ServerConfig{DurableHandleTimeout: 5 * time.Minute, MaxDurableHandleTimeout: time.Minute}
	if got := cfg2.durableTimeout(0); got != time.Minute {
		t.Errorf("default above the cap should clamp: got %v, want 1m", got)
	}
}

// stubHandle is a minimal Handle for table-level durable tests.
type stubHandle struct {
	path  string
	isDir bool
}

func (s *stubHandle) Stat() (FileInfo, error) { return FileInfo{Name: s.path}, nil }
func (s *stubHandle) Path() Path              { return s.path }
func (s *stubHandle) IsDir() bool             { return s.isDir }

// TestDurableReclaimRequiresMatchingIdentity is the security property of the
// feature: a parked handle may only be reclaimed by the principal that opened
// it, on the same share. Without the check, any authenticated user could take
// over another's handle by presenting a guessed FileId.
func TestDurableReclaimRequiresMatchingIdentity(t *testing.T) {
	s := &Server{Config: &ServerConfig{DurableHandles: true}}
	defer s.stopDurables()

	var fid [16]byte
	fid[8] = 42
	d := &durableHandle{
		FileID:   fid,
		Handle:   &stubHandle{path: "doc.txt"},
		Share:    "data",
		Username: "alice",
		Domain:   "CORP",
		Timeout:  time.Minute,
	}
	s.registerDurable(d)
	s.parkDurable(d)

	var zeroGuid [16]byte
	if _, ok := s.reclaimDurable(zeroGuid, fid, "data", "bob", "CORP"); ok {
		t.Error("a different user reclaimed the handle")
	}
	if _, ok := s.reclaimDurable(zeroGuid, fid, "data", "alice", "OTHER"); ok {
		t.Error("a different domain reclaimed the handle")
	}
	if _, ok := s.reclaimDurable(zeroGuid, fid, "other", "alice", "CORP"); ok {
		t.Error("a different share reclaimed the handle")
	}

	// The rightful owner gets it back, case-insensitively.
	got, ok := s.reclaimDurable(zeroGuid, fid, "DATA", "Alice", "corp")
	if !ok {
		t.Fatal("the owning principal could not reclaim the handle")
	}
	if got.Handle.Path() != "doc.txt" {
		t.Errorf("reclaimed the wrong handle: %q", got.Handle.Path())
	}
	// It is no longer parked, so a second reclaim must fail.
	if _, ok := s.reclaimDurable(zeroGuid, fid, "data", "alice", "CORP"); ok {
		t.Error("an already-reclaimed handle was handed out twice")
	}
}

// TestDurableExpiryClosesHandle checks the reaper releases the VFS resource
// once the grant lapses, and that an expired handle cannot be reclaimed.
func TestDurableExpiryClosesHandle(t *testing.T) {
	vfs := &countingVFS{}
	s := &Server{Config: &ServerConfig{DurableHandles: true}}
	defer s.stopDurables()

	var fid [16]byte
	fid[8] = 7
	d := &durableHandle{
		FileID:   fid,
		Handle:   &stubHandle{path: "big.iso"},
		VFS:      vfs,
		Share:    "data",
		Username: "alice",
		Timeout:  10 * time.Millisecond,
	}
	s.registerDurable(d)
	s.parkDurable(d)

	s.expireDurables(time.Now().Add(time.Second))

	if vfs.closes != 1 {
		t.Errorf("VFS.Close called %d times on expiry, want 1", vfs.closes)
	}
	var zeroGuid [16]byte
	if _, ok := s.reclaimDurable(zeroGuid, fid, "data", "alice", ""); ok {
		t.Error("an expired handle was reclaimed")
	}
}

// TestDurableNotGrantedWhenDisabled makes sure the feature is genuinely
// opt-in: with DurableHandles unset, no grant is recorded and no response
// context is emitted, so clients never believe they hold a durable handle.
func TestDurableNotGrantedWhenDisabled(t *testing.T) {
	s := &Server{Config: &ServerConfig{}}
	c := &Conn{Server: s}
	tree := &Tree{Share: Share{Name: "data", VFS: &countingVFS{}}}
	sess := &Session{Username: "alice"}

	reqCtxs := []createContext{{Name: createContextDurableRequest}}
	if got := c.grantDurable(sess, tree, &stubHandle{}, make([]byte, 16), reqCtxs); got != nil {
		t.Errorf("grantDurable returned %v with DurableHandles disabled, want nil", got)
	}
}

// countingVFS is a no-op VFS that records how many times Close was called, so
// tests can assert on resource release without a real filesystem.
type countingVFS struct {
	closes int
}

func (v *countingVFS) Create(ctx context.Context, sess *Session, req CreateRequest) (CreateResult, uint32, error) {
	return CreateResult{Handle: &stubHandle{path: req.Path}}, 0, nil
}
func (v *countingVFS) Close(ctx context.Context, h Handle) error { v.closes++; return nil }
func (v *countingVFS) Read(ctx context.Context, h Handle, off int64, b []byte) (int, uint32, error) {
	return 0, 0, nil
}
func (v *countingVFS) Write(ctx context.Context, h Handle, off int64, d []byte) (int, uint32, error) {
	return 0, 0, nil
}
func (v *countingVFS) Flush(ctx context.Context, h Handle) (uint32, error) { return 0, nil }
func (v *countingVFS) QueryFileInfo(ctx context.Context, h Handle, cls byte) (any, uint32, error) {
	return nil, 0, nil
}
func (v *countingVFS) SetFileInfo(ctx context.Context, h Handle, cls byte, raw []byte) (uint32, error) {
	return 0, nil
}
func (v *countingVFS) QueryDirectory(ctx context.Context, h Handle, pattern string, restart bool) ([]DirEntry, uint32, error) {
	return nil, 0, nil
}
func (v *countingVFS) QueryFSInfo(ctx context.Context, cls byte) (any, uint32, error) {
	return nil, 0, nil
}
func (v *countingVFS) QuerySecurity(ctx context.Context, h Handle, add uint32) ([]byte, uint32, error) {
	return nil, 0, nil
}
func (v *countingVFS) Ioctl(ctx context.Context, h Handle, code uint32, in []byte, maxOut uint32) ([]byte, uint32, error) {
	return nil, 0, nil
}
