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

package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestOplockBreakRoundTrip verifies the OPLOCK_BREAK wire format: a 64-byte
// header followed by the 24-byte body (StructureSize 24, OplockLevel, two
// reserved fields, 16-byte FileId).
func TestOplockBreakRoundTrip(t *testing.T) {
	s := &Session{}
	fileId := bytes.Repeat([]byte{0xAB}, 16)
	ack := s.NewOplockBreakAck(fileId, OpLockLevelII)

	buf, err := ack.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(buf) != 64+24 {
		t.Fatalf("marshaled length = %d, want 88", len(buf))
	}
	if ss := binary.LittleEndian.Uint16(buf[64:66]); ss != 24 {
		t.Errorf("body StructureSize = %d, want 24", ss)
	}

	var got OplockBreak
	if err := got.UnmarshalBinary(buf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.OplockLevel != OpLockLevelII {
		t.Errorf("OplockLevel = 0x%02x, want 0x%02x", got.OplockLevel, OpLockLevelII)
	}
	if !bytes.Equal(got.FileId, fileId) {
		t.Errorf("FileId = %x, want %x", got.FileId, fileId)
	}
}

// TestParseOplockBreak checks the discriminator logic: a 24-byte-body packet
// parses, while a lease break (StructureSize 44) and an over-short buffer are
// rejected so the read loop ignores them rather than mis-decoding.
func TestParseOplockBreak(t *testing.T) {
	s := &Session{}
	ack := s.NewOplockBreakAck(bytes.Repeat([]byte{1}, 16), OpLockLevelNone)
	valid, err := ack.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parseOplockBreak(valid); !ok {
		t.Errorf("parseOplockBreak(valid oplock) ok = false, want true")
	}

	// Same header but a lease-break StructureSize in the body.
	lease := append([]byte(nil), valid...)
	binary.LittleEndian.PutUint16(lease[64:66], 44)
	if _, ok := parseOplockBreak(lease); ok {
		t.Errorf("parseOplockBreak(lease break) ok = true, want false (not modeled)")
	}

	if _, ok := parseOplockBreak(valid[:60]); ok {
		t.Errorf("parseOplockBreak(short) ok = true, want false")
	}
}

// TestHandleServerBreakInvokesHandler drives the read-loop dispatch path: a
// crafted unsolicited oplock break must reach the registered handler with the
// decoded notification. The connection's error is pre-set so the fire-and-
// forget acknowledgment goroutine returns immediately instead of touching a
// live socket.
func TestHandleServerBreakInvokesHandler(t *testing.T) {
	fileId := bytes.Repeat([]byte{0x5A}, 16)
	sess := &Session{}
	conn := &Connection{Session: sess}
	conn.err = fmt.Errorf("test: no live transport") // makes the ack goroutine exit early

	got := make(chan OplockBreak, 1)
	sess.SetOplockBreakHandler(func(_ *Connection, nb OplockBreak) byte {
		got <- nb
		return OpLockLevelNone
	})

	notification := sess.NewOplockBreakAck(fileId, OpLockLevelII)
	notification.Header.MessageID = unsolicitedMessageID
	raw, err := notification.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	conn.handleServerBreak(raw)

	select {
	case nb := <-got:
		if !bytes.Equal(nb.FileId, fileId) {
			t.Errorf("handler FileId = %x, want %x", nb.FileId, fileId)
		}
		if nb.OplockLevel != OpLockLevelII {
			t.Errorf("handler OplockLevel = 0x%02x, want 0x%02x", nb.OplockLevel, OpLockLevelII)
		}
	default:
		t.Fatal("oplock break handler was not invoked")
	}
}

// TestNewCancelReq pins the CANCEL header: it reuses the target MessageId, and
// when the target went asynchronous it sets the async flag and overlays the
// AsyncId onto the Reserved/TreeID header fields (MS-SMB2 §2.2.30 / §3.2.4.24).
func TestNewCancelReq(t *testing.T) {
	s := &Session{sessionID: 0x1122}

	// Synchronous cancel: no async flag, correlated by MessageId only.
	sync := s.NewCancelReq(42, 0)
	if sync.Header.Command != CommandCancel {
		t.Errorf("Command = %d, want CommandCancel", sync.Header.Command)
	}
	if sync.Header.MessageID != 42 {
		t.Errorf("MessageID = %d, want 42 (target id)", sync.Header.MessageID)
	}
	if sync.StructureSize != 4 {
		t.Errorf("StructureSize = %d, want 4", sync.StructureSize)
	}
	if sync.Header.Flags&SMB2_FLAGS_ASYNC_COMMAND != 0 {
		t.Errorf("sync cancel unexpectedly has ASYNC flag")
	}

	// Asynchronous cancel: async flag set, AsyncId split across Reserved/TreeID.
	const asyncId = uint64(0xDEADBEEF12345678)
	async := s.NewCancelReq(42, asyncId)
	if async.Header.Flags&SMB2_FLAGS_ASYNC_COMMAND == 0 {
		t.Errorf("async cancel missing ASYNC flag")
	}
	recombined := uint64(async.Header.Reserved) | uint64(async.Header.TreeID)<<32
	if recombined != asyncId {
		t.Errorf("AsyncId overlay = 0x%x, want 0x%x", recombined, asyncId)
	}
}
