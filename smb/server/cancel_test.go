// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// TestCancel verifies that an inbound SMB2 CANCEL is answered with
// STATUS_CANCELLED rather than STATUS_NOT_SUPPORTED (which would be the
// default-handler outcome). MS-SMB2 §3.3.5.16: cancel should be handled
// gracefully even when there is nothing to cancel.
func TestCancel(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{}}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Build a minimal SMB2 CANCEL: 64-byte header + 4-byte body
	// (StructureSize=4, Reserved=0).
	body := make([]byte, 64+4)
	copy(body[0:4], []byte(smb.ProtocolSmb2))
	binary.LittleEndian.PutUint16(body[4:6], 64) // header StructureSize
	binary.LittleEndian.PutUint16(body[12:14], smb.CommandCancel)
	binary.LittleEndian.PutUint16(body[14:16], 1)             // credits
	binary.LittleEndian.PutUint64(body[24:32], 0x42)          // MessageID
	binary.LittleEndian.PutUint16(body[64:66], 4)             // body StructureSize

	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		t.Fatalf("read framing: %v", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(resp) < 64 {
		t.Fatalf("reply too short: %d", len(resp))
	}
	if got := binary.LittleEndian.Uint32(resp[8:12]); got != smb.StatusCancelled {
		t.Errorf("status: got 0x%08x want STATUS_CANCELLED (0xc0000120)", got)
	}
	if got := binary.LittleEndian.Uint64(resp[24:32]); got != 0x42 {
		t.Errorf("MessageID: got 0x%x want 0x42", got)
	}
}
