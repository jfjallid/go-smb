// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// TestEcho drives a raw SMB2 Echo (keepalive) request against the
// server and verifies the OnEcho hook fires plus a well-formed reply.
func TestEcho(t *testing.T) {
	var hookFired atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			OnEcho: func(c *server.Conn) error {
				hookFired.Store(true)
				return nil
			},
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := smb.EchoReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandEcho,
			Credits:       1,
			MessageID:     0,
			Signature:     make([]byte, 16),
		},
		StructureSize: 4,
	}
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
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
	bodyLen := binary.BigEndian.Uint32(lenBuf[:])
	resp := make([]byte, bodyLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read body: %v", err)
	}

	var res smb.EchoRes
	if err := res.UnmarshalBinary(resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Header.Status != smb.StatusOk {
		t.Errorf("status: got 0x%08x want 0", res.Header.Status)
	}
	if res.StructureSize != 4 {
		t.Errorf("StructureSize: got %d want 4", res.StructureSize)
	}
	if res.Header.Command != smb.CommandEcho {
		t.Errorf("Command: got 0x%x want CommandEcho", res.Header.Command)
	}
	if !hookFired.Load() {
		t.Errorf("OnEcho hook did not fire")
	}
}

// TestEchoAbortsOnHookError verifies that returning an error from the
// OnEcho hook tears down the connection without writing a reply.
func TestEchoAbortsOnHookError(t *testing.T) {
	srv := &server.Server{
		Config: &server.ServerConfig{
			OnEcho: func(c *server.Conn) error {
				return context.Canceled
			},
		},
	}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	req := smb.EchoReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandEcho,
			Credits:       1,
			Signature:     make([]byte, 16),
		},
		StructureSize: 4,
	}
	body, _ := req.MarshalBinary()
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [4]byte
	_, err = io.ReadFull(conn, lenBuf[:])
	if err == nil {
		t.Errorf("expected EOF/error after hook abort, got reply")
	}
}
