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

// TestSessionBindingRejected verifies that a SessionSetup request with
// SMB2_SESSION_FLAG_BINDING (0x01) is rejected with STATUS_REQUEST_NOT_ACCEPTED
// per MS-SMB2 §3.3.5.5.2 — our server doesn't support multichannel.
//
// We bypass the in-tree client because it doesn't set the BINDING flag.
// The test does a minimum Negotiate handshake by hand, then synthesizes a
// SessionSetup1Req with the flag set.
func TestSessionBindingRejected(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{}}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The server's BINDING check (handleSessionSetup, MS-SMB2 §3.3.5.5.2)
	// runs before any dialect-dependent processing, so we can skip the
	// Negotiate handshake here and synthesize the SessionSetup PDU directly.

	// Hand-build a SessionSetup1Req with the BINDING flag set. We use the
	// raw layout (StructureSize=25, 4 zero bytes for the NegTokenInit blob)
	// because the server only inspects header fields and Flags/PreviousSessionID
	// before rejecting.
	body := make([]byte, 64+24+4) // header(64) + body fixed(24) + minimal blob(4)
	copy(body[0:4], []byte(smb.ProtocolSmb2))
	binary.LittleEndian.PutUint16(body[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(body[12:14], smb.CommandSessionSetup)
	binary.LittleEndian.PutUint16(body[14:16], 1) // credits
	binary.LittleEndian.PutUint64(body[24:32], 1) // MessageID = 1
	// body offset 0..2: StructureSize=25
	binary.LittleEndian.PutUint16(body[64:66], 25)
	body[66] = smb.SMB2_SESSION_FLAG_BINDING // Flags
	body[67] = 0                             // SecurityMode
	// Capabilities(4) at body+4, Channel(4) at body+8
	binary.LittleEndian.PutUint16(body[64+12:64+14], 88) // SecurityBufferOffset (== header+body fixed)
	binary.LittleEndian.PutUint16(body[64+14:64+16], 4)  // SecurityBufferLength
	// PreviousSessionID(8) at body+16: zero
	// Minimal SecurityBlob: 4 bytes of 0x60 0x00 0x00 0x00 (not actually
	// parsed before reject)
	body[88] = 0x60

	if err := writeNetBIOS(conn, body); err != nil {
		t.Fatalf("write session-setup: %v", err)
	}

	resp, err := readNetBIOS(conn)
	if err != nil {
		t.Fatalf("read session-setup reply: %v", err)
	}
	if len(resp) < 64 {
		t.Fatalf("reply too short: %d", len(resp))
	}
	got := binary.LittleEndian.Uint32(resp[8:12])
	if got != smb.StatusRequestNotAccepted {
		t.Errorf("status: got 0x%08x want STATUS_REQUEST_NOT_ACCEPTED (0xc00000d0)", got)
	}
}

func writeNetBIOS(conn net.Conn, body []byte) error {
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	_, err := conn.Write(frame)
	return err
}

func readNetBIOS(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var lenBuf [4]byte
	if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint32(lenBuf[:])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
