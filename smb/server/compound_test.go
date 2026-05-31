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
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

// TestCompoundEcho sends two SMB2 Echo PDUs compounded in a single NetBIOS
// frame (NextCommand on the first segment) and verifies the server returns
// two replies, also compounded. Echo is allowed pre-auth so we don't need
// SessionSetup to exercise the chain walker.
func TestCompoundEcho(t *testing.T) {
	var echoCount atomic.Int32
	srv := &server.Server{
		Config: &server.ServerConfig{
			OnEcho: func(c *server.Conn) error {
				echoCount.Add(1)
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

	// Build two Echo PDUs. The first carries NextCommand pointing at the
	// second (8-byte aligned offset from start of PDU#1).
	pduSize := 64 + 4 // Echo body is 4 bytes (StructureSize=4, Reserved=0)
	// 8-align pduSize for NextCommand
	pad := (8 - (pduSize % 8)) % 8
	pdu1Total := pduSize + pad

	pdu1 := buildEchoPDU(t, 0, uint32(pdu1Total))
	pdu1 = append(pdu1, make([]byte, pad)...)
	pdu2 := buildEchoPDU(t, 1, 0) // last in chain: NextCommand=0

	buf := append([]byte{}, pdu1...)
	buf = append(buf, pdu2...)

	frame := make([]byte, 4+len(buf))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(buf)))
	copy(frame[4:], buf)
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

	// First reply: NextCommand must point at the second reply.
	if len(resp) < 64+4 {
		t.Fatalf("response too short: %d", len(resp))
	}
	next := binary.LittleEndian.Uint32(resp[20:24])
	if next == 0 {
		t.Fatalf("first reply has NextCommand=0; expected pointer to second reply")
	}
	if next%8 != 0 {
		t.Errorf("first reply NextCommand=%d not 8-aligned", next)
	}
	if int(next) > len(resp) {
		t.Fatalf("first reply NextCommand=%d > resp len %d", next, len(resp))
	}
	if int(next) < 64+4 {
		t.Errorf("first reply NextCommand=%d too small (header+echo body = 68)", next)
	}

	// Second reply: NextCommand must be zero.
	second := resp[next:]
	if len(second) < 64+4 {
		t.Fatalf("second reply too short: %d", len(second))
	}
	if got := binary.LittleEndian.Uint32(second[20:24]); got != 0 {
		t.Errorf("second reply NextCommand=%d want 0", got)
	}

	// Sanity-check MessageIDs were echoed.
	if got := binary.LittleEndian.Uint64(resp[24:32]); got != 0 {
		t.Errorf("first reply MessageID=%d want 0", got)
	}
	if got := binary.LittleEndian.Uint64(second[24:32]); got != 1 {
		t.Errorf("second reply MessageID=%d want 1", got)
	}

	if got := echoCount.Load(); got != 2 {
		t.Errorf("OnEcho hook fired %d times, expected 2 (one per PDU in compound)", got)
	}
}

func buildEchoPDU(t *testing.T, msgID uint64, nextCmd uint32) []byte {
	t.Helper()
	req := smb.EchoReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandEcho,
			Credits:       1,
			NextCommand:   nextCmd,
			MessageID:     msgID,
			Signature:     make([]byte, 16),
		},
		StructureSize: 4,
	}
	body, err := encoder.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}
