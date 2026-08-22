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

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// TestNegotiateNoCommonDialect verifies that when a client offers only dialects
// the server does not allow, the server replies with a STATUS_NOT_SUPPORTED
// error response (MS-SMB2 §3.3.5.4) rather than silently dropping the
// connection.
func TestNegotiateNoCommonDialect(t *testing.T) {
	// Restrict the server to SMB 3.x so an SMB 2.0.2-only offer has no match.
	srv := &Server{
		Config: &ServerConfig{
			MinDialect: smb.DialectSmb_3_0,
			MaxDialect: smb.DialectSmb_3_1_1,
		},
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if err := <-serveErr; err != nil && err != ErrServerClosed {
			t.Errorf("Serve returned: %v", err)
		}
	}()

	conn, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Craft a minimal SMB2 NegotiateReq offering only SMB 2.0.2.
	hdr := smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		Command:       smb.CommandNegotiate,
		Credits:       1,
		MessageID:     0,
		Signature:     make([]byte, 16),
	}
	req := smb.NegotiateReq{
		Header:        hdr,
		StructureSize: 36,
		DialectCount:  1,
		SecurityMode:  smb.SecurityModeSigningEnabled,
		ClientGuid:    make([]byte, 16),
		Dialects:      []uint16{smb.DialectSmb_2_0_2},
	}
	body, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal NegotiateReq: %v", err)
	}

	// NetBIOS framing: 4-byte big-endian length prefix.
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write negotiate: %v", err)
	}

	// Read the framed response.
	var sizeBuf [4]byte
	if _, err := io.ReadFull(conn, sizeBuf[:]); err != nil {
		t.Fatalf("read response length: %v", err)
	}
	respLen := binary.BigEndian.Uint32(sizeBuf[:])
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	// The SMB2 header Status field is at byte offset 8 (ProtocolId(4) +
	// StructureSize(2) + CreditCharge(2)).
	if len(resp) < 12 {
		t.Fatalf("response too short: %d bytes", len(resp))
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb.StatusNotSupported {
		t.Errorf("status = 0x%08X, want STATUS_NOT_SUPPORTED (0x%08X)", status, smb.StatusNotSupported)
	}

	// The Command field (offset 12) must echo Negotiate.
	if cmd := binary.LittleEndian.Uint16(resp[12:14]); cmd != smb.CommandNegotiate {
		t.Errorf("command = %d, want Negotiate (%d)", cmd, smb.CommandNegotiate)
	}
}

// TestClientNegotiateNoCommonDialectStatus drives this repo's own client
// (smb.NewConnection) against a dialect-restricted server and asserts the
// client surfaces the server's STATUS_NOT_SUPPORTED as a typed NTStatusError
// rather than a misleading "unexpected EOF" from unmarshalling the short error
// PDU as a full NegotiateRes.
func TestClientNegotiateNoCommonDialectStatus(t *testing.T) {
	srv := &Server{
		Config: &ServerConfig{
			MinDialect: smb.DialectSmb_3_0,
			MaxDialect: smb.DialectSmb_3_1_1,
		},
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if err := <-serveErr; err != nil && err != ErrServerClosed {
			t.Errorf("Serve returned: %v", err)
		}
	}()

	addr := l.Addr().(*net.TCPAddr)
	opts := smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		ManualLogin: true,
		// Offer only SMB 2.0.2, which the 3.x-only server cannot honor. A
		// non-empty Dialects list forces the direct SMB2 negotiate path.
		Dialects:       []uint16{smb.DialectSmb_2_0_2},
		DisableSigning: true,
		Encryption:     smb.EncryptionDisabled,
		DialTimeout:    2 * time.Second,
	}

	c, err := smb.NewConnection(opts)
	if err == nil {
		c.Close()
		t.Fatal("NewConnection succeeded, want STATUS_NOT_SUPPORTED failure")
	}

	var nterr *smb.NTStatusError
	if !errors.As(err, &nterr) {
		t.Fatalf("error = %v (%T), want *smb.NTStatusError carrying STATUS_NOT_SUPPORTED", err, err)
	}
	if nterr.Status != smb.StatusNotSupported {
		t.Errorf("status = 0x%08X, want STATUS_NOT_SUPPORTED (0x%08X)", nterr.Status, smb.StatusNotSupported)
	}
}
