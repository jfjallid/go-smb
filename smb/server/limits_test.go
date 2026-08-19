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

// startBoundedServer brings up a server on an ephemeral port with the given
// config and returns its address plus a shutdown func.
func startBoundedServer(t *testing.T, cfg *ServerConfig) (string, func()) {
	t.Helper()
	srv := &Server{Config: cfg}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	return l.Addr().String(), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if err := <-serveErr; err != nil && err != ErrServerClosed {
			t.Errorf("Serve returned: %v", err)
		}
	}
}

// readsClosed reports whether the peer closed the connection within d. A read
// on an accepted-but-idle connection blocks; one on a closed connection returns
// io.EOF (or a reset) promptly.
func readsClosed(t *testing.T, c net.Conn, d time.Duration) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	var buf [1]byte
	_, err := c.Read(buf[:])
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false // still open, just quiet
	}
	return true // EOF or reset
}

// TestMaxConnectionsRefusesOverCap: the accept loop closes connections beyond
// MaxConnections instead of accepting work it cannot bound.
func TestMaxConnectionsRefusesOverCap(t *testing.T) {
	const cap = 3
	addr, stop := startBoundedServer(t, &ServerConfig{
		MaxConnections: cap,
		IdleTimeout:    -1, // don't let the idle reaper interfere
	})
	defer stop()

	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()

	// Fill the cap. These must stay open.
	for i := 0; i < cap; i++ {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
	}
	// Give the accept loop a moment to register all of them.
	time.Sleep(200 * time.Millisecond)
	for i, c := range held {
		if readsClosed(t, c, 200*time.Millisecond) {
			t.Fatalf("connection %d within the cap was closed", i)
		}
	}

	// The next one is over the cap and must be closed by the server.
	over, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		// A refused dial is an equally valid signal.
		return
	}
	defer over.Close()
	if !readsClosed(t, over, 3*time.Second) {
		t.Error("connection beyond MaxConnections was kept open, want closed")
	}
}

// TestMaxConnectionsAcceptsAfterRelease: capacity freed by a closed connection
// is reusable, i.e. the count tracks live connections rather than a total.
func TestMaxConnectionsAcceptsAfterRelease(t *testing.T) {
	addr, stop := startBoundedServer(t, &ServerConfig{
		MaxConnections: 1,
		IdleTimeout:    -1,
	})
	defer stop()

	first, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	first.Close()

	// Wait for the server to notice the close and release the slot.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		next, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err == nil {
			open := !readsClosed(t, next, 300*time.Millisecond)
			next.Close()
			if open {
				return // slot was reused
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Error("capacity was never released after the first connection closed")
}

// TestIdleTimeoutClosesQuietConnection: a peer that connects and sends nothing
// must be reaped rather than holding a goroutine and socket indefinitely.
func TestIdleTimeoutClosesQuietConnection(t *testing.T) {
	addr, stop := startBoundedServer(t, &ServerConfig{
		IdleTimeout: 300 * time.Millisecond,
	})
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if !readsClosed(t, c, 5*time.Second) {
		t.Error("idle connection was not closed within 5s of a 300ms IdleTimeout")
	}
}

// TestIdleTimeoutDisabled: a negative IdleTimeout means no reaping, so a quiet
// connection stays up.
func TestIdleTimeoutDisabled(t *testing.T) {
	addr, stop := startBoundedServer(t, &ServerConfig{IdleTimeout: -1})
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if readsClosed(t, c, 1*time.Second) {
		t.Error("connection was closed despite IdleTimeout being disabled")
	}
}

// TestBoundingDefaults pins the zero-value config to the documented defaults and
// the negative-means-disabled convention. A zero ServerConfig must still be
// bounded: that is the whole point of the defaults.
func TestBoundingDefaults(t *testing.T) {
	zero := &ServerConfig{}
	if got := zero.idleTimeout(); got != DefaultIdleTimeout {
		t.Errorf("zero idleTimeout = %v, want %v", got, DefaultIdleTimeout)
	}
	if got := zero.writeTimeout(); got != DefaultWriteTimeout {
		t.Errorf("zero writeTimeout = %v, want %v", got, DefaultWriteTimeout)
	}
	if got := zero.maxConnections(); got != DefaultMaxConnections {
		t.Errorf("zero maxConnections = %v, want %v", got, DefaultMaxConnections)
	}

	off := &ServerConfig{IdleTimeout: -1, WriteTimeout: -1, MaxConnections: -1}
	if got := off.idleTimeout(); got != 0 {
		t.Errorf("negative idleTimeout = %v, want 0 (disabled)", got)
	}
	if got := off.writeTimeout(); got != 0 {
		t.Errorf("negative writeTimeout = %v, want 0 (disabled)", got)
	}
	if got := off.maxConnections(); got > 0 {
		t.Errorf("negative maxConnections = %v, want <= 0 (unlimited)", got)
	}

	set := &ServerConfig{
		IdleTimeout:    7 * time.Second,
		WriteTimeout:   9 * time.Second,
		MaxConnections: 11,
	}
	if got := set.idleTimeout(); got != 7*time.Second {
		t.Errorf("explicit idleTimeout = %v, want 7s", got)
	}
	if got := set.writeTimeout(); got != 9*time.Second {
		t.Errorf("explicit writeTimeout = %v, want 9s", got)
	}
	if got := set.maxConnections(); got != 11 {
		t.Errorf("explicit maxConnections = %v, want 11", got)
	}
}

// TestIdleTimeoutIsPerRequestNotPerConnection: the deadline must be rearmed
// after each completed request, so a connection that keeps talking survives
// well past a single idle window.
func TestIdleTimeoutIsPerRequestNotPerConnection(t *testing.T) {
	addr, stop := startBoundedServer(t, &ServerConfig{
		IdleTimeout: 600 * time.Millisecond,
	})
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	// Drive three negotiates spaced under the idle window. Each completed
	// request must rearm the deadline; the total elapsed time exceeds it.
	for i := 0; i < 3; i++ {
		if err := writeNegotiate(c, uint64(i)); err != nil {
			t.Fatalf("negotiate %d: %v", i, err)
		}
		if _, err := readPDU(c, 2*time.Second); err != nil {
			t.Fatalf("read negotiate response %d: %v", i, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
	// Total elapsed is ~900ms against a 600ms window; still up.
	if readsClosed(t, c, 100*time.Millisecond) {
		t.Error("connection was reaped despite completing requests within each idle window")
	}
}

// writeNegotiate sends a minimal NetBIOS-framed NEGOTIATE offering SMB 2.1.
func writeNegotiate(c net.Conn, msgID uint64) error {
	req := smb.NegotiateReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandNegotiate,
			Credits:       1,
			MessageID:     msgID,
			Signature:     make([]byte, 16),
		},
		StructureSize: 36,
		DialectCount:  1,
		SecurityMode:  smb.SecurityModeSigningEnabled,
		ClientGuid:    make([]byte, 16),
		Dialects:      []uint16{smb.DialectSmb_2_1},
	}
	body, err := req.MarshalBinary()
	if err != nil {
		return err
	}
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
	copy(frame[4:], body)
	if err := c.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return err
	}
	_, err = c.Write(frame)
	return err
}

// readPDU reads one NetBIOS-framed PDU.
func readPDU(c net.Conn, d time.Duration) ([]byte, error) {
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		return nil, err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
