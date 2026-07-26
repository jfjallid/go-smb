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
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package smb

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestParseAccessMaskGenericBits pins every generic/standard bit to its name.
// The GENERIC_WRITE entry of accessMaskMap was previously written as 0x4000000
// — one zero short of 0x40000000 — so ParseAccessMask silently never reported
// GENERIC_WRITE and attributed it to the reserved bit 0x04000000 instead. That
// fed QueryInfoSecurity, i.e. every DACL this library reported.
func TestParseAccessMaskGenericBits(t *testing.T) {
	cases := []struct {
		mask uint32
		want string
	}{
		{FAccMaskGenericRead, AccessMaskGenericRead},
		{FAccMaskGenericWrite, AccessMaskGenericWrite},
		{FAccMaskGenericExecute, AccessMaskGenericExecute},
		{FAccMaskGenericAll, AccessMaskGenericAll},
		{FAccMaskMaximumAllowed, AccessMaskMaximumAllowed},
		{FAccMaskAccessSystemSecurity, AccessMaskAccessSystemSecurity},
		{FAccMaskSynchronize, AccessMaskSynchronize},
		{FAccMaskWriteOwner, AccessMaskWriteOwner},
		{FAccMaskWriteDac, AccessMaskWriteDACL},
		{FAccMaskReadControl, AccessMaskReadControl},
		{FAccMaskDelete, AccessMaskDelete},
	}
	for _, tc := range cases {
		got := ParseAccessMask(tc.mask)
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("ParseAccessMask(0x%08x) = %v, want [%s]", tc.mask, got, tc.want)
		}
	}

	// 0x04000000 is reserved and must map to nothing at all.
	if got := ParseAccessMask(0x04000000); len(got) != 0 {
		t.Errorf("ParseAccessMask(0x04000000) = %v, want [] (reserved bit)", got)
	}

	// A realistic combined mask must list every constituent.
	combined := FAccMaskGenericRead | FAccMaskGenericWrite | FAccMaskDelete
	got := ParseAccessMask(combined)
	want := []string{AccessMaskDelete, AccessMaskGenericRead, AccessMaskGenericWrite}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("ParseAccessMask(read|write|delete) = %v, want %v", got, want)
	}
}

// TestParseHeaderRejectsShortBuffer covers the guard behind every response
// path: parseHeader must reject a reply too short to hold a header rather than
// letting a buf[:64] slice panic on the caller's goroutine.
func TestParseHeaderRejectsShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, 63} {
		if _, err := parseHeader("Test", make([]byte, n)); err == nil {
			t.Errorf("parseHeader accepted a %d-byte buffer, want an error", n)
		}
	}
	buf := make([]byte, headerSize)
	copy(buf, []byte(ProtocolSmb2))
	buf[4] = 64 // StructureSize
	if _, err := parseHeader("Test", buf); err != nil {
		t.Errorf("parseHeader rejected a valid 64-byte header: %v", err)
	}
}

// TestCloseIsIdempotent covers the "defer c.Close()" plus explicit-Close
// pattern. Close used to call close(c.rdone) unguarded, so the second call
// panicked with "close of closed channel".
func TestCloseIsIdempotent(t *testing.T) {
	newConn := func() *Connection {
		c := &Connection{
			outstandingRequests: newOutstandingRequests(),
			rdone:               make(chan struct{}, 1),
			wdone:               make(chan struct{}, 1),
			write:               make(chan []byte, 1),
			werr:                make(chan error, 1),
		}
		c.Session = &Session{
			isSigningRequired: atomic.Bool{},
			trees:             make(map[string]*treeConnect),
			creditMgr:         newCreditManager(1),
		}
		return c
	}

	c := newConn()
	c.Close()
	c.Close() // must not panic
	c.Close()

	// Concurrent closes must be safe too.
	c2 := newConn()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c2.Close()
		}()
	}
	wg.Wait()
}

// TestNegotiateCipherNoneIsNotFatal documents the mapping for the cipher value
// a server returns when it shares no cipher with our offer (MS-SMB2 §3.3.5.4):
// 0x0000 means "encryption unavailable", not "unknown algorithm". The client
// used to fail NegotiateProtocol outright on it and so could not talk to such
// a server at all.
func TestNegotiateCipherNoneIsNotFatal(t *testing.T) {
	if CipherNone != 0x0000 {
		t.Fatalf("CipherNone = 0x%04x, want 0x0000", CipherNone)
	}
	for _, c := range []uint16{AES128CCM, AES128GCM, AES256CCM, AES256GCM} {
		if c == CipherNone {
			t.Errorf("cipher constant 0x%04x collides with CipherNone", c)
		}
	}
}

// shortHeaderResponse builds a minimal well-formed SMB2 response header with
// the given status, for the status-decoding helpers.
func shortHeaderResponse(status uint32) []byte {
	buf := make([]byte, headerSize)
	copy(buf, []byte(ProtocolSmb2))
	buf[4] = 64 // StructureSize low byte
	buf[8] = byte(status)
	buf[9] = byte(status >> 8)
	buf[10] = byte(status >> 16)
	buf[11] = byte(status >> 24)
	return buf
}

// TestHeaderStatusShortBuffer ensures the shared status helper reports a
// truncated reply as an error rather than panicking, on both the success and
// failure paths.
func TestHeaderStatusShortBuffer(t *testing.T) {
	if _, err := headerStatus("Echo", []byte{0x01, 0x02}); err == nil {
		t.Error("headerStatus accepted a 2-byte buffer, want an error")
	} else if !strings.Contains(err.Error(), "too short") {
		t.Errorf("unexpected error for short buffer: %v", err)
	}

	if _, err := headerStatus("Echo", shortHeaderResponse(StatusOk)); err != nil {
		t.Errorf("headerStatus on STATUS_OK returned %v, want nil", err)
	}
	if _, err := headerStatus("Echo", shortHeaderResponse(StatusAccessDenied)); err == nil {
		t.Error("headerStatus on STATUS_ACCESS_DENIED returned nil, want an error")
	}
}

// TestReserveContextCancels covers the cancellable credit wait. reserve is
// built on a sync.Cond, which can only be woken by a Broadcast, so a cancelled
// context must be translated into one — otherwise a caller blocked on a starved
// credit window would ignore cancellation entirely and hang for the full
// reserve timeout (60s by default).
func TestReserveContextCancels(t *testing.T) {
	cm := newCreditManager(0) // no credits: any reserve blocks

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- cm.reserveContext(ctx, 1, 0) }()

	// Give the reserve a moment to park on the cond.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("reserveContext returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserveContext ignored cancellation")
	}
}

// TestReserveContextDeadline is the same guarantee via a deadline.
func TestReserveContextDeadline(t *testing.T) {
	cm := newCreditManager(0)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	start := time.Now()
	err := cm.reserveContext(ctx, 1, 0)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reserveContext returned %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("reserveContext took %v to honor a 30ms deadline", elapsed)
	}
}

// TestReserveContextSucceedsWhenCreditsAvailable checks the happy path still
// works and that the watcher goroutine does not interfere.
func TestReserveContextSucceedsWhenCreditsAvailable(t *testing.T) {
	cm := newCreditManager(4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cm.reserveContext(ctx, 2, 0); err != nil {
		t.Fatalf("reserveContext with sufficient credits: %v", err)
	}
	if got := cm.available(); got != 2 {
		t.Errorf("balance after reserving 2 of 4 = %d, want 2", got)
	}
}

// TestSendrecvContextPreCancelled checks the cheap early-out: an
// already-cancelled context must fail before any bytes are put on the wire.
func TestSendrecvContextPreCancelled(t *testing.T) {
	c := &Connection{
		outstandingRequests: newOutstandingRequests(),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
	}
	c.Session = &Session{trees: make(map[string]*treeConnect), creditMgr: newCreditManager(1)}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := c.sendrecvContext(ctx, &EchoReq{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("sendrecvContext with a cancelled context returned %v, want context.Canceled", err)
	}
	// Nothing may have been queued for the sender.
	select {
	case pkt := <-c.write:
		t.Fatalf("a cancelled sendrecvContext still queued %d bytes for sending", len(pkt))
	default:
	}
}
