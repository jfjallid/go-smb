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
	"context"
	"fmt"
	"sync"
	"time"
)

// creditManager implements the client half of MS-SMB2 credit-based flow
// control (§3.2.4.1.2, §3.2.5.1.4). The server grants credits in every
// response; each request consumes CreditCharge credits from the balance. A
// client that sends without available credits is a protocol violation that
// strict servers answer by dropping the connection, so senders block here until
// the receiver has granted enough.
type creditManager struct {
	mu      sync.Mutex
	cond    *sync.Cond
	balance uint64
	closed  bool
}

// newCreditManager seeds the balance with the connection's initial credits.
// MS-SMB2 §3.2.4.1.6 starts Connection.SequenceWindow at 1, so the client may
// always send its first request (the NEGOTIATE) before any grant arrives.
func newCreditManager(initial uint64) *creditManager {
	cm := &creditManager{balance: initial}
	cm.cond = sync.NewCond(&cm.mu)
	return cm
}

// grant credits the balance with the Credits field of a received response and
// wakes any senders blocked in reserve. A grant of 0 is a no-op.
func (cm *creditManager) grant(n uint16) {
	if n == 0 {
		return
	}
	cm.mu.Lock()
	cm.balance += uint64(n)
	cm.mu.Unlock()
	cm.cond.Broadcast()
}

// reserve consumes charge credits, blocking until the balance can cover them.
// charge is clamped to a minimum of 1 because every request consumes at least
// one sequence-window slot (MS-SMB2 §3.2.4.1.6). It returns an error if the
// connection is torn down while waiting, or if timeout elapses first. A
// timeout <= 0 waits indefinitely (relying on shutdown to unblock a dead
// connection). The timeout turns a credit starvation that would otherwise hang
// the caller forever — a large request the server never grants enough credits
// for, or an unfair wakeup that keeps losing the balance to other senders —
// into a loud error instead of a silent deadlock.
func (cm *creditManager) reserve(charge uint16, timeout time.Duration) error {
	return cm.reserveContext(context.Background(), charge, timeout)
}

// reserveContext is reserve with cancellation. Because the wait is built on a
// sync.Cond — which can only be woken by a Broadcast — a cancellable wait needs
// a watcher goroutine to issue that Broadcast when ctx fires; the loop then
// re-evaluates and returns ctx.Err(). The watcher is torn down on every exit
// path so a satisfied reserve leaves nothing running.
func (cm *creditManager) reserveContext(ctx context.Context, charge uint16, timeout time.Duration) error {
	need := uint64(charge)
	if need == 0 {
		need = 1
	}

	if done := ctx.Done(); done != nil {
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			select {
			case <-done:
				cm.cond.Broadcast()
			case <-stop:
			}
		}()
	}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
		// cond.Wait can only be woken by a Broadcast, so schedule one at the
		// deadline to re-evaluate the loop condition and return the timeout
		// error. Stop it on the way out so a satisfied reserve doesn't leave a
		// timer (and a spurious broadcast) pending.
		t := time.AfterFunc(timeout, cm.cond.Broadcast)
		defer t.Stop()
	}

	for cm.balance < need {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for %d credits: %w", need, err)
		}
		if cm.closed {
			return fmt.Errorf("connection closed while waiting for %d credits", need)
		}
		if timeout > 0 && !time.Now().Before(deadline) {
			return fmt.Errorf("timed out after %s waiting for %d credits (have %d)", timeout, need, cm.balance)
		}
		cm.cond.Wait()
	}
	cm.balance -= need
	return nil
}

// release returns credits taken by a prior reserve whose request never reached
// the server (a marshalling / signing / send failure after the reserve). The
// clamp mirrors reserve so the balance reconciles exactly. Without this the
// credits would be lost — no response will ever arrive to grant them back — and
// enough such failures would starve the window into a deadlock.
func (cm *creditManager) release(charge uint16) {
	n := uint64(charge)
	if n == 0 {
		n = 1
	}
	cm.mu.Lock()
	cm.balance += n
	cm.mu.Unlock()
	cm.cond.Broadcast()
}

// shutdown unblocks every waiting sender with an error. Called when the
// receive loop exits so reserve callers don't hang on a dead connection.
func (cm *creditManager) shutdown() {
	cm.mu.Lock()
	cm.closed = true
	cm.mu.Unlock()
	cm.cond.Broadcast()
}

// requestSize computes the CreditRequest a request should advertise (the
// header Credits field). It is the "ask for more" half of the Windows credit
// strategy: the server grants up to what the client asks, so a client that
// requests toward a target on every request grows and then holds a healthy
// window instead of draining toward zero.
//
// It returns at least charge — MS-SMB2 §3.2.4.1.2 recommends CreditRequest >=
// CreditCharge so a single operation never net-shrinks the window — and enough
// beyond that to refill the (post-reserve) balance up to target. charge is the
// amount already reserved for this request.
func (cm *creditManager) requestSize(charge uint16, target uint64) uint16 {
	need := uint64(charge)
	if need == 0 {
		need = 1
	}
	cm.mu.Lock()
	bal := cm.balance
	cm.mu.Unlock()

	req := need
	if bal < target {
		if grow := target - bal; grow > req {
			req = grow
		}
	}
	if req > 65535 {
		req = 65535
	}
	return uint16(req)
}

// creditTarget resolves the desired credit balance from the session options,
// falling back to defaultCreditTarget when unset.
func (s *Session) creditTarget() uint64 {
	if s.options.CreditTarget > 0 {
		return uint64(s.options.CreditTarget)
	}
	return defaultCreditTarget
}

// creditReserveTimeout resolves the per-request credit wait ceiling from the
// session options: an explicit positive value is used as-is, a negative value
// means wait forever, and zero selects the package default.
func (s *Session) creditReserveTimeout() time.Duration {
	switch {
	case s.options.CreditReserveTimeout > 0:
		return s.options.CreditReserveTimeout
	case s.options.CreditReserveTimeout < 0:
		return 0 // wait indefinitely
	default:
		return defaultCreditReserveTimeout
	}
}

// available returns the current credit balance. Intended for tests and
// diagnostics; the value is a point-in-time snapshot.
func (cm *creditManager) available() uint64 {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	return cm.balance
}

// creditWindowBytes reports how many bytes of a single READ/WRITE the currently
// granted credit balance can cover — one credit per 64 KiB (MS-SMB2 §3.1.5.2).
// Capping a transfer to this keeps its CreditCharge within the granted window,
// so reserve never waits on a charge the balance cannot reach.
//
// One credit is held back: MS-SMB2 §3.2.4.1.2 requires a non-zero balance while
// a request is outstanding, and a request charging the entire balance leaves the
// server unable to validate the next MessageId. Floored at 65536 so a balance of
// 1 still makes progress, since splitting further is impossible there.
func (s *Session) creditWindowBytes() int {
	if s.creditMgr == nil {
		return 65536
	}
	avail := s.creditMgr.available()
	// Clamp before the multiply so the byte count can't overflow int; any real
	// MaxReadSize/MaxWriteSize is far smaller and bounds the result anyway.
	const maxCredits = uint64((1<<31 - 1) / 65536)
	if avail > maxCredits {
		avail = maxCredits
	}
	if avail > 1 {
		avail-- // headroom: never let one request take the last credit
	}
	if bytes := int(avail) * 65536; bytes >= 65536 {
		return bytes
	}
	return 65536
}
