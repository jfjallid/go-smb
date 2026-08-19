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
	"testing"
	"time"
)

// TestCreditManagerReserveWithinBalance: a reserve that fits the balance
// consumes immediately without blocking, and the balance decreases by the
// (clamped) charge.
func TestCreditManagerReserveWithinBalance(t *testing.T) {
	cm := newCreditManager(10)
	if err := cm.reserve(4, 0); err != nil {
		t.Fatalf("reserve(4): %v", err)
	}
	if got := cm.available(); got != 6 {
		t.Errorf("balance after reserve(4) = %d, want 6", got)
	}
	// CreditCharge 0 is clamped to a minimum of 1 slot.
	if err := cm.reserve(0, 0); err != nil {
		t.Fatalf("reserve(0): %v", err)
	}
	if got := cm.available(); got != 5 {
		t.Errorf("balance after reserve(0) = %d, want 5", got)
	}
}

// TestCreditManagerReserveBlocksUntilGrant: a reserve larger than the balance
// blocks until a grant lifts the balance over the threshold.
func TestCreditManagerReserveBlocksUntilGrant(t *testing.T) {
	cm := newCreditManager(1)

	done := make(chan error, 1)
	go func() { done <- cm.reserve(8, 0) }()

	// The reserve must still be blocked (only 1 credit available).
	select {
	case <-done:
		t.Fatal("reserve(8) returned before sufficient credits were granted")
	case <-time.After(50 * time.Millisecond):
	}

	cm.grant(7) // balance 1 -> 8, enough for the pending reserve(8)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reserve(8) after grant: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve(8) did not unblock after grant")
	}
	if got := cm.available(); got != 0 {
		t.Errorf("balance after unblocked reserve(8) = %d, want 0", got)
	}
}

// TestCreditManagerShutdownUnblocks: shutdown wakes a blocked sender with an
// error rather than hanging on a dead connection.
func TestCreditManagerShutdownUnblocks(t *testing.T) {
	cm := newCreditManager(0)

	done := make(chan error, 1)
	go func() { done <- cm.reserve(1, 0) }()

	time.Sleep(50 * time.Millisecond)
	cm.shutdown()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reserve after shutdown returned nil, want error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve did not unblock after shutdown")
	}
}

// TestCreditManagerConcurrent exercises many concurrent reservers against a
// steady stream of grants; run under -race to catch balance data races. Every
// reserver must eventually succeed and the final balance must reconcile.
func TestCreditManagerConcurrent(t *testing.T) {
	cm := newCreditManager(0)
	const n = 50

	done := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() { done <- cm.reserve(2, 0) }()
	}

	// Feed grants incrementally; total granted == total reserved (n*2).
	go func() {
		for i := 0; i < n; i++ {
			cm.grant(2)
			time.Sleep(time.Millisecond)
		}
	}()

	for i := 0; i < n; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("concurrent reserve %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d reservers completed", i, n)
		}
	}
	if got := cm.available(); got != 0 {
		t.Errorf("final balance = %d, want 0 (all grants consumed)", got)
	}
}

// TestCreditManagerReserveTimeout: a reserve that the balance can never satisfy
// returns a timeout error rather than hanging forever, and does not consume
// the balance it failed to reserve.
func TestCreditManagerReserveTimeout(t *testing.T) {
	cm := newCreditManager(1)

	done := make(chan error, 1)
	go func() { done <- cm.reserve(8, 50*time.Millisecond) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("reserve(8) with 1 credit returned nil, want timeout error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve(8) did not time out")
	}
	// The failed reserve must leave the balance untouched.
	if got := cm.available(); got != 1 {
		t.Errorf("balance after timed-out reserve = %d, want 1", got)
	}
}

// TestCreditManagerReleaseReturnsCredits: release puts credits back so a
// subsequent reserve can use them, and it wakes a blocked reserver.
func TestCreditManagerReleaseReturnsCredits(t *testing.T) {
	cm := newCreditManager(4)
	if err := cm.reserve(4, 0); err != nil {
		t.Fatalf("reserve(4): %v", err)
	}
	if got := cm.available(); got != 0 {
		t.Fatalf("balance after reserve(4) = %d, want 0", got)
	}

	done := make(chan error, 1)
	go func() { done <- cm.reserve(3, 0) }()

	// Blocked: balance is 0.
	select {
	case <-done:
		t.Fatal("reserve(3) returned before credits were released")
	case <-time.After(50 * time.Millisecond):
	}

	cm.release(4) // return the earlier reservation; balance 0 -> 4
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("reserve(3) after release: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reserve(3) did not unblock after release")
	}
	if got := cm.available(); got != 1 {
		t.Errorf("balance after release(4)+reserve(3) = %d, want 1", got)
	}
}

// TestCreditManagerRequestSize: the advertised CreditRequest covers at least
// the charge (never net-shrink) and grows the post-reserve balance toward the
// target, saturating once the balance is at or above target.
func TestCreditManagerRequestSize(t *testing.T) {
	cases := []struct {
		name    string
		balance uint64
		charge  uint16
		target  uint64
		want    uint16
	}{
		{"grow from low balance", 8, 1, 512, 504},       // target - balance
		{"charge floors the request", 8, 600, 512, 600}, // max(charge, target-bal)
		{"at target, request == charge", 512, 4, 512, 4},
		{"above target, request == charge", 700, 2, 512, 2},
		{"zero charge clamps to one", 512, 0, 512, 1},
		{"request capped at uint16 max", 0, 1, 200000, 65535},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cm := newCreditManager(tc.balance)
			if got := cm.requestSize(tc.charge, tc.target); got != tc.want {
				t.Errorf("requestSize(%d, %d) with balance %d = %d, want %d",
					tc.charge, tc.target, tc.balance, got, tc.want)
			}
		})
	}
}

// TestCreditTargetOption: the resolved target honors an explicit option and
// falls back to the default when unset.
func TestCreditTargetOption(t *testing.T) {
	if got := (&Session{options: Options{CreditTarget: 128}}).creditTarget(); got != 128 {
		t.Errorf("creditTarget with option 128 = %d, want 128", got)
	}
	if got := (&Session{options: Options{}}).creditTarget(); got != defaultCreditTarget {
		t.Errorf("creditTarget with unset option = %d, want %d", got, defaultCreditTarget)
	}
}

// TestCreditWindowBytes: the byte ceiling tracks the balance at one credit per
// 64 KiB, less one credit of headroom, floored at one credit's worth.
func TestCreditWindowBytes(t *testing.T) {
	cases := []struct {
		credits uint64
		want    int
	}{
		{0, 65536},
		{1, 65536}, // floor wins over the holdback
		{2, 65536},
		{4, 196608},
		{16, 15 * 65536},
		{128, 127 * 65536},
	}
	for _, tc := range cases {
		s := &Session{creditMgr: newCreditManager(tc.credits)}
		if got := s.creditWindowBytes(); got != tc.want {
			t.Errorf("creditWindowBytes(%d credits) = %d, want %d", tc.credits, got, tc.want)
		}
	}
}

// TestCreditWindowLeavesHeadroom: when the window rather than MaxReadSize bounds
// a read, the resulting CreditCharge must not consume the whole balance. A client
// at zero credits with a request outstanding violates MS-SMB2 §3.2.4.1.2.
func TestCreditWindowLeavesHeadroom(t *testing.T) {
	const maxReadSize = 8 << 20

	for _, target := range []uint64{2, 8, 64, 127, 128, 129, 512} {
		s := &Session{creditMgr: newCreditManager(target)}

		// Mirror ReadFileContext's sizing: MaxReadSize capped by the window.
		size := maxReadSize
		if w := s.creditWindowBytes(); w < size {
			size = w
		}
		charge := uint64(calcCreditCharge(uint32(size)))

		if charge >= target && target > 1 {
			t.Errorf("CreditTarget %d: a single read charges %d of %d credits, draining the balance to zero",
				target, charge, target)
		}
	}
}
