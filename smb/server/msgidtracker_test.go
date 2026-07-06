// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server

import "testing"

// TestMsgIDTrackerDedup verifies the basic duplicate-detection contract: a
// fresh id is unseen (and recorded), and a repeat of it is reported as seen.
func TestMsgIDTrackerDedup(t *testing.T) {
	var tr msgIDTracker
	if tr.seen(1) {
		t.Fatal("first sight of id=1 reported as seen")
	}
	if !tr.seen(1) {
		t.Fatal("repeat of id=1 not reported as seen")
	}
	if tr.seen(2) {
		t.Fatal("first sight of id=2 reported as seen")
	}
	if !tr.seen(2) {
		t.Fatal("repeat of id=2 not reported as seen")
	}
}

// TestMsgIDTrackerBounded is the regression guard for finding #3: feeding an
// ever-increasing stream of MessageIds must not grow the tracker without
// bound. After 10*maxTrackedMsgIDs distinct insertions the retained set must
// stay within the two-generation cap (2*maxTrackedMsgIDs).
func TestMsgIDTrackerBounded(t *testing.T) {
	var tr msgIDTracker
	n := uint64(maxTrackedMsgIDs) * 10
	for i := uint64(0); i < n; i++ {
		if tr.seen(i) {
			t.Fatalf("distinct id %d falsely reported as seen", i)
		}
	}
	total := len(tr.cur) + len(tr.prev)
	if total > 2*maxTrackedMsgIDs {
		t.Fatalf("tracker retained %d entries, want <= %d (unbounded growth)", total, 2*maxTrackedMsgIDs)
	}
	// A recently-seen id (within the last generation) is still detected as a
	// duplicate, confirming the window remains useful after rotation.
	recent := n - 1
	if !tr.seen(recent) {
		t.Fatalf("recently-seen id %d not detected as duplicate after rotation", recent)
	}
}
