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
	"strings"
	"testing"
)

func TestDialectString(t *testing.T) {
	cases := map[uint16]string{
		DialectSmb_2_0_2: "2.0.2",
		DialectSmb_2_1:   "2.1",
		DialectSmb_3_0:   "3.0",
		DialectSmb_3_0_2: "3.0.2",
		DialectSmb_3_1_1: "3.1.1",
		0x0999:           "0x0999", // unknown -> hex fallback
	}
	for d, want := range cases {
		if got := DialectString(d); got != want {
			t.Errorf("DialectString(0x%04X) = %q, want %q", d, got, want)
		}
	}
	// The wildcard dialect renders with a recognizable label.
	if got := DialectString(DialectSmb2_ALL); !strings.Contains(got, "wildcard") {
		t.Errorf("DialectString(wildcard) = %q, want it to mention wildcard", got)
	}
}

func TestDialectsString(t *testing.T) {
	in := []uint16{DialectSmb_3_1_1, DialectSmb_3_0_2, DialectSmb_3_0}
	got := DialectsString(in)
	want := []string{"3.1.1", "3.0.2", "3.0"}
	if len(got) != len(want) {
		t.Fatalf("DialectsString len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DialectsString[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
