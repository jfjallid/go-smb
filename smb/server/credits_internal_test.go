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
	"testing"

	"github.com/jfjallid/go-smb/smb"
)

// TestGrantedCredits pins the server credit-grant policy: never grant fewer
// than the request consumed (CreditCharge, min 1), honor the client's
// CreditRequest, and cap the grant so the client's window stays bounded.
func TestGrantedCredits(t *testing.T) {
	for _, tc := range []struct {
		name        string
		charge, req uint16
		want        uint16
	}{
		{"typical single-credit op requesting a window", 1, 127, 127},
		{"zero charge clamps to 1", 0, 0, 1},
		{"grant replaces multi-credit charge when client asks for less", 8, 1, 8},
		{"request honored above charge", 4, 64, 64},
		{"grant capped at maxCreditGrant", 1, 60000, maxCreditGrant},
		{"charge above cap still granted (never starve consumed)", maxCreditGrant + 10, 1, maxCreditGrant + 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &smb.Header{CreditCharge: tc.charge, Credits: tc.req}
			if got := grantedCredits(h); got != tc.want {
				t.Errorf("grantedCredits(charge=%d,req=%d) = %d, want %d", tc.charge, tc.req, got, tc.want)
			}
		})
	}
}
