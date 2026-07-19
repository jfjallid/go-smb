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
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"testing"

	"github.com/jfjallid/go-smb/smb/encoder"
)

// TestNegotiateReqOffersSmb3_0 pins that the client advertises SMB 3.0 and
// 3.0.2 in addition to 3.1.1 and the 2.x dialects. Omitting 3.0/3.0.2 makes a
// server whose maximum is one of those dialects silently downgrade to 2.1,
// losing SMB3 signing (AES-CMAC) and encryption. The offer must also be in
// descending preference order so the server picks the strongest common dialect.
func TestNegotiateReqOffersSmb3_0(t *testing.T) {
	s := &Session{clientGuid: make([]byte, 16)}
	req, err := s.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq: %v", err)
	}

	for _, want := range []uint16{DialectSmb_3_1_1, DialectSmb_3_0_2, DialectSmb_3_0, DialectSmb_2_1, DialectSmb_2_0_2} {
		if !slices.Contains(req.Dialects, want) {
			t.Errorf("negotiate offer missing dialect 0x%04x; got %#x", want, req.Dialects)
		}
	}
	if int(req.DialectCount) != len(req.Dialects) {
		t.Errorf("DialectCount=%d, len(Dialects)=%d", req.DialectCount, len(req.Dialects))
	}

	// Descending preference: every dialect must be >= the one after it.
	if !slices.IsSortedFunc(req.Dialects, func(a, b uint16) int { return int(b) - int(a) }) {
		t.Errorf("dialects not in descending preference order: %#x", req.Dialects)
	}

	// DialectsSMB2Only must restrict the offer to 2.1 only.
	s.options.Dialects = DialectsSMB2Only
	req2, err := s.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq(DialectsSMB2Only): %v", err)
	}
	if len(req2.Dialects) != 1 || req2.Dialects[0] != DialectSmb_2_1 {
		t.Errorf("DialectsSMB2Only offer = %#x, want [0x0210]", req2.Dialects)
	}
}

// TestNegotiateReqCustomDialects verifies Options.Dialects overrides the offer
// verbatim and that the 3.1.1-only negotiate contexts are emitted only when
// 3.1.1 is actually offered.
func TestNegotiateReqCustomDialects(t *testing.T) {
	// Custom offer including 3.1.1: exact list, contexts present, 3.x caps.
	s := &Session{clientGuid: make([]byte, 16),
		options: Options{Dialects: []uint16{DialectSmb_3_1_1, DialectSmb_3_0}}}
	req, err := s.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq: %v", err)
	}
	if !slices.Equal(req.Dialects, []uint16{DialectSmb_3_1_1, DialectSmb_3_0}) {
		t.Errorf("custom offer = %#x, want [0x0311 0x0300]", req.Dialects)
	}
	if len(req.ContextList) == 0 {
		t.Error("offer with 3.1.1 must carry negotiate contexts")
	}
	if req.Capabilities&GlobalCapLargeMTU == 0 {
		t.Error("offer with 3.x must set GlobalCapLargeMTU")
	}

	// Custom offer without 3.1.1: no negotiate contexts (they are 3.1.1-only).
	s2 := &Session{clientGuid: make([]byte, 16),
		options: Options{Dialects: []uint16{DialectSmb_3_0, DialectSmb_2_1}}}
	req2, err := s2.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq(no 3.1.1): %v", err)
	}
	if len(req2.ContextList) != 0 {
		t.Errorf("offer without 3.1.1 must not carry negotiate contexts, got %d", len(req2.ContextList))
	}
}

// TestNegotiateContextOffsetAlignment checks the first negotiate context lands
// at a minimal, 8-byte-aligned offset — including the boundary case of a
// 2-dialect offer where the dialect array already ends on an 8-byte boundary
// (a spurious 8 bytes of padding here would still parse but is malformed).
func TestNegotiateContextOffsetAlignment(t *testing.T) {
	s := &Session{clientGuid: make([]byte, 16),
		options: Options{Dialects: []uint16{DialectSmb_3_1_1, DialectSmb_3_0}}}
	req, err := s.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq: %v", err)
	}
	buf, err := encoder.Marshal(&req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// NegotiateContextOffset is a uint32 at byte 92 (64 header + 28 into body).
	off := binary.LittleEndian.Uint32(buf[92:96])
	if off%8 != 0 {
		t.Errorf("NegotiateContextOffset %d is not 8-byte aligned", off)
	}
	// Minimal: 64 header + 36 fixed body + 2 dialects*2 bytes = 104, already
	// aligned, so no padding should be added.
	if off != 104 {
		t.Errorf("NegotiateContextOffset = %d, want 104 (no spurious padding)", off)
	}
}

// TestValidateOptionsDialects covers the Dialects validation: unknown revisions
// are rejected and a valid custom list is accepted.
func TestValidateOptionsDialects(t *testing.T) {
	base := Options{Host: "h", Port: 445, ManualLogin: true}

	valid := base
	valid.Dialects = []uint16{DialectSmb_3_1_1, DialectSmb_2_1}
	if err := validateOptions(valid); err != nil {
		t.Errorf("valid custom dialects rejected: %v", err)
	}

	unknown := base
	unknown.Dialects = []uint16{0x0400}
	if err := validateOptions(unknown); err == nil {
		t.Error("unknown dialect 0x0400 should be rejected")
	}
}

// TestSmb30KdfLabelBytes locks the exact SMB 3.0/3.0.2 KDF label and context
// byte strings (MS-SMB2 §3.1.4.2). These are the classic footgun: the C2S
// context "ServerIn " has a trailing space, and every string is
// NUL-terminated. A wrong byte here derives the wrong key and every signed or
// encrypted PDU is silently rejected by the server.
func TestSmb30KdfLabelBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"signing label", smb30LabelSigning, "SMB2AESCMAC\x00"},
		{"signing context", smb30ContextSigning, "SmbSign\x00"},
		{"cipher label", smb30LabelCipher, "SMB2AESCCM\x00"},
		{"c2s context", smb30ContextC2S, "ServerIn \x00"},
		{"s2c context", smb30ContextS2C, "ServerOut\x00"},
		{"app label", smb30LabelApp, "SMB2APP\x00"},
		{"app context", smb30ContextApp, "SmbRpc\x00"},
	} {
		if string(tc.got) != tc.want {
			t.Errorf("%s = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// TestSmb30KdfDerivation cross-checks that kdf() wired with the SMB 3.0
// constants produces the SP800-108 counter-mode output for the intended
// label/context. The expectation is recomputed here from literal correct bytes
// (independent of the smb30* package vars) so that changing a constant — e.g.
// dropping the trailing space in "ServerIn " — makes this test diverge.
func TestSmb30KdfDerivation(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 16)

	// Independent SP800-108 counter-mode (single iteration, L=128) with the
	// literal, spec-correct label/context bytes.
	expect := func(label, context string, L uint32) []byte {
		h := hmac.New(sha256.New, key)
		h.Write([]byte{0, 0, 0, 1}) // counter i=1, r=32
		h.Write([]byte(label))
		h.Write([]byte{0x00})
		h.Write([]byte(context))
		h.Write(binary.BigEndian.AppendUint32(nil, L))
		return h.Sum(nil)[:L/8]
	}

	for _, tc := range []struct {
		name           string
		label, context []byte
		wantL, wantCtx string
	}{
		{"signing", smb30LabelSigning, smb30ContextSigning, "SMB2AESCMAC\x00", "SmbSign\x00"},
		{"c2s", smb30LabelCipher, smb30ContextC2S, "SMB2AESCCM\x00", "ServerIn \x00"},
		{"s2c", smb30LabelCipher, smb30ContextS2C, "SMB2AESCCM\x00", "ServerOut\x00"},
		{"app", smb30LabelApp, smb30ContextApp, "SMB2APP\x00", "SmbRpc\x00"},
	} {
		got := kdf(key, tc.label, tc.context, 128)
		want := expect(tc.wantL, tc.wantCtx, 128)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: kdf mismatch\n got=%x\nwant=%x", tc.name, got, want)
		}
		if len(got) != 16 {
			t.Errorf("%s: key length %d, want 16", tc.name, len(got))
		}
	}
}
