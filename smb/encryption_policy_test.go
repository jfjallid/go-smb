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
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/jfjallid/go-smb/smb/crypto/ccm"
	"github.com/jfjallid/go-smb/spnego"
)

// testAEAD builds a throwaway encrypter. Only its non-nil-ness matters here:
// canEncrypt requires one, and applyEncryptionPolicy keys off canEncrypt.
func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	aead, err := ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// baseOpts returns the minimum Options that pass validateOptions, so each case
// below varies only the encryption fields under test.
func baseOpts() Options {
	return Options{
		Host:      "127.0.0.1",
		Port:      445,
		Initiator: &spnego.NTLMInitiator{User: "u", Password: "p"},
	}
}

// TestValidateOptionsEncryptionCombinations covers the encryption
// misconfigurations that are decidable before dialing. Catching them in
// validateOptions matters because the alternative is what this whole change
// fixes: an unmet encryption demand that produces a working plaintext
// connection and no diagnostic.
func TestValidateOptionsEncryptionCombinations(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(*Options)
		wantErr bool
		// wantSentinel asserts the error carries ErrEncryptionNotNegotiated so
		// callers can distinguish "cannot encrypt" from any other config error.
		wantSentinel bool
	}{
		{
			name:   "defaults are valid",
			mutate: func(o *Options) {},
		},
		{
			name:   "each policy is valid on its own",
			mutate: func(o *Options) { o.Encryption = EncryptionServerDirected },
		},
		{
			name:   "required alone is valid",
			mutate: func(o *Options) { o.Encryption = EncryptionRequired },
		},
		{
			name:   "disabled alone is valid",
			mutate: func(o *Options) { o.Encryption = EncryptionDisabled },
		},
		{
			name:    "an out-of-range policy is rejected",
			mutate:  func(o *Options) { o.Encryption = EncryptionPolicy(42) },
			wantErr: true,
		},
		{
			name: "required with an SMB 2.x-only dialect offer is unsatisfiable",
			mutate: func(o *Options) {
				o.Encryption = EncryptionRequired
				o.Dialects = DialectsSMB2Only
			},
			wantErr:      true,
			wantSentinel: true,
		},
		{
			name: "required with 2.0.2 and 2.1 only is unsatisfiable",
			mutate: func(o *Options) {
				o.Encryption = EncryptionRequired
				o.Dialects = []uint16{DialectSmb_2_1, DialectSmb_2_0_2}
			},
			wantErr:      true,
			wantSentinel: true,
		},
		{
			name: "required with a mixed offer containing 3.x is fine",
			mutate: func(o *Options) {
				o.Encryption = EncryptionRequired
				o.Dialects = []uint16{DialectSmb_3_1_1, DialectSmb_2_1}
			},
		},
		{
			// Only EncryptionRequired is unsatisfiable on a 2.x-only offer; the
			// other policies degrade to plaintext there by design.
			name: "server-directed with a 2.x-only offer is fine",
			mutate: func(o *Options) {
				o.Encryption = EncryptionServerDirected
				o.Dialects = DialectsSMB2Only
			},
		},
		{
			name: "disabled with a 2.x-only offer is fine",
			mutate: func(o *Options) {
				o.Encryption = EncryptionDisabled
				o.Dialects = DialectsSMB2Only
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opt := baseOpts()
			tc.mutate(&opt)
			err := validateOptions(opt)
			if tc.wantErr && err == nil {
				t.Fatalf("validateOptions() = nil, want an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateOptions() = %v, want nil", err)
			}
			if tc.wantSentinel && !errors.Is(err, ErrEncryptionNotNegotiated) {
				t.Errorf("validateOptions() = %v, want it to wrap ErrEncryptionNotNegotiated", err)
			}
		})
	}
}

// TestNegotiateReqEncryptionOffer pins that EncryptionDisabled removes
// encryption from the negotiation itself rather than only from the send path.
// Both halves matter: a server derives no decrypter without
// SMB2_GLOBAL_CAP_ENCRYPTION, and it answers with an EncryptionCapabilities
// context only when the client sent one (MS-SMB2 §3.3.5.4), so leaving the
// context in would still select a cipher neither side intends to use.
func TestNegotiateReqEncryptionOffer(t *testing.T) {
	hasCtx := func(req NegotiateReq, want uint16) bool {
		for _, ctx := range req.ContextList {
			if ctx.ContextType == want {
				return true
			}
		}
		return false
	}

	// Every policy but EncryptionDisabled must negotiate a cipher.
	// EncryptionServerDirected in particular needs one: without it an
	// ENCRYPT_DATA share becomes unreachable, which is the whole distinction
	// between that policy and EncryptionDisabled.
	for _, policy := range []EncryptionPolicy{EncryptionPreferred, EncryptionServerDirected, EncryptionRequired} {
		t.Run(policy.String()+" offers encryption", func(t *testing.T) {
			s := &Session{clientGuid: make([]byte, 16)}
			s.options.Encryption = policy
			req, err := s.NewNegotiateReq()
			if err != nil {
				t.Fatalf("NewNegotiateReq: %v", err)
			}
			if req.Capabilities&GlobalCapEncryption == 0 {
				t.Errorf("Capabilities=0x%08x, want SMB2_GLOBAL_CAP_ENCRYPTION set", req.Capabilities)
			}
			if !hasCtx(req, EncryptionCapabilities) {
				t.Errorf("negotiate offer has no EncryptionCapabilities context")
			}
		})
	}

	t.Run("EncryptionDisabled offers none", func(t *testing.T) {
		s := &Session{clientGuid: make([]byte, 16)}
		s.options.Encryption = EncryptionDisabled
		req, err := s.NewNegotiateReq()
		if err != nil {
			t.Fatalf("NewNegotiateReq: %v", err)
		}
		if req.Capabilities&GlobalCapEncryption != 0 {
			t.Errorf("Capabilities=0x%08x, want SMB2_GLOBAL_CAP_ENCRYPTION clear", req.Capabilities)
		}
		if hasCtx(req, EncryptionCapabilities) {
			t.Errorf("negotiate offer carries an EncryptionCapabilities context despite EncryptionDisabled")
		}
		// The other 3.1.1 contexts must survive: preauth integrity is mandatory
		// and dropping the signing context would silently downgrade signing.
		if !hasCtx(req, PreauthIntegrityCapabilities) {
			t.Errorf("PreauthIntegrityCapabilities context went missing")
		}
		if !hasCtx(req, SigningCapabilities) {
			t.Errorf("SigningCapabilities context went missing")
		}
		if int(req.NegotiateContextCount) != len(req.ContextList) {
			t.Errorf("NegotiateContextCount=%d, len(ContextList)=%d", req.NegotiateContextCount, len(req.ContextList))
		}
	})
}

// TestApplyEncryptionPolicy walks the four policies against every combination
// of "can this connection encrypt" and "did the server demand it". The send
// path gates on SessionFlagEncryptData alone (connection.go), so the bit must
// track the policy exactly: set it without an encrypter and the client emits
// traffic it cannot produce; leave it clear when an encrypter exists and the
// prefer-where-available default silently degrades to plaintext.
func TestApplyEncryptionPolicy(t *testing.T) {
	for _, tc := range []struct {
		name          string
		policy        EncryptionPolicy
		canEncrypt    bool
		serverDemands bool
		guest         bool
		wantEncrypt   bool
		wantErr       bool
	}{
		// Preferred: encrypt whenever possible, plaintext otherwise.
		{name: "preferred encrypts when able", policy: EncryptionPreferred, canEncrypt: true, wantEncrypt: true},
		{name: "preferred encrypts even unasked", policy: EncryptionPreferred, canEncrypt: true, serverDemands: false, wantEncrypt: true},
		{name: "preferred falls back to plaintext", policy: EncryptionPreferred, canEncrypt: false, wantEncrypt: false},

		// ServerDirected: encrypt only what the server asked for. The
		// can-encrypt-but-not-asked case is the one that distinguishes this
		// policy from the default.
		{name: "server-directed stays plaintext when unasked", policy: EncryptionServerDirected, canEncrypt: true, serverDemands: false, wantEncrypt: false},
		{name: "server-directed honors the server demand", policy: EncryptionServerDirected, canEncrypt: true, serverDemands: true, wantEncrypt: true},
		{name: "server-directed is plaintext with no cipher", policy: EncryptionServerDirected, canEncrypt: false, serverDemands: false, wantEncrypt: false},

		// A demand we cannot meet is an error, not a silent downgrade: the
		// server rejects every subsequent request, so plaintext only defers the
		// failure to a point where the cause is no longer visible.
		{name: "server-directed fails on an unmeetable demand", policy: EncryptionServerDirected, canEncrypt: false, serverDemands: true, wantErr: true},
		{name: "preferred fails on an unmeetable demand", policy: EncryptionPreferred, canEncrypt: false, serverDemands: true, wantErr: true},

		// Required: encrypt or fail.
		{name: "required encrypts when able", policy: EncryptionRequired, canEncrypt: true, wantEncrypt: true},
		{name: "required fails without an encrypter", policy: EncryptionRequired, canEncrypt: false, wantErr: true},

		// Disabled: never encrypt, and never carry a server verdict we cannot
		// honor through to the send path.
		{name: "disabled never encrypts", policy: EncryptionDisabled, canEncrypt: false, wantEncrypt: false},
		{name: "disabled clears a server demand", policy: EncryptionDisabled, canEncrypt: false, serverDemands: true, wantEncrypt: false},

		// Guest and anonymous sessions have no key to encrypt with.
		{name: "guest never encrypts", policy: EncryptionPreferred, guest: true, wantEncrypt: false},
		{name: "guest under server-directed stays plaintext", policy: EncryptionServerDirected, guest: true, serverDemands: true, wantEncrypt: false},
		{name: "guest fails an encryption requirement", policy: EncryptionRequired, guest: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{supportsEncryption: tc.canEncrypt}
			s.options.Encryption = tc.policy
			if tc.canEncrypt {
				s.encrypter = testAEAD(t)
			}
			if tc.serverDemands {
				s.sessionFlags |= SessionFlagEncryptData
			}
			if tc.guest {
				s.sessionFlags |= SessionFlagIsGuest
			}
			c := &Connection{Session: s}

			err := c.applyEncryptionPolicy()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("applyEncryptionPolicy() = nil, want an error")
				}
				if !errors.Is(err, ErrEncryptionNotNegotiated) {
					t.Errorf("applyEncryptionPolicy() = %v, want it to wrap ErrEncryptionNotNegotiated", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("applyEncryptionPolicy() error: %v", err)
			}
			got := s.sessionFlags&SessionFlagEncryptData != 0
			if got != tc.wantEncrypt {
				t.Errorf("SessionFlagEncryptData = %v, want %v", got, tc.wantEncrypt)
			}
		})
	}
}
