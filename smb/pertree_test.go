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
	"testing"

	"github.com/jfjallid/go-smb/smb/crypto/ccm"
)

// TestTreeConnectAttributesAndEncryptLookup verifies the per-tree bookkeeping
// added in Phase 2: TreeConnectInfo surfaces the ShareFlags/Capabilities/
// MaximalAccess captured from the TREE_CONNECT reply, and treeId /
// treeIdEncrypts resolve the right entry (including the per-share ENCRYPT_DATA
// flag) by name and by TreeId.
func TestTreeConnectAttributesAndEncryptLookup(t *testing.T) {
	s := &Session{
		trees: map[string]*treeConnect{
			"data": {treeId: 1, shareFlags: 0, capabilities: ShareCapDFS, maximalAccess: 0x1f01ff},
			"secret": {
				treeId:      2,
				shareFlags:  ShareFlagEncryptData,
				encryptData: true,
			},
		},
	}

	if got := s.treeId("secret"); got != 2 {
		t.Errorf("treeId(secret) = %d, want 2", got)
	}
	if got := s.treeId("missing"); got != 0 {
		t.Errorf("treeId(missing) = %d, want 0 sentinel", got)
	}
	if !s.hasTree("data") || s.hasTree("missing") {
		t.Errorf("hasTree wrong: data=%v missing=%v", s.hasTree("data"), s.hasTree("missing"))
	}

	flags, caps, maximal, ok := s.TreeConnectInfo("data")
	if !ok || flags != 0 || caps != ShareCapDFS || maximal != 0x1f01ff {
		t.Errorf("TreeConnectInfo(data) = (0x%x,0x%x,0x%x,%v)", flags, caps, maximal, ok)
	}
	if _, _, _, ok := s.TreeConnectInfo("missing"); ok {
		t.Errorf("TreeConnectInfo(missing) ok = true, want false")
	}

	// treeIdEncrypts keys on TreeId, not name.
	if !s.treeIdEncrypts(2) {
		t.Errorf("treeIdEncrypts(2) = false, want true (ENCRYPT_DATA share)")
	}
	if s.treeIdEncrypts(1) {
		t.Errorf("treeIdEncrypts(1) = true, want false")
	}
	if s.treeIdEncrypts(0) {
		t.Errorf("treeIdEncrypts(0) = true, want false (0 is the not-found sentinel)")
	}
}

// TestCanEncrypt pins the exact condition under which the client will engage
// per-tree encryption: encryption must be supported, not opted out via
// EncryptionDisabled, and an encrypter must be initialized. The
// EncryptionDisabled case is the important one — supportsEncryption can be true
// from the negotiate context alone, but the server derives no decrypter unless
// the client advertised GlobalCapEncryption, so encrypting anyway would produce
// undecryptable traffic.
func TestCanEncrypt(t *testing.T) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := ccm.NewCCMWithNonceAndTagSizes(block, 11, 16)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		supports   bool
		disabled   bool
		hasEnc     bool
		wantResult bool
	}{
		{"fully negotiated", true, false, true, true},
		{"disabled by option", true, true, true, false},
		{"not supported", false, false, true, false},
		{"no encrypter built", true, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{supportsEncryption: tc.supports}
			if tc.disabled {
				s.options.Encryption = EncryptionDisabled
			}
			if tc.hasEnc {
				s.encrypter = enc
			}
			if got := s.canEncrypt(); got != tc.wantResult {
				t.Errorf("canEncrypt() = %v, want %v", got, tc.wantResult)
			}
		})
	}
}
