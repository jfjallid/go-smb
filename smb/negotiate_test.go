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
	"encoding/binary"
	"testing"

	"github.com/jfjallid/gofork/encoding/asn1"
	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
)

// TestNegotiateResContextOffsetZeroFor2_0_2 locks in the encoder fix: when a
// NegotiateRes is marshaled with an empty ContextList (as is the case for a
// 2.0.2 dialect reply), the NegotiateContextOffset wire bytes must be zero.
// Without the fix the encoder writes the would-be offset of ContextList
// (header + fixed body + SecurityBlob) instead of zero.
//
// NegotiateContextOffset sits at byte 128 of the marshaled buffer:
//
//	Header(64) + StructureSize(2) + SecurityMode(2) + DialectRevision(2)
//	+ NegotiateContextCount(2) + ServerGuid(16) + Capabilities(4)
//	+ MaxTransactSize(4) + MaxReadSize(4) + MaxWriteSize(4) + SystemTime(8)
//	+ ServerStartTime(8) + SecurityBufferOffset(2) + SecurityBufferLength(2)
//	= 124, so NegotiateContextOffset occupies bytes [124:128].
func TestNegotiateResContextOffsetZeroFor2_0_2(t *testing.T) {
	res := NewNegotiateRes()
	res.Header.Command = CommandNegotiate
	res.DialectRevision = DialectSmb_2_0_2
	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}
	res.ContextList = nil

	buf, err := encoder.Marshal(res)
	if err != nil {
		t.Fatalf("Marshal NegotiateRes: %v", err)
	}

	const offsetPos = 124
	if len(buf) < offsetPos+4 {
		t.Fatalf("marshaled buffer too short: %d bytes", len(buf))
	}
	got := binary.LittleEndian.Uint32(buf[offsetPos : offsetPos+4])
	if got != 0 {
		t.Fatalf("NegotiateContextOffset = 0x%x, want 0 for 2.0.2 reply", got)
	}
	count := binary.LittleEndian.Uint16(buf[70:72])
	if count != 0 {
		t.Fatalf("NegotiateContextCount = %d, want 0", count)
	}
}

// TestNegotiateReqContextOffsetAligned locks in the wire-format invariant
// that MS-SMB2 §2.2.3 requires: when a 3.1.1 NegotiateReq carries negotiate
// contexts, the NegotiateContextOffset must be an 8-byte aligned absolute
// offset from the start of the SMB2 header. A strict server (Windows)
// rejects an unaligned request with STATUS_INVALID_PARAMETER.
//
// Regression coverage: a previous version of session.go called c.send with a
// NegotiateReq value (not a pointer). Because *NegotiateReq.MarshalBinary
// has a pointer receiver, the type assertion in encoder.Marshal failed and
// the encoder silently fell through to tag-based marshaling, which packs the
// contexts immediately after the dialect list without the required padding.
// The resulting wire bytes placed the contexts at offset 106 instead of 112.
//
// This test parametrizes on both the pointer and value call paths so any
// future change that re-introduces the value-marshal regression (either by
// changing the call site or by changing the MarshalBinary receiver in a way
// that breaks pointer-marshal) is caught here.
func TestNegotiateReqContextOffsetAligned(t *testing.T) {
	build := func() NegotiateReq {
		pic, _ := encoder.Marshal(PreauthIntegrityContext{
			HashAlgorithmCount: 1,
			HashAlgorithms:     []uint16{SHA512},
			SaltLength:         32,
			Salt:               make([]byte, 32),
		})
		ec, _ := encoder.Marshal(EncryptionContext{
			CipherCount: 4,
			Ciphers:     []uint16{AES128CCM, AES128GCM, AES256CCM, AES256GCM},
		})
		sc, _ := encoder.Marshal(SigningContext{
			SigningAlgorithmCount: 3,
			SigningAlgorithms:     []uint16{AES_GMAC, AES_CMAC, HMAC_SHA256},
		})
		return NegotiateReq{
			Header: Header{
				ProtocolID:    []byte(ProtocolSmb2),
				StructureSize: 64,
				Command:       CommandNegotiate,
				Credits:       1,
				Signature:     make([]byte, 16),
			},
			StructureSize: 36,
			DialectCount:  3,
			SecurityMode:  SecurityModeSigningEnabled,
			Capabilities:  GlobalCapLargeMTU | GlobalCapEncryption,
			ClientGuid:    make([]byte, 16),
			Dialects:      []uint16{DialectSmb_3_1_1, DialectSmb_2_1, DialectSmb_2_0_2},
			ContextList: []NegContext{
				{ContextType: PreauthIntegrityCapabilities, Data: pic, DataLength: uint16(len(pic)), Padd: make([]byte, (8-len(pic)%8)%8)},
				{ContextType: EncryptionCapabilities, Data: ec, DataLength: uint16(len(ec)), Padd: make([]byte, (8-len(ec)%8)%8)},
				{ContextType: SigningCapabilities, Data: sc, DataLength: uint16(len(sc))},
			},
			NegotiateContextCount: 3,
		}
	}

	cases := []struct {
		name    string
		marshal func(req NegotiateReq) ([]byte, error)
	}{
		{"pointer", func(req NegotiateReq) ([]byte, error) { return encoder.Marshal(&req) }},
		{"value", func(req NegotiateReq) ([]byte, error) { return encoder.Marshal(req) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := build()
			buf, err := tc.marshal(req)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			// NegotiateContextOffset sits at byte 92 of the marshaled buffer:
			//	Header(64) + StructureSize(2) + DialectCount(2) + SecurityMode(2)
			//	+ Reserved(2) + Capabilities(4) + ClientGuid(16) = 92.
			const offsetPos = 92
			if len(buf) < offsetPos+4 {
				t.Fatalf("marshaled buffer too short: %d bytes", len(buf))
			}
			got := binary.LittleEndian.Uint32(buf[offsetPos : offsetPos+4])
			if got%8 != 0 {
				t.Fatalf("NegotiateContextOffset=%d (0x%x) not 8-byte aligned — Windows servers will reject with STATUS_INVALID_PARAMETER",
					got, got)
			}
			// And it must actually point past the dialects (start of body + 36
			// + 2*DialectCount = 100 + 6 = 106; the next aligned position is 112).
			if got < 106 {
				t.Errorf("NegotiateContextOffset=%d, want >= 106 (past dialects)", got)
			}
			// Bytes between the dialect list and the first context must be
			// zero padding — anything else means a stale field leaked through.
			for i := 106; i < int(got); i++ {
				if buf[i] != 0 {
					t.Errorf("non-zero alignment pad at offset %d: 0x%02x", i, buf[i])
				}
			}
		})
	}
}

// TestSessionSetupSecurityModeRequired pins MS-SMB2 §2.2.5: a client that
// requires signing MUST set SecurityMode to (SIGNING_ENABLED | SIGNING_REQUIRED)
// = 0x03, not SIGNING_REQUIRED alone (0x02). REQUIRED without ENABLED is
// contradictory ("I require signatures but don't support them") and strict
// servers (Windows) respond by TCP-RST'ing the connection rather than sending
// an SMB error reply.
//
// Regression coverage: an earlier version of (*Connection).NewSessionSetup1Req
// and NewSessionSetup2Req wrote 0x02 alone when isSigningRequired was true,
// which kept SessionSetup working against lenient servers (go-smb's own server,
// Samba) but caused Windows hosts to drop the connection without a reply.
func TestSessionSetupSecurityModeRequired(t *testing.T) {
	ntlm := &spnego.NTLMInitiator{User: "u", Password: "p"}
	spnegoClient, err := spnego.NewClient([]gss.Mechanism{ntlm})
	if err != nil {
		t.Fatalf("spnego.NewClient: %v", err)
	}

	for _, tc := range []struct {
		name           string
		signingRequired bool
		wantMode       byte
	}{
		{"signing_required", true, byte(SecurityModeSigningEnabled | SecurityModeSigningRequired)},
		{"signing_optional", false, byte(SecurityModeSigningEnabled)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &Connection{Session: &Session{}}
			conn.isSigningRequired.Store(tc.signingRequired)
			ssreq, err := conn.NewSessionSetup1Req(spnegoClient)
			if err != nil {
				t.Fatalf("NewSessionSetup1Req: %v", err)
			}
			if ssreq.SecurityMode != tc.wantMode {
				t.Errorf("SessionSetup1Req SecurityMode = 0x%02x, want 0x%02x", ssreq.SecurityMode, tc.wantMode)
			}
			// NewSessionSetup2Req parses a NegTokenResp blob; build a
			// well-formed one so we exercise the post-parse path that sets
			// SecurityMode.
			resp := gss.NegTokenResp{
				State:         asn1.Enumerated(gss.GssStateAcceptIncomplete),
				ResponseToken: []byte{0x00},
			}
			respBlob, err := encoder.Marshal(&resp)
			if err != nil {
				t.Fatalf("marshal NegTokenResp: %v", err)
			}
			ss2req, err := conn.NewSessionSetup2Req(respBlob, &SessionSetup1Res{})
			if err != nil {
				t.Fatalf("NewSessionSetup2Req: %v", err)
			}
			if ss2req.SecurityMode != tc.wantMode {
				t.Errorf("SessionSetup2Req SecurityMode = 0x%02x, want 0x%02x", ss2req.SecurityMode, tc.wantMode)
			}
		})
	}
}
