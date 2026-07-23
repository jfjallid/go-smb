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

package spnego

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// driveAcceptorThroughAuth runs a full NTLM-over-SPNEGO exchange in-process:
// build a NegTokenInit with an NTLMSSP NEGOTIATE, hand it to the acceptor,
// take the resulting NegTokenResp out, feed its ResponseToken back to a
// matching ntlmssp.Client to get an AUTHENTICATE, then wrap that AUTHENTICATE
// in a final NegTokenResp (with or without a MechListMIC depending on
// includeInboundMIC) and feed it to the acceptor's second leg. Returns the
// acceptor's outbound bytes from the final leg.
func driveAcceptorThroughAuth(t *testing.T, includeInboundMIC bool) []byte {
	t.Helper()

	// Client side: produce a NEGOTIATE.
	client := &ntlmssp.Client{
		User:     "alice",
		Password: "p4ss",
		Domain:   "TESTDOM",
		Hash:     ntlmssp.Ntowfv1("p4ss"),
	}
	negMsg, err := client.Negotiate()
	if err != nil {
		t.Fatalf("client.Negotiate: %v", err)
	}

	// Acceptor side: build with a Verify callback that hands back a fixed
	// 16-byte session key so MakeSession can derive signing keys.
	fixedKey := bytes.Repeat([]byte{0xab}, 16)
	acceptor := &NTLMAcceptor{
		Server: &ntlmssp.Server{
			TargetName:      "TESTSRV",
			NetBIOSName:     "TESTSRV",
			NetBIOSDomain:   "TESTDOM",
			DnsComputerName: "testsrv.testdom.local",
			DnsDomainName:   "testdom.local",
		},
		Verify: func(_ *ntlmssp.Authenticate, _ [8]byte) ([]byte, uint32) {
			return fixedKey, 0
		},
	}

	// Leg 1: wrap NEGOTIATE in a NegTokenInit and feed it in.
	initBytes, err := gss.NewNegTokenInit(
		[]asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		negMsg,
	)
	if err != nil {
		t.Fatalf("NewNegTokenInit: %v", err)
	}
	out1, done, err := acceptor.AcceptSecContext(initBytes)
	if err != nil {
		t.Fatalf("AcceptSecContext leg1: %v", err)
	}
	if done {
		t.Fatalf("AcceptSecContext leg1: unexpectedly done")
	}

	// Leg 1 response is a NegTokenResp wrapping the CHALLENGE.
	var challResp gss.NegTokenResp
	if err := encoder.Unmarshal(out1, &challResp); err != nil {
		t.Fatalf("decode leg1 NegTokenResp: %v", err)
	}
	if len(challResp.ResponseToken) == 0 {
		t.Fatalf("leg1 NegTokenResp has no ResponseToken")
	}

	// Client side: consume CHALLENGE, produce AUTHENTICATE.
	authMsg, err := client.Authenticate(challResp.ResponseToken)
	if err != nil {
		t.Fatalf("client.Authenticate: %v", err)
	}

	// Leg 2: wrap AUTHENTICATE in a NegTokenResp. Toggle MechListMIC per
	// the parameter so the same driver covers both gate paths.
	respIn := gss.NegTokenResp{
		ResponseToken: authMsg,
	}
	if includeInboundMIC {
		// Any non-empty bytes suffice — acceptor only checks presence.
		respIn.MechListMIC = bytes.Repeat([]byte{0xcc}, 16)
	}
	in2, err := encoder.Marshal(&respIn)
	if err != nil {
		t.Fatalf("marshal leg2 NegTokenResp: %v", err)
	}
	out2, done, err := acceptor.AcceptSecContext(in2)
	if err != nil {
		t.Fatalf("AcceptSecContext leg2: %v", err)
	}
	if !done {
		t.Fatalf("AcceptSecContext leg2: expected done=true")
	}
	return out2
}

// TestAcceptorOmitsMIC_WhenInitiatorOmitted is the regression for the Windows
// Server 2019 2.0.2 disconnect: when the inbound NegTokenResp carries no
// MechListMIC, the acceptor must reply with the bare 9-byte accept-completed
// token — never an unsolicited MIC.
//
// Wire shape we expect:
//
//	a1 07           // [1] NegTokenResp, 7 bytes
//	  30 05         //   SEQUENCE, 5 bytes
//	    a0 03       //     [0] negState (explicit)
//	      0a 01 00  //       ENUMERATED 0 (accept-completed)
func TestAcceptorOmitsMIC_WhenInitiatorOmitted(t *testing.T) {
	out := driveAcceptorThroughAuth(t, false)
	want := []byte{0xa1, 0x07, 0x30, 0x05, 0xa0, 0x03, 0x0a, 0x01, 0x00}
	if !bytes.Equal(out, want) {
		t.Fatalf("acceptor leg2 output = % x (len=%d), want % x", out, len(out), want)
	}
}

// TestAcceptorIncludesMIC_WhenInitiatorIncluded verifies the existing
// smbclient code path: when the inbound NegTokenResp carries a MechListMIC,
// the acceptor still computes and returns one. We don't assert the exact MIC
// bytes (those depend on the negotiated NTLM session key), only that the
// MechListMIC field is present in the output token.
func TestAcceptorIncludesMIC_WhenInitiatorIncluded(t *testing.T) {
	out := driveAcceptorThroughAuth(t, true)
	var resp gss.NegTokenResp
	if err := encoder.Unmarshal(out, &resp); err != nil {
		t.Fatalf("decode acceptor output: %v", err)
	}
	if int(resp.State) != gss.GssStateAcceptCompleted {
		t.Fatalf("State = %d, want accept-completed (%d)", resp.State, gss.GssStateAcceptCompleted)
	}
	if len(resp.MechListMIC) == 0 {
		t.Fatalf("expected non-empty MechListMIC when initiator sent one")
	}
}

// newRawAcceptor builds an NTLMAcceptor whose Verify returns (verifyKey,
// verifyStatus). verifyKey==nil with status 0 mimics an anonymous accept.
func newRawAcceptor(verifyKey []byte, verifyStatus uint32) *NTLMAcceptor {
	return &NTLMAcceptor{
		Server: &ntlmssp.Server{
			TargetName:      "TESTSRV",
			NetBIOSName:     "TESTSRV",
			NetBIOSDomain:   "TESTDOM",
			DnsComputerName: "testsrv.testdom.local",
			DnsDomainName:   "testdom.local",
		},
		Verify: func(_ *ntlmssp.Authenticate, _ [8]byte) ([]byte, uint32) {
			return verifyKey, verifyStatus
		},
	}
}

// TestAcceptorRawNTLMSSP drives a bare (non-SPNEGO) NTLMSSP exchange as the
// Linux kernel CIFS client does: the leading token is an NTLMSSP NEGOTIATE with
// no SPNEGO wrapper. The acceptor must reply with a bare CHALLENGE (MessageType
// 2, no ASN.1), and on the AUTHENTICATE leg return an empty output token with a
// non-nil session key and Status 0 for good credentials.
func TestAcceptorRawNTLMSSP(t *testing.T) {
	client := &ntlmssp.Client{
		User:     "alice",
		Password: "p4ss",
		Domain:   "TESTDOM",
		Hash:     ntlmssp.Ntowfv1("p4ss"),
	}
	negMsg, err := client.Negotiate()
	if err != nil {
		t.Fatalf("client.Negotiate: %v", err)
	}

	fixedKey := bytes.Repeat([]byte{0xab}, 16)
	acceptor := newRawAcceptor(fixedKey, 0)

	// Leg 1: feed the bare NEGOTIATE directly (no NegTokenInit).
	out1, done, err := acceptor.AcceptSecContext(negMsg)
	if err != nil {
		t.Fatalf("AcceptSecContext leg1: %v", err)
	}
	if done {
		t.Fatalf("leg1 unexpectedly done")
	}
	// Output must be a bare CHALLENGE: signature + MessageType 2, no wrapper.
	if len(out1) < 12 || string(out1[:8]) != ntlmssp.Signature {
		t.Fatalf("leg1 output is not a bare NTLMSSP message: %x", out1[:min(12, len(out1))])
	}
	if mt := binary.LittleEndian.Uint32(out1[8:12]); mt != ntlmssp.TypeNtLmChallenge {
		t.Fatalf("leg1 output MessageType = %d, want CHALLENGE (%d)", mt, ntlmssp.TypeNtLmChallenge)
	}
	if out1[0] == 0x60 || out1[0] == 0xa1 || out1[0] == 0x30 {
		t.Fatalf("leg1 output looks ASN.1/SPNEGO-wrapped (first byte 0x%02x)", out1[0])
	}

	// Client consumes the bare CHALLENGE, produces an AUTHENTICATE.
	authMsg, err := client.Authenticate(out1)
	if err != nil {
		t.Fatalf("client.Authenticate: %v", err)
	}

	// Leg 2: feed the bare AUTHENTICATE directly.
	out2, done, err := acceptor.AcceptSecContext(authMsg)
	if err != nil {
		t.Fatalf("AcceptSecContext leg2: %v", err)
	}
	if !done {
		t.Fatalf("leg2 expected done=true")
	}
	if len(out2) != 0 {
		t.Fatalf("leg2 output token must be empty on the raw path, got %x", out2)
	}
	if acceptor.Status() != 0 {
		t.Fatalf("Status() = 0x%08x, want 0", acceptor.Status())
	}
	if len(acceptor.SessionKey()) == 0 {
		t.Fatalf("SessionKey() is empty, want non-nil for good credentials")
	}
	if acceptor.User() != "alice" {
		t.Fatalf("User() = %q, want alice", acceptor.User())
	}
}

// TestAcceptorRawNTLMSSP_BadCredentials verifies the raw path surfaces the
// Verify callback's failure status (and no session key) unchanged.
func TestAcceptorRawNTLMSSP_BadCredentials(t *testing.T) {
	const statusLogonFailure = 0xC000006D

	client := &ntlmssp.Client{User: "bob", Password: "wrong", Domain: "TESTDOM", Hash: ntlmssp.Ntowfv1("wrong")}
	negMsg, err := client.Negotiate()
	if err != nil {
		t.Fatalf("client.Negotiate: %v", err)
	}
	acceptor := newRawAcceptor(nil, statusLogonFailure)

	out1, _, err := acceptor.AcceptSecContext(negMsg)
	if err != nil {
		t.Fatalf("leg1: %v", err)
	}
	authMsg, err := client.Authenticate(out1)
	if err != nil {
		t.Fatalf("client.Authenticate: %v", err)
	}
	if _, done, err := acceptor.AcceptSecContext(authMsg); err != nil || !done {
		t.Fatalf("leg2: done=%v err=%v", done, err)
	}
	if acceptor.Status() != statusLogonFailure {
		t.Fatalf("Status() = 0x%08x, want 0x%08x", acceptor.Status(), statusLogonFailure)
	}
	if len(acceptor.SessionKey()) != 0 {
		t.Fatalf("SessionKey() should be empty on failure, got %x", acceptor.SessionKey())
	}
}
