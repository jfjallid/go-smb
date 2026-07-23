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
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// Acceptor is the server-side counterpart to Client: it processes inbound
// SPNEGO tokens and produces outbound ones. v1 supports NTLMSSP only.
//
// AcceptSecContext returns the next outbound token plus a "done" flag. When
// done==true the exchange has reached a terminal state — the caller should
// inspect SessionKey() to distinguish success (non-nil) from rejection
// (nil). Plumbing failures (decode errors, malformed tokens) are returned as
// err.
type Acceptor interface {
	AcceptSecContext(inputToken []byte) (outputToken []byte, done bool, err error)
	SessionKey() []byte
	User() string
	Domain() string
	Workstation() string
	IsAnonymous() bool
}

// NTLMAuthCallback is invoked by NTLMAcceptor once the AUTHENTICATE message
// has been parsed. It returns the derived 16-byte session key and an NT
// status. Callers map non-zero status to the appropriate SMB error
// (typically smb.StatusLogonFailure). Returning a nil sessionKey with status
// 0 (StatusOk) is allowed for null/anonymous sessions.
type NTLMAuthCallback func(auth *ntlmssp.Authenticate, serverChallenge [8]byte) (sessionKey []byte, status uint32)

// NTLMAcceptor wraps an ntlmssp.Server in SPNEGO framing. After construction,
// callers populate Server (with TargetName/NetBIOSName/etc.) and Verify, then
// drive the exchange via AcceptSecContext.
type NTLMAcceptor struct {
	Server *ntlmssp.Server
	Verify NTLMAuthCallback

	// State populated as the exchange progresses.
	sessionKey   []byte
	status       uint32
	user         string
	domain       string
	workstation  string
	leg          int                     // 0 = nothing yet, 1 = challenge sent, 2 = auth processed
	offeredMechs []asn1.ObjectIdentifier // mech list from the inbound NegTokenInit (input to MechListMIC)
	// raw reports that this exchange is bare NTLMSSP (no SPNEGO framing) —
	// set when the first token carries the "NTLMSSP\0" signature rather than
	// a NegTokenInit/NegTokenResp. The Linux kernel CIFS client sends this
	// form. On the raw path the CHALLENGE is returned unwrapped and no RFC
	// 4178 MechListMIC is produced (there is no mech list).
	raw bool
}

// AcceptSecContext processes one round of SPNEGO. The first call expects a
// NegTokenInit wrapping an NTLMSSP NEGOTIATE; subsequent calls expect a
// NegTokenResp wrapping an NTLMSSP AUTHENTICATE.
func (a *NTLMAcceptor) AcceptSecContext(inputToken []byte) ([]byte, bool, error) {
	if a.Server == nil {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: Server is nil")
	}
	if len(inputToken) == 0 {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: empty input token")
	}

	// Bare NTLMSSP (no SPNEGO wrapper). The Linux kernel CIFS client sends
	// the NTLMSSP token directly, prefixed with the "NTLMSSP\0" signature and
	// a 4-byte little-endian MessageType. Detect it by signature before the
	// SPNEGO tag switch — 0x4e ('N') collides with neither 0x60 nor 0xa1.
	if len(inputToken) >= 12 && string(inputToken[:8]) == ntlmssp.Signature {
		a.raw = true
		switch binary.LittleEndian.Uint32(inputToken[8:12]) {
		case ntlmssp.TypeNtLmNegotiate:
			return a.acceptRawNegotiate(inputToken)
		case ntlmssp.TypeNtLmAuthenticate:
			return a.acceptRawAuthenticate(inputToken)
		default:
			return nil, false, fmt.Errorf("spnego.NTLMAcceptor: unexpected raw NTLMSSP MessageType %d", binary.LittleEndian.Uint32(inputToken[8:12]))
		}
	}

	switch inputToken[0] {
	case 0x60: // NegTokenInit (first leg)
		return a.acceptInit(inputToken)
	case 0xa1: // NegTokenResp (second+ leg)
		return a.acceptResp(inputToken)
	default:
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: unknown token tag 0x%02x", inputToken[0])
	}
}

// acceptRawNegotiate handles leg 1 of a bare (non-SPNEGO) NTLMSSP exchange:
// the input token IS the NTLMSSP NEGOTIATE. It returns the CHALLENGE bytes
// unwrapped — no NegTokenResp framing — so the reply matches the bare request.
func (a *NTLMAcceptor) acceptRawNegotiate(buf []byte) ([]byte, bool, error) {
	chall, err := a.Server.AcceptNegotiate(buf)
	if err != nil {
		return nil, false, err
	}
	a.leg = 1
	return chall, false, nil
}

// acceptRawAuthenticate handles leg 2 of a bare NTLMSSP exchange: the input
// token IS the NTLMSSP AUTHENTICATE. It runs the shared verification tail and
// returns an empty output token (bare NTLM has no terminal SPNEGO message and
// no MechListMIC).
func (a *NTLMAcceptor) acceptRawAuthenticate(buf []byte) ([]byte, bool, error) {
	auth, err := a.Server.AcceptAuthenticate(buf)
	if err != nil {
		return nil, false, err
	}
	a.finishAuthenticate(auth)
	a.leg = 2
	return nil, true, nil
}

// acceptInit parses a NegTokenInit, checks that NTLMSSP is among the offered
// MechTypes, runs the embedded NTLMSSP NEGOTIATE through the ntlmssp.Server,
// and wraps the resulting Challenge in a NegTokenResp.
func (a *NTLMAcceptor) acceptInit(buf []byte) ([]byte, bool, error) {
	var init gss.NegTokenInit
	if err := encoder.Unmarshal(buf, &init); err != nil {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: decode NegTokenInit: %w", err)
	}

	hasNTLM := false
	for _, mt := range init.Data.MechTypes {
		if mt.Equal(gss.NtLmSSPMechTypeOid) {
			hasNTLM = true
			break
		}
	}
	if !hasNTLM {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: client did not offer NTLMSSP among %v", init.Data.MechTypes)
	}
	// Capture the offered mech list — the MechListMIC (RFC 4178 §5) is
	// computed over its asn1-encoded form on both sides.
	a.offeredMechs = init.Data.MechTypes

	if len(init.Data.MechToken) == 0 {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: NegTokenInit has empty MechToken")
	}
	chall, err := a.Server.AcceptNegotiate(init.Data.MechToken)
	if err != nil {
		return nil, false, err
	}

	resp := gss.NegTokenResp{
		State:         asn1.Enumerated(gss.GssStateAcceptIncomplete),
		SupportedMech: gss.NtLmSSPMechTypeOid,
		ResponseToken: chall,
	}
	out, err := encoder.Marshal(&resp)
	if err != nil {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: marshal NegTokenResp: %w", err)
	}
	a.leg = 1
	return out, false, nil
}

// acceptResp parses a NegTokenResp, runs its ResponseToken through
// ntlmssp.Server.AcceptAuthenticate, then invokes Verify to produce a
// session key / status. The outbound token is a NegTokenResp signaling
// accept-completed or reject.
func (a *NTLMAcceptor) acceptResp(buf []byte) ([]byte, bool, error) {
	var resp gss.NegTokenResp
	if err := encoder.Unmarshal(buf, &resp); err != nil {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: decode NegTokenResp: %w", err)
	}
	if len(resp.ResponseToken) == 0 {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: NegTokenResp has empty ResponseToken")
	}

	auth, err := a.Server.AcceptAuthenticate(resp.ResponseToken)
	if err != nil {
		return nil, false, err
	}

	a.finishAuthenticate(auth)
	sessionKey := a.sessionKey
	status := a.status

	out := gss.NegTokenResp{}
	if status == 0 {
		out.State = asn1.Enumerated(gss.GssStateAcceptCompleted)
	} else {
		out.State = asn1.Enumerated(gss.GssStateReject)
	}
	// RFC 4178 §5: when authentication succeeds and we have a non-anonymous
	// session key, return a MechListMIC computed over the asn1-encoded mech
	// list the initiator offered. Without this, signing-required clients
	// (e.g. smbclient) fail SessionSetup with NT_STATUS_ACCESS_DENIED.
	//
	// However, only emit a MIC when the initiator included one in its own
	// NegTokenResp. Sending an unsolicited MIC causes Windows clients that
	// did not negotiate SPNEGO integrity (notably Windows Server 2019 over
	// SMB 2.0.2 without signing) to reject the SessionSetup response and
	// drop the connection. Mirroring the initiator matches Impacket and
	// RFC 4178 §5 ("the acceptor SHOULD NOT generate a MIC" when the
	// preferred mechanism was selected and the initiator omitted one).
	if status == 0 && len(sessionKey) > 0 && len(a.offeredMechs) > 0 && len(resp.MechListMIC) > 0 {
		ms, mErr := asn1.Marshal(a.offeredMechs)
		if mErr != nil {
			return nil, false, fmt.Errorf("spnego.NTLMAcceptor: marshal mechTypes for MIC: %w", mErr)
		}
		ntlmSess, sErr := a.Server.MakeSession(sessionKey)
		if sErr != nil {
			return nil, false, fmt.Errorf("spnego.NTLMAcceptor: ntlmssp session: %w", sErr)
		}
		mic, _ := ntlmSess.Sum(ms, 0)
		if mic != nil {
			out.MechListMIC = mic
		}
	}
	outBytes, err := marshalFinalNegTokenResp(out)
	if err != nil {
		return nil, false, fmt.Errorf("spnego.NTLMAcceptor: marshal NegTokenResp: %w", err)
	}
	a.leg = 2
	return outBytes, true, nil
}

// finishAuthenticate is the framing-agnostic tail shared by acceptResp (SPNEGO)
// and acceptRawAuthenticate (bare NTLMSSP): it decodes the identity fields from
// the parsed AUTHENTICATE, invokes the Verify callback, and records the derived
// session key and NT status on the acceptor. It emits no output token and does
// not touch the RFC 4178 MechListMIC (which is SPNEGO-only and lives in
// acceptResp).
func (a *NTLMAcceptor) finishAuthenticate(auth *ntlmssp.Authenticate) {
	// Decode failures here mean the client sent malformed UTF-16 — Debugf,
	// not Errorf, since attackers can spam this. Fall back to empty so the
	// rest of authentication proceeds (the Verify callback gets the raw
	// bytes via the auth message).
	var fuErr error
	if a.user, fuErr = encoder.FromUnicodeString(auth.UserName); fuErr != nil {
		log.Debugf("spnego.NTLMAcceptor: decode UserName: %v", fuErr)
	}
	if a.domain, fuErr = encoder.FromUnicodeString(auth.DomainName); fuErr != nil {
		log.Debugf("spnego.NTLMAcceptor: decode DomainName: %v", fuErr)
	}
	if a.workstation, fuErr = encoder.FromUnicodeString(auth.Workstation); fuErr != nil {
		log.Debugf("spnego.NTLMAcceptor: decode Workstation: %v", fuErr)
	}

	var (
		sessionKey []byte
		status     uint32
	)
	if a.Verify != nil {
		sessionKey, status = a.Verify(auth, a.Server.Challenge)
	}
	a.sessionKey = sessionKey
	a.status = status
}

// finalNegTokenResp is the wire shape for the acceptor's terminal
// NegTokenResp. It mirrors gss.NegTokenResp but drops omitempty from State so
// that AcceptCompleted (=0) is encoded explicitly rather than dropped — Windows
// (and the RFC 4178 spec) require negState to be present in the final token,
// otherwise the response degenerates to an empty SEQUENCE that some clients
// reject.
type finalNegTokenResp struct {
	State         asn1.Enumerated       `asn1:"explicit,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,omitempty,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// marshalFinalNegTokenResp produces the [1] CONTEXT-tagged ASN.1 bytes
// matching gss.NegTokenResp's wire format, but with the negState always
// emitted (see finalNegTokenResp). Mirrors gss.gsswrapped: marshal a single-
// field outer struct so asn1 emits `30 LL <NegTokenResp SEQUENCE>`, then
// rewrite the outer tag to 0xa1 ([1] CONTEXT) per RFC 4178.
func marshalFinalNegTokenResp(r gss.NegTokenResp) ([]byte, error) {
	w := struct {
		G finalNegTokenResp
	}{
		G: finalNegTokenResp{
			State:         r.State,
			SupportedMech: r.SupportedMech,
			ResponseToken: r.ResponseToken,
			MechListMIC:   r.MechListMIC,
		},
	}
	buf, err := asn1.Marshal(w)
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("spnego: empty NegTokenResp encoding")
	}
	buf[0] = 0xa1
	return buf, nil
}

func (a *NTLMAcceptor) SessionKey() []byte { return a.sessionKey }
func (a *NTLMAcceptor) User() string       { return a.user }
func (a *NTLMAcceptor) Domain() string     { return a.domain }
func (a *NTLMAcceptor) Workstation() string {
	return a.workstation
}
func (a *NTLMAcceptor) IsAnonymous() bool {
	return a.Server != nil && a.Server.IsAnonymous()
}

// Status returns the NT status from the most recent Verify callback (0 if
// authentication has not yet occurred).
func (a *NTLMAcceptor) Status() uint32 { return a.status }
