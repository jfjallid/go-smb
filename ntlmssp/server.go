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

package ntlmssp

import (
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/smb/encoder"
)

// Server is the acceptor side of an NTLMSSP exchange. It parses an inbound
// Negotiate message, generates a Challenge with a server challenge and
// TargetInfo AVPairs, and parses the inbound Authenticate. Verification of
// the Authenticate (HMAC compare against a stored NT hash) is left to the
// caller — see the Authenticator interface in smb/server.
type Server struct {
	// Configuration set by the caller before the first Accept call.
	TargetName      string // NTLMSSP TargetName (NetBIOS server name, default empty)
	NetBIOSName     string // for MsvAvNbComputerName AVPair
	NetBIOSDomain   string // for MsvAvNbDomainName  AVPair
	DnsComputerName string // for MsvAvDnsComputerName AVPair
	DnsDomainName   string // for MsvAvDnsDomainName AVPair

	// Server-side state populated as the exchange progresses.
	Challenge      [8]byte
	Negotiate      *Negotiate
	Authenticate   *Authenticate
	NegotiateFlags uint32 // flags chosen for the Challenge
	rawChallenge   []byte // serialized Challenge bytes (for downstream MIC validation)
}

// AcceptNegotiate parses an inbound NTLMSSP NEGOTIATE message and produces
// the corresponding NTLMSSP CHALLENGE message bytes (ready to wrap in a
// SPNEGO NegTokenResp). The server challenge is generated with crypto/rand.
func (s *Server) AcceptNegotiate(neg []byte) ([]byte, error) {
	if len(neg) < 16 || string(neg[:8]) != Signature {
		return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: not an NTLMSSP message")
	}
	hdr := Header{}
	if err := hdr.UnmarshalBinary(neg[:12]); err != nil {
		return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: header decode: %w", err)
	}
	if hdr.MessageType != TypeNtLmNegotiate {
		return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: expected message type 1, got %d", hdr.MessageType)
	}

	parsed := &Negotiate{}
	if err := parsed.UnmarshalBinary(neg); err != nil {
		return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: decode Negotiate: %w", err)
	}
	s.Negotiate = parsed

	if bytes.Equal(s.Challenge[:], make([]byte, 8)) {
		if _, err := rand.Read(s.Challenge[:]); err != nil {
			return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: rand: %w", err)
		}
	}

	chall := NewChallenge()

	// Compute the chosen NegotiateFlags from the intersection of what the
	// client offered and what the server is willing to accept.
	clientFlags := parsed.NegotiateFlags
	chall.NegotiateFlags = (clientFlags & supportedClientFlags) | mandatoryServerFlags
	// If the client offered Unicode prefer Unicode; otherwise OEM.
	if clientFlags&FlgNegUnicode != 0 {
		chall.NegotiateFlags |= FlgNegUnicode
		chall.NegotiateFlags &^= FlgNegOEM
	} else if clientFlags&FlgNegOEM != 0 {
		chall.NegotiateFlags |= FlgNegOEM
	}
	s.NegotiateFlags = chall.NegotiateFlags

	chall.ServerChallenge = binary.LittleEndian.Uint64(s.Challenge[:])

	// TargetName (NetBIOS server name) — Windows servers always populate this.
	if s.TargetName != "" {
		chall.TargetName = encoder.ToUnicode(s.TargetName)
	}

	// TargetInfo: a sequence of AVPairs providing identity / time stamps.
	avs := AvPairSlice{}
	addAv := func(id uint16, val []byte) {
		avs = append(avs, AvPair{AvID: id, AvLen: uint16(len(val)), Value: val})
	}
	// Windows rejects a CHALLENGE whose TargetInfo lacks the domain/DNS pairs.
	// Every real SMB server fills these in; a workgroup server uses its own name for
	// all four. Fall back to NetBIOSName rather than omitting the pair. Keep the
	// order MsvAvNbDomainName before MsvAvNbComputerName — that is what Windows
	// servers emit.
	//NOTE Might want to introduce a way to explicitly skip them if so desired
	nbDomain := orDefaultStr(s.NetBIOSDomain, s.NetBIOSName)
	dnsDomain := orDefaultStr(s.DnsDomainName, s.NetBIOSName)
	dnsComputer := orDefaultStr(s.DnsComputerName, s.NetBIOSName)
	if nbDomain != "" {
		addAv(MsvAvNbDomainName, encoder.ToUnicode(nbDomain))
	}
	if s.NetBIOSName != "" {
		addAv(MsvAvNbComputerName, encoder.ToUnicode(s.NetBIOSName))
	}
	if dnsDomain != "" {
		addAv(MsvAvDnsDomainName, encoder.ToUnicode(dnsDomain))
	}
	if dnsComputer != "" {
		addAv(MsvAvDnsComputerName, encoder.ToUnicode(dnsComputer))
	}
	tsBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(tsBuf, ConvertToFileTime(time.Now()))
	addAv(MsvAvTimestamp, tsBuf)
	addAv(MsvAvEOL, []byte{})
	chall.TargetInfo = &avs

	// Set version to a plausible Windows 10 build so clients that gate on
	// ChallengeVersion (smb/client.go:286 — serverBuild>6003) treat us as a
	// modern server.
	chall.Version = uint64(WINDOWS_MAJOR_VERSION_10) |
		uint64(WINDOWS_MINOR_VERSION_0)<<8 |
		uint64(19041)<<16 |
		uint64(NTLMSSP_REVISION_W2K3)<<56

	out, err := chall.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("ntlmssp: AcceptNegotiate: marshal Challenge: %w", err)
	}
	s.rawChallenge = make([]byte, len(out))
	copy(s.rawChallenge, out)
	return out, nil
}

// AcceptAuthenticate parses an inbound NTLMSSP AUTHENTICATE message into the
// Authenticate struct (stored on the Server) and returns it. Verification of
// the NT/LM responses is the caller's responsibility.
func (s *Server) AcceptAuthenticate(auth []byte) (*Authenticate, error) {
	if len(auth) < 12 || string(auth[:8]) != Signature {
		return nil, fmt.Errorf("ntlmssp: AcceptAuthenticate: not an NTLMSSP message")
	}
	hdr := Header{}
	if err := hdr.UnmarshalBinary(auth[:12]); err != nil {
		return nil, fmt.Errorf("ntlmssp: AcceptAuthenticate: header decode: %w", err)
	}
	if hdr.MessageType != TypeNtLmAuthenticate {
		return nil, fmt.Errorf("ntlmssp: AcceptAuthenticate: expected message type 3, got %d", hdr.MessageType)
	}

	parsed := &Authenticate{}
	if err := parsed.UnmarshalBinary(auth); err != nil {
		return nil, fmt.Errorf("ntlmssp: AcceptAuthenticate: decode Authenticate: %w", err)
	}
	s.Authenticate = parsed
	return parsed, nil
}

// RawChallenge returns the serialized NTLMSSP CHALLENGE message bytes that
// were sent on the wire. Useful for downstream MIC validation.
func (s *Server) RawChallenge() []byte {
	if s.rawChallenge == nil {
		return nil
	}
	out := make([]byte, len(s.rawChallenge))
	copy(out, s.rawChallenge)
	return out
}

// MakeSession constructs a server-side NTLMSSP Session bound to the flags
// negotiated by the parsed Authenticate message and the supplied exported
// session key. SPNEGO acceptors use this after a successful Verify to
// compute GSS_GetMIC (the MechListMIC required by RFC 4178 §5 when the
// initiator included one).
//
// AcceptAuthenticate must have run first so Authenticate.NegotiateFlags is
// available; the client's flags are authoritative because the client used
// them to derive its own signing/sealing keys.
func (s *Server) MakeSession(sessionKey []byte) (*Session, error) {
	if s.Authenticate == nil {
		return nil, fmt.Errorf("ntlmssp: Server.MakeSession: AcceptAuthenticate has not run")
	}
	flags := s.Authenticate.NegotiateFlags
	sess := &Session{
		isClientSide:       false,
		negotiateFlags:     flags,
		exportedSessionKey: sessionKey,
		clientSigningKey:   signKey(flags, sessionKey, true),
		serverSigningKey:   signKey(flags, sessionKey, false),
	}
	var err error
	if sess.clientHandle, err = rc4.NewCipher(sealKey(flags, sessionKey, true)); err != nil {
		return nil, fmt.Errorf("ntlmssp: Server.MakeSession: rc4 client: %w", err)
	}
	if sess.serverHandle, err = rc4.NewCipher(sealKey(flags, sessionKey, false)); err != nil {
		return nil, fmt.Errorf("ntlmssp: Server.MakeSession: rc4 server: %w", err)
	}
	return sess, nil
}

// IsAnonymous reports whether the parsed Authenticate represents an
// anonymous (null-session) login: empty UserName, empty NT/LM responses (or
// only the trivial 1-byte LM placeholder Windows sends).
func (s *Server) IsAnonymous() bool {
	if s.Authenticate == nil {
		return false
	}
	a := s.Authenticate
	return a.UserNameLen == 0 &&
		a.NtChallengeResponseLen == 0 &&
		(a.LmChallengeResponseLen == 0 || a.LmChallengeResponseLen == 1)
}

// supportedClientFlags lists the NTLMSSP flags we are willing to inherit from
// the client's NEGOTIATE.
const supportedClientFlags uint32 = FlgNegUnicode |
	FlgNegOEM |
	FlgNegRequestTarget |
	FlgNegSign |
	FlgNegSeal |
	// FlgNegLmKey deliberately NOT inherited: MS-NLMP §2.2.2.5 makes LM_KEY and
	// EXTENDED_SESSIONSECURITY mutually exclusive, and mandatoryServerFlags
	// always asserts EXTENDED_SESSIONSECURITY. Windows clients request both, so
	// inheriting LM_KEY would emit a spec-violating CHALLENGE.
	FlgNegNtLm |
	FlgNegAlwaysSign |
	FlgNegExtendedSessionSecurity |
	FlgNegTargetInfo |
	FlgNegVersion |
	FlgNeg128 |
	FlgNeg56 |
	FlgNegKeyExch

// mandatoryServerFlags are flags the server always asserts in the Challenge.
const mandatoryServerFlags uint32 = FlgNegRequestTarget |
	FlgNegTargetInfo |
	FlgNegTargetTypeServer |
	FlgNegNtLm |
	FlgNegExtendedSessionSecurity |
	FlgNegVersion

// orDefaultStr returns v when it is non-empty, otherwise def.
func orDefaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// silence unused-import warning when only some symbols are exported.
var _ = bytes.Equal
