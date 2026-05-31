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
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// Authenticator verifies an NTLMSSP AUTHENTICATE message. Returning a
// non-nil sessionKey and status==smb.StatusOk authenticates the session
// (sessionKey is the 16-byte exported session key used to derive signing
// and encryption keys). Returning a non-zero status fails the
// authentication; status is sent back to the client (typically
// smb.StatusLogonFailure).
//
// The default Authenticator is AlwaysFailAuthenticator: it captures the
// hash but always returns logon-failure. Use MapAuthenticator (or your own
// implementation) to allow real logons against a stored NT-hash table.
type Authenticator interface {
	Verify(c *Conn, auth *ntlmssp.Authenticate, serverChallenge [8]byte) (sessionKey []byte, status uint32)
}

// AlwaysFailAuthenticator is the default Authenticator: it captures the
// hash via OnCredentialCaptured (raised by the SessionSetup handler) and
// always returns smb.StatusLogonFailure. Suitable for honeypot deployments.
type AlwaysFailAuthenticator struct{}

func (AlwaysFailAuthenticator) Verify(_ *Conn, _ *ntlmssp.Authenticate, _ [8]byte) ([]byte, uint32) {
	return nil, smb.StatusLogonFailure
}

// Account is a single user record consumed by MapAuthenticator. NTHash is
// the 16-byte MD4 of the unicode-encoded password (a.k.a. "NT hash" or
// "NTLMv1 hash").
type Account struct {
	NTHash []byte
}

// MapAuthenticator implements Authenticator by computing the expected
// NTLMv2 response from a stored NT hash and comparing against the inbound
// proof. It does not handle NTLMv1.
//
// The Domain field is matched case-insensitively. Accounts is keyed by
// lower-cased username.
type MapAuthenticator struct {
	Domain   string
	Accounts map[string]*Account
}

// Verify implements Authenticator.
func (m *MapAuthenticator) Verify(c *Conn, auth *ntlmssp.Authenticate, serverChallenge [8]byte) ([]byte, uint32) {
	logger := c.Server.Config.logger()
	if auth == nil || len(auth.NtChallengeResponse) < 16 {
		return nil, smb.StatusLogonFailure
	}
	user, err := encoder.FromUnicodeString(auth.UserName)
	if err != nil {
		logger.Debugf("auth: failed to decode username: %v", err)
		return nil, smb.StatusLogonFailure
	}
	domain, err := encoder.FromUnicodeString(auth.DomainName)
	if err != nil {
		logger.Debugf("auth: failed to decode domain: %v", err)
		return nil, smb.StatusLogonFailure
	}
	if m.Domain != "" && !strings.EqualFold(m.Domain, domain) {
		logger.Debugf("auth: domain mismatch (got %q, expected %q)", domain, m.Domain)
		return nil, smb.StatusLogonFailure
	}
	acct, ok := m.Accounts[strings.ToLower(user)]
	if !ok || acct.NTHash == nil {
		logger.Debugf("auth: unknown user %q", user)
		return nil, smb.StatusLogonFailure
	}

	// NTLMv2 response layout: NTProofStr(16) || temp(blob)
	ntProof := auth.NtChallengeResponse[:16]
	temp := auth.NtChallengeResponse[16:]

	ntHashV2 := ntlmssp.Ntowfv2Hash(user, domain, acct.NTHash)
	mac := hmac.New(md5.New, ntHashV2)
	mac.Write(serverChallenge[:])
	mac.Write(temp)
	expected := mac.Sum(nil)

	if !hmac.Equal(ntProof, expected) {
		logger.Debugf("auth: NTLMv2 proof mismatch for user %q", user)
		return nil, smb.StatusLogonFailure
	}

	// Session base key (KeyExchangeKey for NTLMv2): HMAC-MD5(ntHashV2, ntProofStr)
	mac2 := hmac.New(md5.New, ntHashV2)
	mac2.Write(ntProof)
	keyExchangeKey := mac2.Sum(nil)

	// MS-NLMP §3.4.5.1: when the client negotiates NTLMSSP_NEGOTIATE_KEY_EXCH
	// it generates a random ExportedSessionKey, RC4-encrypts it with the
	// KeyExchangeKey, and sends the result in EncryptedRandomSessionKey.
	// Recover the real exported key by RC4-decrypting (RC4 is symmetric).
	// Without key-exchange the exported key IS the KeyExchangeKey.
	if len(auth.EncryptedRandomSessionKey) == 16 {
		ciph, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			logger.Errorf("auth: rc4 init: %v", err)
			return nil, smb.StatusLogonFailure
		}
		out := make([]byte, 16)
		ciph.XORKeyStream(out, auth.EncryptedRandomSessionKey)
		return out, smb.StatusOk
	}
	return keyExchangeKey, smb.StatusOk
}

// Credential represents a captured NTLM authentication attempt. The Hashcat
// field is pre-formatted as "user::domain:serverChallenge:ntProof:temp",
// suitable for `hashcat -m 5600`.
type Credential struct {
	Username        string
	Domain          string
	Workstation     string
	LM              []byte
	NT              []byte
	ServerChallenge [8]byte
	Hashcat         string
	Format          string // "Net-NTLMv2" or "Net-NTLMv1"
	RemoteAddr      net.Addr
}

// BuildCredential assembles a Credential from a parsed NTLMSSP Authenticate
// message and the server-side challenge that was actually used. Exposed to
// the relay/ package so it can format captured upstream credentials with the
// same hashcat string the listener emits.
func BuildCredential(c *Conn, auth *ntlmssp.Authenticate, chal [8]byte) *Credential {
	cred := &Credential{
		LM:              auth.LmChallengeResponse,
		NT:              auth.NtChallengeResponse,
		ServerChallenge: chal,
		RemoteAddr:      c.RemoteAddr,
	}
	var err error
	if cred.Username, err = encoder.FromUnicodeString(auth.UserName); err != nil {
		c.Server.Config.logger().Debugf("BuildCredential: decode username: %v", err)
	}
	if cred.Domain, err = encoder.FromUnicodeString(auth.DomainName); err != nil {
		c.Server.Config.logger().Debugf("BuildCredential: decode domain: %v", err)
	}
	if cred.Workstation, err = encoder.FromUnicodeString(auth.Workstation); err != nil {
		c.Server.Config.logger().Debugf("BuildCredential: decode workstation: %v", err)
	}

	if len(auth.NtChallengeResponse) > 24 {
		cred.Format = "Net-NTLMv2"
		cred.Hashcat = fmt.Sprintf("%s::%s:%s:%s:%s",
			cred.Username,
			cred.Domain,
			hex.EncodeToString(chal[:]),
			hex.EncodeToString(auth.NtChallengeResponse[:16]),
			hex.EncodeToString(auth.NtChallengeResponse[16:]),
		)
	} else if len(auth.NtChallengeResponse) == 24 {
		cred.Format = "Net-NTLMv1"
		cred.Hashcat = fmt.Sprintf("%s::%s:%s:%s:%s",
			cred.Username,
			cred.Domain,
			hex.EncodeToString(auth.LmChallengeResponse),
			hex.EncodeToString(auth.NtChallengeResponse),
			hex.EncodeToString(chal[:]),
		)
	}
	return cred
}
