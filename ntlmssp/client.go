// Copyright (c) 2016 Hiroshi Ioka. All rights reserved.
// Copyright (c) 2023 Jimmy Fjällid for derivative changes
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   - Redistributions of source code must retain the above copyright
//
// notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above
//
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package ntlmssp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/golog"
)

var le = binary.LittleEndian

var log = golog.Get("github.com/jfjallid/go-smb/ntlmssp").SetDisplayName("ntlmssp")

var version = []byte{
	0: WINDOWS_MAJOR_VERSION_10,
	1: WINDOWS_MINOR_VERSION_0,
	7: NTLMSSP_REVISION_W2K3,
}

type Client struct {
	User               string
	Password           string
	Hash               []byte // Password Hash
	NTHash             []byte // Output from Ntowfv2
	LMHash             []byte // Output from Lmowfv2
	LocalUser          bool   // Don't use domain name from server
	Domain             string
	Workstation        string
	NullSession        bool
	guestSession       bool
	session            *Session
	neg                *Negotiate
	negBytes           []byte // Original marshaled Negotiate for MIC computation
	TargetSPN          string
	channelBindingHash [16]byte // MD5 of gss_channel_bindings_struct for EPA
	hasChannelBinding  bool     // true when channelBindingHash has been set

	// StripFlags specifies NTLM negotiate flags to remove from the Negotiate
	// (Type 1) message. The flags are cleared before any internal state is
	// stored, so the flag intersection, MIC, and session keys all remain
	// consistent. For example, to prevent sealing:
	//   c.StripFlags = FlgNegSeal
	// Default (zero) keeps the standard flags (sign + seal + key exchange).
	StripFlags uint32

	// DisableMIC prevents setting MsvAvFlags 0x02 (MIC_PROVIDED) in the
	// NtChallengeResponse TargetInfo and skips MIC computation. The MIC
	// field in the Authenticate message is left as zeros.
	// This is useful for LDAP authentication without SASL wrapping, where
	// the server's strict MIC validation may reject the bind when sign/seal
	// flags are absent.
	DisableMIC bool
}

func (c *Client) Negotiate() ([]byte, error) {
	req := Negotiate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmNegotiate,
		},
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegAlwaysSign |
			FlgNegNtLm |
			FlgNegSeal |
			FlgNegSign |
			FlgNegRequestTarget |
			FlgNegUnicode |
			FlgNegVersion,
	}

	if c.Domain != "" {
		req.DomainName = []byte(c.Domain)
		req.NegotiateFlags |= FlgNegOEMDomainSupplied
	}

	if c.Workstation != "" {
		req.Workstation = []byte(c.Workstation)
		req.NegotiateFlags |= FlgNegOEMWorkstationSupplied
	}

	req.NegotiateFlags |= FlgNegKeyExch
	req.NegotiateFlags &^= c.StripFlags
	req.Version = le.Uint64(version)
	c.neg = &req
	buf, err := encoder.Marshal(req)
	if err != nil {
		return nil, err
	}
	c.negBytes = make([]byte, len(buf))
	copy(c.negBytes, buf)
	return buf, nil
}

func (c *Client) Authenticate(cmsg []byte) (amsg []byte, err error) {
	// Save original challenge bytes for MIC computation before any processing.
	// Unmarshal may create slices sharing cmsg's backing array, and subsequent
	// AV_PAIR modifications (MsvAvFlags) could mutate cmsg in place.
	originalChallenge := make([]byte, len(cmsg))
	copy(originalChallenge, cmsg)

	chall := NewChallenge()
	err = encoder.Unmarshal(cmsg, &chall)
	if err != nil {
		return
	}

	if len(cmsg) < 48 {
		err := fmt.Errorf("message length is too short")
		return nil, err
	}

	if !bytes.Equal(chall.Signature, []byte(Signature)) {
		err := fmt.Errorf("invalid signature")
		return nil, err
	}

	if chall.MessageType != TypeNtLmChallenge {
		err := fmt.Errorf("invalid message type")
		return nil, err
	}

	flags := c.neg.NegotiateFlags & chall.NegotiateFlags

	if flags&FlgNegRequestTarget == 0 {
		err := fmt.Errorf("invalid negotiate flags")
		return nil, err
	}
	targetName := chall.TargetName

	if flags&FlgNegTargetInfo == 0 {
		err := fmt.Errorf("invalid negotiate flags")
		return nil, err
	}

	if chall.TargetInfo == nil {
		err := fmt.Errorf("invalid target info format")
		return nil, err
	}

	if c.User == "" && (!c.NullSession) {
		c.guestSession = true
	}

	// Assumes domain, user, and workstation are not unicode
	var domain []byte
	if c.Domain != "" {
		domain = encoder.ToUnicode(c.Domain)
	} else if !c.LocalUser {
		c.Domain, _ = encoder.FromUnicodeString(targetName)
		domain = targetName
	}

	domainstr, err := encoder.FromUnicodeString(domain)
	if err != nil {
		return
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)
	w := bytes.NewBuffer(make([]byte, 0))
	binary.Write(w, binary.LittleEndian, chall.ServerChallenge)
	serverChallenge := w.Bytes()
	w = bytes.NewBuffer(make([]byte, 0))

	flagsFound := false
	channelBindingsFound := false
	timestampFound := false
	timestamp := make([]byte, 8)

	var nbComputerName string

	// NOTE An alternative approach to this is to parse the AV Pairs into a map and then
	// check if keys exist and to serialize that map when needed.
	for _, av := range *chall.TargetInfo {
		if av.AvID == MsvAvFlags {
			flagsFound = true
			if !c.DisableMIC {
				le.PutUint32(av.Value, le.Uint32(av.Value)|0x02)
			}
		} else if av.AvID == MsvAvNbComputerName {
			nbComputerName, err = encoder.FromUnicodeString(av.Value)
			if err != nil {
				// Can't use computer name for MsvAvTargetName but no reason to fail
				log.Debugln(err)
				err = nil
			}
		} else if av.AvID == MsvAvChannelBindings {
			channelBindingsFound = true
			if c.hasChannelBinding {
				copy(av.Value, c.channelBindingHash[:])
			}
		} else if av.AvID == MsvAvTimestamp {
			timestampFound = true
			copy(timestamp, av.Value[:8])
		} else if av.AvID == 0 {
			continue
		}
		// Copy any AV Pair received in the Challenge to the Authenticate request
		binary.Write(w, binary.LittleEndian, av.AvID)
		binary.Write(w, binary.LittleEndian, av.AvLen)
		binary.Write(w, binary.LittleEndian, av.Value)
	}

	//If timestamp was not found in AV Pairs I should add a timestamp with current time
	if !timestampFound {
		binary.LittleEndian.PutUint64(timestamp, ConvertToFileTime(time.Now()))
	}

	if !flagsFound && !c.DisableMIC {
		temp := make([]byte, 2)
		le.PutUint16(temp, MsvAvFlags)
		temp = le.AppendUint16(temp, 4)
		temp = le.AppendUint32(temp, 0x02)
		binary.Write(w, binary.LittleEndian, temp)
	}

	// MS-NLMP Section 3.1.5.1.2
	// Add MsAvChannelBindings with the actual hash if set, otherwise zeros.
	if !channelBindingsFound {
		temp := make([]byte, 2)
		le.PutUint16(temp, MsvAvChannelBindings)
		temp = le.AppendUint16(temp, 16)
		if c.hasChannelBinding {
			temp = append(temp, c.channelBindingHash[:]...)
		} else {
			temp = append(temp, make([]byte, 16)...)
		}
		binary.Write(w, binary.LittleEndian, temp)
	}

	var temp []byte
	// MS-NLMP Section 3.1.5.1.2, If the ClientSuppliedTargetName (TargetSPN) is NULL
	// Add an empty MsvAvTargetName, else if it is not null, set the value without
	// terminating NULL character.
	// This is made more complicated by the Security Policy
	// "Microsoft network server: Server SPN target name validation level"
	// If the policy is set to "Required from client", the client must send the MsvAvTargetName
	// or else the authentication attempt is denied. If the policy is set to "Accept if provided by client",
	// We must NOT send an empty value or the authentication will fail. A fairly safe default is to always
	// send an SPN of "cifs/<NetBios Hostname>" unless a SPN is manually specifed.
	// MsvAvTargetName is not supported by Windows Server 2008 and below.
	serverBuild := (chall.Version >> 16) & 0xFFFF
	if serverBuild > 6003 { // Will be false if the server does not populate the Version field in the challenge.
		if c.TargetSPN != "" {
			temp = make([]byte, 2)
			le.PutUint16(temp, MsvAvTargetName)
			spn := encoder.ToUnicode(c.TargetSPN)
			temp = le.AppendUint16(temp, uint16(len(spn)))
			temp = append(temp, spn...)
			binary.Write(w, binary.LittleEndian, temp)
		} else if nbComputerName != "" {
			// Might cause a problem if the target server does not accept the NETBIOS computer name as a valid SPN
			temp = make([]byte, 2)
			le.PutUint16(temp, MsvAvTargetName)
			spn := encoder.ToUnicode("cifs/" + nbComputerName)
			temp = le.AppendUint16(temp, uint16(len(spn)))
			temp = append(temp, spn...)
			binary.Write(w, binary.LittleEndian, temp)
		}
	}

	// Add MsAvEOL
	temp = make([]byte, 4)
	w.Write(temp)

	// Calc NT Hash
	if c.Hash != nil {
		c.NTHash = Ntowfv2Hash(c.User, domainstr, c.Hash)
	} else {
		c.NTHash = Ntowfv2(c.Password, c.User, domainstr)
	}

	//NOTE c.LMHash is likely empty but is currently not used
	response := ComputeResponseNTLMv2(c.NTHash, c.LMHash, clientChallenge, serverChallenge, timestamp, w.Bytes())

	/*
	   MS-NLMP Section 3.1.5.1.2
	   If NTLM v2 authentication is used and the CHALLENGE_MESSAGE TargetInfo field (section 2.2.1.2)
	   has an MsvAvTimestamp present, the client SHOULD NOT send the LmChallengeResponse and
	   SHOULD send Z(24) instead
	*/
	var lmChallengeResponse []byte
	if !timestampFound {
		h := hmac.New(md5.New, c.LMHash)
		h.Write(append(serverChallenge, clientChallenge...))
		lmChallengeResponse = h.Sum(nil)
		lmChallengeResponse = append(lmChallengeResponse, clientChallenge...)
	} else {
		lmChallengeResponse = make([]byte, 24)
	}

	/* AuthenticateMessage
		0-8         Signature
		8-12        MessageType
		12-14       LmChallengeResponseLen
		14-16       LmChallengeResponseMaxLen
		16-20       LmChallengeResponseBufferOffset
		20-22       NtChallengeResponseLen
		22-24       NtChallengeResponseMaxLen
		24-28       NtChallengResponseBufferOffset
		28-30       DomainNameLen
		30-32       DomainNameMaxLen
		32-36       DomainNameBufferOffset
		36-38       UserNameLen
		38-40       UserNameMaxLen
		40-44       UserNameBufferOffset
		44-46       WorkstationLen
		46-48       WorkstationMaxLen
		48-52       WorkstationBufferOffset
		52-54       EncryptedRandomSessionKeyLen
		54-56       EncryptedRandomSessionKeyMaxLen
		56-60       EncryptedRandomSessionKeyBufferOffset
		60-64       NegotiateFlags
	    64-72       Version
	    72-88       MIC
	    88-         Payload:
	                    DomainName
		                UserName
		                Workstation
		                EncryptedRandomSessionKey
		                LmChallengeResponse
		                NtChallengeResponse
	*/

	auth := Authenticate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmAuthenticate,
		},
		DomainName:  domain,
		Workstation: encoder.ToUnicode(c.Workstation),
		MIC:         make([]byte, 16),
	}
	// Anonymous auth attempt
	if c.NullSession {
		auth.NtChallengeResponse = nil
		auth.LmChallengeResponse = nil
	} else if c.guestSession {
		auth.NtChallengeResponse = response
		auth.LmChallengeResponse = lmChallengeResponse
	} else {
		auth.NtChallengeResponse = response
		auth.LmChallengeResponse = lmChallengeResponse
		auth.UserName = encoder.ToUnicode(c.User)
	}

	session := new(Session)
	session.isClientSide = true
	session.user = c.User
	/* In connection-oriented mode, a NEGOTIATE structure (section 2.2.2.5)
	   that contains the set of bit flags negotiated in the previous messages. */
	//NOTE According to MS-NLMP Section 2.2.1.3 this should be set to the flags from the challenge received

	if c.guestSession || c.NullSession {
		flags |= FlgNegAnonymous
	}

	session.negotiateFlags = flags

	//Create SessionKey
	h := hmac.New(md5.New, c.NTHash)
	h.Write(response[:16])
	sessionBaseKey := h.Sum(nil)

	// MS-NLMP Secion 3.4.5.1 KXKey
	keyExchangeKey := sessionBaseKey // if ntlm version == 2

	if flags&FlgNegKeyExch != 0 {
		session.exportedSessionKey = make([]byte, 16)
		_, err := rand.Read(session.exportedSessionKey)
		if err != nil {
			return nil, err
		}
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		encryptedRandomSessionKey := make([]byte, 16)

		// MS-NLMP Section 4.2.4.2.3
		cipher.XORKeyStream(encryptedRandomSessionKey, session.exportedSessionKey)

		auth.EncryptedRandomSessionKey = encryptedRandomSessionKey
		auth.EncryptedRandomSessionKeyLen = uint16(len(encryptedRandomSessionKey))
		auth.EncryptedRandomSessionKeyMaxLen = uint16(len(encryptedRandomSessionKey))
		// Buffer offset set automatically
	} else {
		session.exportedSessionKey = keyExchangeKey
	}

	auth.NegotiateFlags = flags

	auth.Version = c.neg.Version

	// Calc MIC of Neg, Chall, and Auth messages.
	// Per MS-NLMP, the MIC must be computed over the original wire bytes of each
	// message, not re-marshaled structs. Re-marshaling can produce different bytes
	// due to offset recalculation and AV_PAIR mutations (MsvAvFlags).
	// When DisableMIC is set, MsvAvFlags 0x02 (MIC_PROVIDED) was not included
	// in the TargetInfo so the server will not verify the MIC. Leave it as zeros.
	if !c.DisableMIC {
		h = hmac.New(md5.New, session.exportedSessionKey)
		h.Write(c.negBytes)
		h.Write(originalChallenge)

		var authBytes []byte
		authBytes, err = encoder.Marshal(&auth)
		if err != nil {
			return
		}
		h.Write(authBytes)
		mic := h.Sum(nil)
		copy(auth.MIC, mic[:16])
	}

	session.clientSigningKey = signKey(flags, session.exportedSessionKey, true)
	session.serverSigningKey = signKey(flags, session.exportedSessionKey, false)

	session.clientHandle, err = rc4.NewCipher(sealKey(flags, session.exportedSessionKey, true))
	if err != nil {
		return nil, err
	}
	session.serverHandle, err = rc4.NewCipher(sealKey(flags, session.exportedSessionKey, false))
	if err != nil {
		return nil, err
	}

	c.session = session

	return encoder.Marshal(&auth)
}

func (c *Client) Session() *Session {
	return c.session
}

// SetChannelBindingHash sets the pre-computed MD5 hash of the
// gss_channel_bindings_struct for EPA (Extended Protection for
// Authentication). When set, the MsvAvChannelBindings AV pair in the
// Authenticate message will contain this hash instead of zeros.
func (c *Client) SetChannelBindingHash(hash [16]byte) {
	c.channelBindingHash = hash
	c.hasChannelBinding = true
}
