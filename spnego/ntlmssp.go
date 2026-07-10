// Copyright (c) 2016 Hiroshi Ioka. All rights reserved.
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
package spnego

import (
	"fmt"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
)

// NTLMInitiator implements session setup through NTLMv2.
// It does not support NTLMv1. It is possible to use hash instead of password.
// NTLMAuthMode and its constants are re-exported from the ntlmssp package so
// callers can select the auth mode without importing ntlmssp directly, e.g.
// &spnego.NTLMInitiator{AuthMode: spnego.NTLMAuthGuest}.
type NTLMAuthMode = ntlmssp.NTLMAuthMode

const (
	NTLMAuthCredentials = ntlmssp.NTLMAuthCredentials
	NTLMAuthAnonymous   = ntlmssp.NTLMAuthAnonymous
	NTLMAuthGuest       = ntlmssp.NTLMAuthGuest
)

type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	LocalUser   bool
	NullSession bool // Deprecated: prefer AuthMode = NTLMAuthAnonymous. Equivalent, kept for backwards compatibility.
	// AuthMode selects the NTLM auth mode (credentials / anonymous / guest)
	// explicitly. Left at its zero value it preserves legacy behaviour:
	// NullSession==true selects anonymous, and an empty User selects guest.
	AuthMode    NTLMAuthMode
	Workstation string
	TargetSPN   string

	ntlm      *ntlmssp.Client
	micSeqNum uint32

	sealSeqNum   uint32
	unsealSeqNum uint32
}

func (i *NTLMInitiator) Oid() asn1.ObjectIdentifier {
	return gss.NtLmSSPMechTypeOid
}

func (i *NTLMInitiator) Logoff() {
}

func (i *NTLMInitiator) InitSecContext(inputToken []byte) ([]byte, error) {
	//if !((i.User != "") && (i.Password != "")) && !((i.User != "") && (i.Hash != nil)) {
	//	return nil, fmt.Errorf("Invalid NTLMInitiator! Must specify username + password or username + hash")
	//}
	if inputToken == nil {
		i.ntlm = &ntlmssp.Client{
			User:        i.User,
			Password:    i.Password,
			Domain:      i.Domain,
			LocalUser:   i.LocalUser,
			NullSession: i.NullSession,
			AuthMode:    i.AuthMode,
			Hash:        i.Hash,
			Workstation: i.Workstation,
			TargetSPN:   i.TargetSPN,
		}

		if len(i.Hash) == 0 {
			i.Hash = ntlmssp.Ntowfv1(i.Password)
			i.ntlm.Hash = i.Hash
		}
		nmsg, err := i.ntlm.Negotiate()
		if err != nil {
			return nil, err
		}
		return nmsg, nil
	} else {
		amsg, err := i.ntlm.Authenticate(inputToken)
		if err != nil {
			return nil, err
		}
		return amsg, nil

	}
}

// AcceptSecContext should only be called by a server application
func (i *NTLMInitiator) AcceptSecContext(sc []byte) ([]byte, error) {
	return nil, fmt.Errorf("AcceptSecContext not yet implemented")
}

func (i *NTLMInitiator) Sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.micSeqNum)
	return mic
}

func (i *NTLMInitiator) SessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) IsNullSession() bool {
	return i.NullSession || i.AuthMode == ntlmssp.NTLMAuthAnonymous
}

func (i *NTLMInitiator) GetUsername() string {
	if i.ntlm.Domain != "" {
		return i.ntlm.Domain + "\\" + i.ntlm.User
	}
	return i.ntlm.User
}

// Seal encrypts toEncrypt and computes a MAC over toSign.
// Implements the dcerpc.Sealer interface for per-PDU encryption.
func (i *NTLMInitiator) Seal(toEncrypt, toSign []byte) (ciphertext, signature []byte, err error) {
	ct, sig, newSeqNum := i.ntlm.Session().EncryptAndSign(toEncrypt, toSign, i.sealSeqNum)
	i.sealSeqNum = newSeqNum
	return ct, sig, nil
}

// Unseal decrypts ciphertext and verifies the MAC over the full PDU.
// Implements the dcerpc.Sealer interface.
func (i *NTLMInitiator) Unseal(ciphertext, signature, pduHeader, secTrailer []byte) ([]byte, error) {
	plaintext := i.ntlm.Session().DecryptOnly(ciphertext)
	signData := make([]byte, 0, len(pduHeader)+len(plaintext)+len(secTrailer))
	signData = append(signData, pduHeader...)
	signData = append(signData, plaintext...)
	signData = append(signData, secTrailer...)
	newSeqNum, err := i.ntlm.Session().VerifyMAC(signData, signature, i.unsealSeqNum)
	if err != nil {
		return nil, err
	}
	i.unsealSeqNum = newSeqNum
	return plaintext, nil
}

// Sign computes a MAC over toSign without encrypting data.
// Implements the dcerpc.Sealer interface for PktIntegrity.
func (i *NTLMInitiator) Sign(data, toSign []byte) ([]byte, error) {
	sig, newSeqNum := i.ntlm.Session().SignOnly(toSign, i.sealSeqNum)
	i.sealSeqNum = newSeqNum
	return sig, nil
}

// VerifySign verifies the MAC without decrypting data.
// Implements the dcerpc.Sealer interface for PktIntegrity.
func (i *NTLMInitiator) VerifySign(data, signature, pduHeader, secTrailer []byte) error {
	signData := make([]byte, 0, len(pduHeader)+len(data)+len(secTrailer))
	signData = append(signData, pduHeader...)
	signData = append(signData, data...)
	signData = append(signData, secTrailer...)
	newSeqNum, err := i.ntlm.Session().VerifyMACOnly(signData, signature, i.unsealSeqNum)
	if err != nil {
		return err
	}
	i.unsealSeqNum = newSeqNum
	return nil
}

// SignatureSize returns the NTLM signature size (always 16 bytes).
// Implements the dcerpc.Sealer interface.
func (i *NTLMInitiator) SignatureSize() int { return 16 }

// MICSignatureSize returns the NTLM MIC signature size (always 16 bytes).
// For NTLM, this is the same as SignatureSize.
// Implements the dcerpc.Sealer interface.
func (i *NTLMInitiator) MICSignatureSize() int { return 16 }

// EncryptionOverhead returns 0 because NTLM RC4 is size-preserving.
// Implements the dcerpc.Sealer interface.
func (i *NTLMInitiator) EncryptionOverhead() int { return 0 }
