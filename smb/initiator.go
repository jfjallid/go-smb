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
package smb

import (
	"encoding/asn1"
	"fmt"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
)

type Initiator interface {
	oid() asn1.ObjectIdentifier
	initSecContext() ([]byte, error)            // GSS_Init_sec_context
	acceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	sum(bs []byte) []byte                       // GSS_getMIC
	sessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
}

// NTLMInitiator implements session setup through NTLMv2.
// It does not support NTLMv1. It is possible to use hash instead of password.
type NTLMInitiator struct {
	User               string
	Password           string
	Hash               []byte
	Domain             string
	Workstation        string
	TargetSPN          string
	DisableSigning     bool
	EncryptionDisabled bool

	ntlm   *ntlmssp.Client
	seqNum uint32
}

func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return gss.NtLmSSPMechTypeOid
}

func (i *NTLMInitiator) initSecContext() ([]byte, error) {
	if !((i.User != "") && (i.Password != "")) && !((i.User != "") && (i.Hash != nil)) {
		return nil, fmt.Errorf("Invalid NTLMInitiator! Must specify username + password or username + hash")
	}
	i.ntlm = &ntlmssp.Client{
		User:               i.User,
		Password:           i.Password,
		Domain:             i.Domain,
		Hash:               i.Hash,
		Workstation:        i.Workstation,
		TargetSPN:          i.TargetSPN,
		SigningDisabled:    i.DisableSigning,
		EncryptionDisabled: i.EncryptionDisabled,
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
}

func (i *NTLMInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	return amsg, nil
}

func (i *NTLMInitiator) sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) sessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}
