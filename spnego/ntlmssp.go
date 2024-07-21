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
type NTLMInitiator struct {
	User        string
	Password    string
	Hash        []byte
	Domain      string
	LocalUser   bool
	NullSession bool
	Workstation string
	TargetSPN   string

	ntlm   *ntlmssp.Client
	seqNum uint32
}

func (i *NTLMInitiator) Oid() asn1.ObjectIdentifier {
	return gss.NtLmSSPMechTypeOid
}

func (i *NTLMInitiator) Logoff() {
	return
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
	return nil, fmt.Errorf("AcceptSecContext NOT YET IMPLEMENTED!")
}

func (i *NTLMInitiator) Sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) SessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) IsNullSession() bool {
	return i.NullSession
}

func (i *NTLMInitiator) GetUsername() string {
	if i.ntlm.Domain != "" {
		return i.ntlm.Domain + "\\" + i.ntlm.User
	}
	return i.ntlm.User
}
