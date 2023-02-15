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

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
)

type spnegoClient struct {
	mechs        []Initiator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Initiator
}

func newSpnegoClient(mechs []Initiator) *spnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.oid()
	}
	return &spnegoClient{
		mechs:     mechs,
		mechTypes: mechTypes,
	}
}

func (c *spnegoClient) oid() asn1.ObjectIdentifier {
	return gss.SpnegoOid
}

func (c *spnegoClient) initSecContext() (negTokenInitBytes []byte, err error) {
	// Serialized Negotiate request
	mechToken, err := c.mechs[0].initSecContext()
	if err != nil {
		return nil, err
	}
	return gss.NewNegTokenInit(c.mechTypes, mechToken)
}

func (c *spnegoClient) acceptSecContext(negTokenRespBytes []byte) (res []byte, err error) {
	var token gss.NegTokenResp
	err = encoder.Unmarshal(negTokenRespBytes, &token)
	if err != nil {
		return
	}
	for i, mechType := range c.mechTypes {
		if mechType.Equal(token.SupportedMech) {
			c.selectedMech = c.mechs[i]
			break
		}
	}

	responseToken, err := c.selectedMech.acceptSecContext(token.ResponseToken)

	ms, err := asn1.Marshal(c.mechTypes)
	if err != nil {
		return
	}

	mecListMIC := c.selectedMech.sum(ms)

	negTokenResp, _ := gss.NewNegTokenResp()
	negTokenResp.ResponseToken = responseToken
	negTokenResp.MechListMIC = mecListMIC
	negTokenResp.State = 1

	return encoder.Marshal(&negTokenResp)
}

func (c *spnegoClient) sum(bs []byte) []byte {
	return c.selectedMech.sum(bs)
}

func (c *spnegoClient) sessionKey() []byte {
	return c.selectedMech.sessionKey()
}
