// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package smb

import (
	"fmt"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// SessionSetupReq is the generic SessionSetup request shape used when the
// caller doesn't yet know whether this is leg 1 (Negotiate) or leg 2
// (Authenticate). The smb/server package decodes the inbound blob through
// this type before dispatching by leading byte (0x60 vs 0xa1).
type SessionSetupReq struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         []byte
}

// SessionSetupRes is the generic SessionSetup response shape used by
// smb/server to emit replies (in particular logon-failure / pre-keys legs)
// where the caller has produced the SecurityBlob bytes itself.
type SessionSetupRes struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         []byte
}

// SendSessionSetup1WithToken forwards an opaque NTLMSSP NEGOTIATE token —
// extracted from a client-side SessionSetup1's NegTokenInit.MechToken — to
// the upstream server in a SessionSetup1 request, and returns the inner
// ResponseToken (the NTLMSSP CHALLENGE) for the relay to forward back to its
// own client. The upstream's allocated SessionID is stashed on this
// Connection so a matching SendSessionSetup2WithBlob lands on the right
// upstream session.
//
// Used by smb/server/relay to drive an upstream NTLMSSP exchange without
// re-implementing request layout. The Connection must already have completed
// NegotiateProtocol (smb.NewConnection with ManualLogin: true does this).
func (c *Connection) SendSessionSetup1WithToken(token []byte) (responseToken []byte, err error) {
	log.Debugln("Sending SessionSetup1 request")
	initBytes, err := gss.NewNegTokenInit([]asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid}, token)
	if err != nil {
		log.Errorln(err)
		return
	}
	var init gss.NegTokenInit
	err = encoder.Unmarshal(initBytes, &init)
	if err != nil {
		log.Errorln(err)
		return
	}

	init.Data.MechToken = token

	ssreq := SessionSetup1Req{
		Header:               newHeader(),
		StructureSize:        25,
		Flags:                0x00,
		Capabilities:         GlobalCapLargeMTU,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}
	ssreq.Header.Command = CommandSessionSetup
	c.applyCreditCharge(&ssreq.Header)

	ssres, err := NewSessionSetup1Res()
	if err != nil {
		log.Debugln(err)
		return
	}

	ssresbuf, err := c.sendrecv(ssreq)
	if err != nil {
		log.Errorln(err)
		return
	}

	if err = encoder.Unmarshal(ssresbuf, &ssres); err != nil {
		log.Debugln(err)
		return
	}

	responseToken = ssres.SecurityBlob.ResponseToken

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, found := StatusMap[ssres.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for SessionSetup1 response: 0x%x\n", ssres.Header.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("NT Status Error: %v\n", status)
		err = status
		return
	}

	c.sessionID = ssres.Header.SessionID
	return
}

// SendSessionSetup2WithBlob forwards an opaque SPNEGO NegTokenResp blob —
// extracted from a client-side SessionSetup2 — to the upstream server in a
// SessionSetup2 request, and returns the upstream's NT status. StatusOk
// indicates the relay succeeded; other values (e.g. StatusLogonFailure,
// StatusAccessDenied) mean the credentials were rejected upstream.
func (c *Connection) SendSessionSetup2WithBlob(blob []byte) (uint32, error) {
	var resp gss.NegTokenResp
	if err := encoder.Unmarshal(blob, &resp); err != nil {
		return 0, fmt.Errorf("decode NegTokenResp: %w", err)
	}

	req := SessionSetup2Req{
		Header:        newHeader(),
		StructureSize: 25,
		Capabilities:  GlobalCapLargeMTU,
		SecurityBlob:  &resp,
	}
	req.Header.Command = CommandSessionSetup
	req.Header.SessionID = c.sessionID
	c.applyCreditCharge(&req.Header)

	buf, err := c.sendrecv(req)
	if err != nil {
		return 0, err
	}
	var hdr Header
	if err := encoder.Unmarshal(buf, &hdr); err != nil {
		return 0, fmt.Errorf("decode response header: %w", err)
	}
	return hdr.Status, nil
}

// UpstreamSessionID returns the SessionID assigned by the upstream server
// during SendSessionSetup1WithToken. Useful for relay diagnostics.
func (c *Connection) UpstreamSessionID() uint64 {
	return c.sessionID
}
