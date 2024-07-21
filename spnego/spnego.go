package spnego

import (
	"fmt"
	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// MS-SPNG

type Client struct {
	mechs        []gss.Mechanism
	mechTypes    []asn1.ObjectIdentifier
	selectedMech gss.Mechanism
}

func NewClient(mechs []gss.Mechanism) (c *Client, err error) {
	if len(mechs) == 0 {
		err = fmt.Errorf("A new SPNEGO client requires atleast one GSS Mechanism")
		return
	}
	c = &Client{
		mechs:     mechs,
		mechTypes: make([]asn1.ObjectIdentifier, len(mechs)),
	}
	for i := range mechs {
		c.mechTypes[i] = mechs[i].Oid()
	}
	return
}

func (c *Client) InitSecContext(inputToken []byte) (res []byte, err error) {
	if inputToken == nil {
		var mechToken []byte
		// Send the optimistic mechanism as the first in the list
		mechToken, err = c.mechs[0].InitSecContext(inputToken)
		if err != nil {
			return
		}
		// Currently we are always sending a MIC Token regardless if required or not.
		// To be compatible with really old servers we would have to only send it when required
		// Typically the server should respond with the request-mic(3) status code rather than
		// accept-complete, but Microsoft's SMB server implementations seems to respond with
		// accept-incomplete unless the MIC Token is included so not sure how to handle that.
		// RFC4178 Section 5
		return gss.NewNegTokenInit(c.mechTypes, mechToken)
	} else {
		// Figure out which offered mechanism the server accepted
		var token gss.NegTokenResp
		var responseToken []byte
		var ms []byte
		err = encoder.Unmarshal(inputToken, &token)
		if err != nil {
			return
		}

		for i := range c.mechTypes {
			if c.mechTypes[i].Equal(token.SupportedMech) {
				// Use the first supported mechanism since they are ordered in falling preference
				c.selectedMech = c.mechs[i]
				break
			}
		}

		responseToken, err = c.selectedMech.InitSecContext(token.ResponseToken)
		if err != nil {
			return
		}

		negTokenRes, _ := gss.NewNegTokenResp()
		negTokenRes.ResponseToken = responseToken
		negTokenRes.State = gss.GssStateAcceptIncomplete

		ms, err = asn1.Marshal(c.mechTypes)
		if err != nil {
			return
		}

		negTokenRes.MechListMIC = c.selectedMech.Sum(ms)
		return encoder.Marshal(&negTokenRes)
	}
}

// AcceptSecContext should only be called by a server application
func (c *Client) AcceptSecContext(buf []byte) (res []byte, err error) {
	return nil, fmt.Errorf("AcceptSecContext NOT YET IMPLEMENTED!")
}

func (c *Client) SessionKey() []byte {
	return c.selectedMech.SessionKey()
}
