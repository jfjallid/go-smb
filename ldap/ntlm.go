// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

package ldap

import (
	"github.com/jfjallid/go-smb/ntlmssp"
	goldap "github.com/jfjallid/ldap/v3"
)

// ntlmNegotiator adapts go-smb's ntlmssp.Client to the interfaces the
// jfjallid/ldap/v3 package uses to drive an NTLM bind. It lets ldap stay free of
// any concrete NTLM (and therefore go-smb) dependency while go-smb supplies the
// implementation. It satisfies goldap.NTLMNegotiator and, optionally,
// goldap.NTLMChannelBinder and goldap.NTLMSessionProvider.
type ntlmNegotiator struct {
	c *ntlmssp.Client
}

var (
	_ goldap.NTLMNegotiator      = (*ntlmNegotiator)(nil)
	_ goldap.NTLMChannelBinder   = (*ntlmNegotiator)(nil)
	_ goldap.NTLMSessionProvider = (*ntlmNegotiator)(nil)
)

// Negotiate produces the NTLM NEGOTIATE_MESSAGE. The credentials (including the
// domain) are already configured on the underlying client by newNTLMNegotiator,
// so the domain argument is informational; only a non-empty workstation
// overrides the configured value.
func (n *ntlmNegotiator) Negotiate(domain, workstation string) ([]byte, error) {
	if workstation != "" {
		n.c.Workstation = workstation
	}
	return n.c.Negotiate()
}

// ChallengeResponse consumes the server CHALLENGE_MESSAGE and returns the NTLM
// AUTHENTICATE_MESSAGE.
func (n *ntlmNegotiator) ChallengeResponse(challenge []byte) ([]byte, error) {
	return n.c.Authenticate(challenge)
}

// SetChannelBindingHash forwards the RFC 5929 channel-binding hash to the NTLM
// client (EPA).
func (n *ntlmNegotiator) SetChannelBindingHash(hash [16]byte) {
	n.c.SetChannelBindingHash(hash)
}

// SecuritySession returns the negotiated NTLM SASL sign/seal session, or nil if
// none was established. *ntlmssp.Session satisfies goldap.SASLSession via its
// Seal/Unseal methods.
func (n *ntlmNegotiator) SecuritySession() goldap.SASLSession {
	s := n.c.Session()
	if s == nil {
		return nil
	}
	return s
}

// newNTLMNegotiator builds an ntlmssp-backed negotiator from the credentials
// resolved by the ldap layer. It is registered as goldap.NTLMNegotiatorFactory
// so credential-based NTLM binds and signing detection work out of the box.
func newNTLMNegotiator(creds goldap.NTLMCredentials) (goldap.NTLMNegotiator, error) {
	c := &ntlmssp.Client{
		User:        creds.Username,
		Domain:      creds.Domain,
		Workstation: creds.Workstation,
		Password:    creds.Password,
		Hash:        creds.Hash,
	}
	// When the caller does not intend to negotiate a SASL sign/seal layer,
	// strip the integrity/confidentiality flags and suppress the MIC. AD's
	// strict MIC validation can otherwise reject an unsigned bind.
	if !creds.SignSeal {
		c.StripFlags = ntlmssp.FlgNegSign | ntlmssp.FlgNegSeal
		c.DisableMIC = true
	}
	return &ntlmNegotiator{c: c}, nil
}

func init() {
	// Provide ldap with go-smb's NTLM implementation. Importing this package is
	// enough to enable credential-based NTLM binds through jfjallid/ldap/v3.
	goldap.NTLMNegotiatorFactory = newNTLMNegotiator
}
