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

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// Forwarder drives an upstream NTLMSSP exchange for one inbound auth. The
// interface boundary carries raw NTLMSSP (no SPNEGO, no HTTP framing) so the
// inbound listener stays protocol-agnostic. SPNEGO unwrapping is the
// listener's job; protocol-specific re-wrapping for the upstream client API
// is the forwarder's job.
type Forwarder interface {
	Target() Target
	Negotiate(neg []byte) (chal []byte, err error)
	Authenticate(remote net.Addr, auth, mic []byte) (cred *Credential, status uint32, err error)
	Close()
}

// SMBForwarder is the upstream-SMB specialization. Take transfers ownership
// of the authenticated *smb.Connection to the caller.
type SMBForwarder interface {
	Forwarder
	Take() *smb.Connection
}

// HTTPForwarder is the upstream-HTTP specialization. Take transfers ownership
// of the authenticated pinned-keepalive socket to the caller.
type HTTPForwarder interface {
	Forwarder
	Take() *httpUpstream
}

// LDAPForwarder is the upstream-LDAP specialization. Take transfers ownership
// of the authenticated LDAP connection to the caller.
type LDAPForwarder interface {
	Forwarder
	Take() *ldapUpstream
}

// newForwarderFor returns a forwarder bound to the supplied target. The
// returned value satisfies SMBForwarder, HTTPForwarder, or LDAPForwarder
// depending on target.Protocol; callers that need to pool the upstream
// type-switch on the concrete return value.
func newForwarderFor(t Target, cfg *ServerConfig, logger server.Logger) (Forwarder, error) {
	switch t.Protocol {
	case ProtoSMB:
		return newSMBForwarder(t, cfg.UpstreamOptions, logger)
	case ProtoHTTP, ProtoHTTPS:
		return newHTTPForwarder(t, cfg.UpstreamDialTimeout, cfg.UpstreamHTTPSTLSConfig, logger), nil
	case ProtoLDAP, ProtoLDAPS:
		return newLDAPForwarder(t, cfg.UpstreamDialTimeout, cfg.UpstreamLDAPSTLSConfig, cfg.DisableLDAPStartTLS, logger), nil
	}
	return nil, fmt.Errorf("unsupported protocol %q", t.Protocol)
}
