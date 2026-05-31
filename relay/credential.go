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
	"net"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/server"
)

// Credential is a captured NTLM authentication attempt. It is a re-export of
// server.Credential so callers of relay/ don't need to import smb/server
// directly.
type Credential = server.Credential

// BuildCredential assembles a Credential from a parsed NTLMSSP Authenticate
// message and the server-side challenge that was actually used during the
// upstream exchange. The remote address is plumbed onto the Credential for
// attribution. Cross-protocol relay uses this directly; both forwarder
// backends share the same code path.
func BuildCredential(remote net.Addr, auth *ntlmssp.Authenticate, chal [8]byte) *Credential {
	return buildCredentialFromAuth(auth, chal, remote)
}
