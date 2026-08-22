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

package smb

import "fmt"

// EncryptionPolicy selects how hard the client tries to encrypt SMB 3.x
// traffic. The four values form a ladder from "never" to "or fail", and the
// zero value is EncryptionPreferred so that leaving Options.Encryption unset
// keeps the documented default.
//
// Encryption is an SMB 3.x feature: below dialect 3.0 there is no cipher to
// negotiate, so only EncryptionRequired (which refuses such a connection) and
// EncryptionDisabled (which asks for nothing) behave distinguishably there.
type EncryptionPolicy uint8

const (
	// EncryptionPreferred encrypts every request whenever the connection
	// negotiated a cipher end-to-end, and falls back to signed plaintext when
	// it did not. This is the default and it encrypts more traffic than the
	// peer strictly asks for.
	EncryptionPreferred EncryptionPolicy = iota

	// EncryptionServerDirected encrypts only what the peer asks for: a session
	// the server flagged SMB2_SESSION_FLAG_ENCRYPT_DATA (MS-SMB2 §3.2.5.3.1),
	// and shares the server flagged SMB2_SHAREFLAG_ENCRYPT_DATA (§3.2.5.5).
	// Everything else travels as signed plaintext. This mirrors how a Windows
	// client behaves, which makes it the choice when the traffic should look
	// ordinary or when a plaintext capture is wanted without losing access to
	// encrypt-only shares. The connection still negotiates a cipher, so those
	// shares remain reachable — unlike EncryptionDisabled, which cannot reach
	// them at all.
	EncryptionServerDirected

	// EncryptionRequired encrypts every request and refuses any connection
	// that cannot: NewConnection returns ErrEncryptionNotNegotiated when the
	// negotiated dialect predates 3.0 or the server selected no cipher, and
	// SessionSetup fails if the server established a guest or anonymous
	// session, which has no key to encrypt with.
	EncryptionRequired

	// EncryptionDisabled removes encryption from the negotiation entirely: no
	// SMB2_GLOBAL_CAP_ENCRYPTION capability and no EncryptionCapabilities
	// context, so no cipher is selected and neither peer derives encryption
	// keys. A share flagged SMB2_SHAREFLAG_ENCRYPT_DATA then fails its
	// TreeConnect with ErrShareRequiresEncryption rather than being sent in the
	// clear.
	EncryptionDisabled
)

func (p EncryptionPolicy) String() string {
	switch p {
	case EncryptionPreferred:
		return "preferred"
	case EncryptionServerDirected:
		return "server-directed"
	case EncryptionRequired:
		return "required"
	case EncryptionDisabled:
		return "disabled"
	default:
		return fmt.Sprintf("EncryptionPolicy(%d)", uint8(p))
	}
}

// valid reports whether p is one of the defined policies. An out-of-range value
// would otherwise fall through every switch in the client and silently behave
// like whichever branch has no case.
func (p EncryptionPolicy) valid() bool {
	switch p {
	case EncryptionPreferred, EncryptionServerDirected, EncryptionRequired, EncryptionDisabled:
		return true
	}
	return false
}
