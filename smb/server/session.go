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

package server

import (
	"context"
	"crypto/cipher"
	"hash"
	"sync"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/spnego"
)

// Session is the per-(SMB)session state held on a Conn. A single TCP
// connection may carry multiple SMB sessions (each with its own SessionID),
// though most clients open just one. Hooks may read or mutate fields below;
// mutation while the server is dispatching is safe as long as the calling
// goroutine holds Session.mu (the dispatcher does so for the duration of a
// hook).
type Session struct {
	ID    uint64
	Conn  *Conn
	Flags uint16 // SessionFlagIsGuest | SessionFlagIsNull | SessionFlagEncryptData

	// Authentication state. Once setup completes successfully Username,
	// Domain, Workstation are populated and SessionKey holds the 16-byte
	// exported session key used to derive signing / encryption keys.
	Username    string
	Domain      string
	Workstation string
	SessionKey  []byte

	// AuthAcceptor holds the in-flight SPNEGO acceptor across the two
	// SessionSetup legs. Set on first leg, consumed on second.
	AuthAcceptor *spnego.NTLMAcceptor
	NTLMServer   *ntlmssp.Server

	// Authenticated reports whether the session has completed setup with a
	// non-failure status.
	Authenticated bool

	// signer / verifier are populated by deriveKeys once the Authenticator
	// returns a non-nil session key. Both are nil until then. SigningActive
	// flips to true after deriveKeys; while false the server neither signs
	// outbound nor verifies inbound.
	//
	// For algorithms that maintain state across messages (HMAC-SHA256,
	// AES-CMAC) signer/verifier hold the pre-keyed hash.Hash. For AES-GMAC
	// (3.1.1 only) the per-message nonce makes a persistent object
	// impractical; we cache signingKey and signingAlg and build the AEAD on
	// demand inside signPDU / verifyPDU.
	signer        hash.Hash
	verifier      hash.Hash
	signingAlg    uint16
	signingKey    []byte
	SigningActive bool

	// SigningRequired is the negotiated requirement per MS-SMB2 §3.3.5.5.3:
	// TRUE when the server's RequireMessageSigning is set OR the client's
	// NegotiateReq SecurityMode included SMB2_NEGOTIATE_SIGNING_REQUIRED.
	// Only when this is TRUE does the server sign every outbound PDU and
	// reject unsigned post-auth inbound PDUs. Independent of SigningActive
	// (which just reports that signing keys are derived).
	SigningRequired bool

	// encrypter / decrypter are populated by deriveKeys when the negotiated
	// dialect is SMB 3.x and the session is configured for encryption
	// (Conn.SupportsEncryption + cfg.EncryptionSupported). encrypter wraps
	// outbound PDUs into TransformHeader frames; decrypter unwraps inbound.
	encrypter cipher.AEAD
	decrypter cipher.AEAD

	// preauthChain is the running SHA-512 chain through SessionSetup; it is
	// seeded from Conn.preauthChain on the first SessionSetup leg. Frozen
	// once deriveKeys consumes it.
	preauthChain [64]byte

	// previousSessionID is captured from SessionSetupReq.PreviousSessionID on
	// the first leg and applied (across all connections owned by Server) on
	// successful authentication. MS-SMB2 §3.3.5.5.3 step 6: when an existing
	// session with the same SessionID exists and is owned by the same user,
	// the server evicts it before installing the new one. The "same user"
	// guard is what justifies deferring the eviction to leg-2 success.
	previousSessionID uint64

	mu sync.Mutex
	// Tree table — populated by TreeConnect / drained by TreeDisconnect.
	trees      map[uint32]*Tree
	nextTreeID uint32
}

// addSession allocates a fresh Session ID and stores it on the Conn. The
// allocated ID is non-zero (zero is reserved for pre-auth packets).
func (c *Conn) addSession() *Session {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil {
		c.sessions = make(map[uint64]*Session)
		c.nextSessionID = 1
	}
	id := c.nextSessionID
	c.nextSessionID++
	s := &Session{ID: id, Conn: c}
	c.sessions[id] = s
	return s
}

// session returns the Session with the given ID, or nil if not found.
func (c *Conn) session(id uint64) *Session {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil {
		return nil
	}
	return c.sessions[id]
}

// removeSession evicts a session (called by Logoff and on TCP close).
func (c *Conn) removeSession(id uint64) *Session {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	if c.sessions == nil {
		return nil
	}
	s := c.sessions[id]
	delete(c.sessions, id)
	return s
}

// RemoveSession is the public counterpart of removeSession — used by relay
// hooks (smb/server.OnSessionSetup) that own session lifetime after returning
// a non-nil *Status. Returns the evicted Session, or nil if not found.
func (c *Conn) RemoveSession(id uint64) *Session {
	return c.removeSession(id)
}

// allSessions returns a snapshot slice of the connection's sessions. Used
// by close paths and tests.
func (c *Conn) allSessions() []*Session {
	c.sessionsMu.Lock()
	defer c.sessionsMu.Unlock()
	out := make([]*Session, 0, len(c.sessions))
	for _, s := range c.sessions {
		out = append(out, s)
	}
	return out
}

// cleanupSessions drains every session's tree handles via VFS.Close. Called
// from the connection's deferred-close path so dangling files released by
// dropped TCP connections still get a Close on the VFS side.
func (c *Conn) cleanupSessions() {
	for _, sess := range c.allSessions() {
		c.cleanupSession(sess)
	}
}

// cleanupSession drains a single session's tree handles via VFS.Close.
// Called by cleanupSessions and by the PreviousSessionID eviction path
// (MS-SMB2 §3.3.5.5.3 step 6).
func (c *Conn) cleanupSession(sess *Session) {
	sess.mu.Lock()
	trees := sess.trees
	sess.trees = nil
	sess.mu.Unlock()
	logger := c.Server.Config.logger()
	for _, t := range trees {
		t.closeOpenHandles(context.Background(), logger)
	}
}
