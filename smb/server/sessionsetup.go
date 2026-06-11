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
	"fmt"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
)

// handleSessionSetup processes both legs of an SMB2 SessionSetup exchange.
// The first leg (security blob starts with 0x60 = NegTokenInit) allocates a
// new Session and replies with STATUS_MORE_PROCESSING_REQUIRED + a Challenge.
// The second leg (0xa1 = NegTokenResp) drives the verifier and replies with
// STATUS_OK / STATUS_LOGON_FAILURE.
func (c *Conn) handleSessionSetup(ctx pduCtx, raw []byte, h *smb.Header) error {
	// SessionSetupReq from smb/relay.go has a raw []byte SecurityBlob,
	// matching the on-wire format regardless of which leg we're in.
	var req smb.SessionSetupReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		return formatErr("decode SessionSetupReq", err)
	}
	// MS-SMB2 §3.3.5.5.2: a server that does not support multichannel
	// session binding MUST fail SessionSetup with STATUS_REQUEST_NOT_ACCEPTED
	// when SMB2_SESSION_FLAG_BINDING is set. Reject before allocating a new
	// session so the bind attempt doesn't leak state on this Conn.
	if req.Flags&smb.SMB2_SESSION_FLAG_BINDING != 0 {
		c.logger().Debugf("SessionSetup BINDING: rejected (multichannel not supported)")
		return c.writeRawError(ctx, h, smb.StatusRequestNotAccepted)
	}
	if len(req.SecurityBlob) == 0 {
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}

	switch req.SecurityBlob[0] {
	case 0x60:
		return c.handleSessionSetupNegotiate(ctx, raw, h, &req)
	case 0xa1:
		return c.handleSessionSetupAuthenticate(ctx, raw, h, &req)
	default:
		return fmt.Errorf("unknown SessionSetup blob tag 0x%02x", req.SecurityBlob[0])
	}
}

func (c *Conn) handleSessionSetupNegotiate(ctx pduCtx, raw []byte, h *smb.Header, req *smb.SessionSetupReq) error {
	cfg := c.Server.Config
	logger := c.logger()

	// Allocate a fresh Session keyed by a new SessionID.
	sess := c.addSession()
	sess.previousSessionID = req.PreviousSessionID
	logger.Debugf("SessionSetup1 from %s: allocated SessionID=%d, previousSessionID=%d",
		c.RemoteAddr, sess.ID, req.PreviousSessionID)
	// Seed the per-session preauth chain from the connection chain (which
	// already covers Negotiate req+res), then fold this inbound leg.
	c.seedPreauthChain(sess)
	c.updatePreauthChainSession(sess, raw)

	// Stand up the NTLMSSP acceptor for this session, plumbed to the
	// configured Authenticator via the spnego.NTLMAuthCallback shape.
	sess.NTLMServer = &ntlmssp.Server{
		TargetName:      cfg.ntlmTargetName(),
		NetBIOSName:     cfg.netbiosName(),
		NetBIOSDomain:   cfg.NetBIOSDomain,
		DnsComputerName: cfg.DnsComputerName,
		DnsDomainName:   cfg.DnsDomainName,
	}
	sess.AuthAcceptor = &spnego.NTLMAcceptor{
		Server: sess.NTLMServer,
		Verify: func(auth *ntlmssp.Authenticate, chal [8]byte) ([]byte, uint32) {
			return c.verifyAndCapture(sess, auth, chal)
		},
	}

	// Hook: OnSessionSetup may short-circuit. A non-nil *Status replaces the
	// default reply status; st.SecurityBlob, when non-nil, is used as the
	// outbound SessionSetupRes.SecurityBlob (relay flows inject the
	// upstream's CHALLENGE here). Hooks that return *Status own the session
	// lifetime — call (*Conn).RemoveSession explicitly when discarding.
	if cb := cfg.OnSessionSetup; cb != nil {
		st, err := cb(c, sess, req.SecurityBlob, SessionSetupStageNegotiate)
		if err != nil {
			c.removeSession(sess.ID)
			return err
		}
		if st != nil {
			return c.writeSessionSetupReply(ctx, h, sess.ID, st.Code, st.SecurityBlob, sess)
		}
	}

	out, _, err := sess.AuthAcceptor.AcceptSecContext(req.SecurityBlob)
	if err != nil {
		logger.Errorf("SessionSetup1: SPNEGO accept failed: %v", err)
		c.removeSession(sess.ID)
		return c.writeSessionSetupReply(ctx, h, 0, smb.StatusInvalidParameter, nil, sess)
	}
	return c.writeSessionSetupReply(ctx, h, sess.ID, smb.StatusMoreProcessingRequired, out, sess)
}

func (c *Conn) handleSessionSetupAuthenticate(ctx pduCtx, raw []byte, h *smb.Header, req *smb.SessionSetupReq) error {
	cfg := c.Server.Config
	logger := c.logger()

	sess := c.session(h.SessionID)
	if sess == nil || sess.AuthAcceptor == nil {
		logger.Errorf("SessionSetup2: unknown SessionID %d", h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}

	// Fold inbound SessionSetup2Req into the preauth chain *before* deriving
	// keys — MS-SMB2 §3.1.5.1 includes every SessionSetup leg up to and
	// including the inbound auth blob in the chain.
	c.updatePreauthChainSession(sess, raw)

	if cb := cfg.OnSessionSetup; cb != nil {
		st, err := cb(c, sess, req.SecurityBlob, SessionSetupStageAuthenticate)
		if err != nil {
			c.removeSession(sess.ID)
			return err
		}
		if st != nil {
			// Hooks returning *Status on leg 2 own the session lifetime —
			// call (*Conn).RemoveSession to evict (relay's capture-and-drop
			// flow keeps the upstream session alive but evicts this one).
			return c.writeSessionSetupReply(ctx, h, sess.ID, st.Code, st.SecurityBlob, sess)
		}
	}

	out, _, err := sess.AuthAcceptor.AcceptSecContext(req.SecurityBlob)
	if err != nil {
		logger.Errorf("SessionSetup2: SPNEGO accept failed: %v", err)
		c.removeSession(sess.ID)
		return c.writeSessionSetupReply(ctx, h, sess.ID, smb.StatusInvalidParameter, nil, sess)
	}

	status := sess.AuthAcceptor.Status()

	// Anonymous / null-session pass-through: an Authenticate with empty
	// user and trivial NT/LM responses.
	if cfg.AllowAnonymous && sess.AuthAcceptor.IsAnonymous() {
		status = smb.StatusOk
		sess.Flags |= smb.SessionFlagIsNull
	}

	// Promote on success: copy state from acceptor onto Session.
	if status == smb.StatusOk {
		sess.Authenticated = true
		sess.SessionKey = sess.AuthAcceptor.SessionKey()
		sess.Username = sess.AuthAcceptor.User()
		sess.Domain = sess.AuthAcceptor.Domain()
		sess.Workstation = sess.AuthAcceptor.Workstation()
		// MS-SMB2 §3.3.5.5.3 step 6: now that we know the user, evict any
		// prior session matching PreviousSessionID owned by the same user
		// across all connections on this server.
		if sess.previousSessionID != 0 {
			c.Server.evictPreviousSession(sess.previousSessionID, sess.Username, sess.Domain, c, sess.ID, logger)
		}
	} else if cfg.AllowGuest {
		// Guest fallback: succeed but flag as guest.
		status = smb.StatusOk
		sess.Authenticated = true
		sess.Flags |= smb.SessionFlagIsGuest
		sess.Username = sess.AuthAcceptor.User() + " (GUEST)"
		sess.Domain = sess.AuthAcceptor.Domain()
		sess.Workstation = sess.AuthAcceptor.Workstation()
	} else {
		// Auth rejected — discard the session so a retry starts fresh.
		c.removeSession(sess.ID)
	}

	// Derive signing/verification keys before sending the final reply, so
	// that the SessionSetup2Res itself is signed (per MS-SMB2 §3.3.5.5).
	// Skip for guest/null sessions: they negotiate signing off.
	if status == smb.StatusOk && len(sess.SessionKey) > 0 &&
		sess.Flags&(smb.SessionFlagIsGuest|smb.SessionFlagIsNull) == 0 {
		// MS-SMB2 §3.3.5.5.3: Session.SigningRequired = server-required
		// OR client SecurityMode includes SMB2_NEGOTIATE_SIGNING_REQUIRED.
		// Set before deriveKeys so anything downstream that consults it
		// (shouldSign on the SessionSetup2Res itself) sees the right value.
		sess.SigningRequired = c.SigningRequired ||
			(c.ClientSecurityMode&smb.SecurityModeSigningRequired != 0)
		logger.Debugf("SessionSetup: SigningRequired=%v ClientSecurityMode=0x%x", sess.SigningRequired, c.ClientSecurityMode)
		if err := c.deriveKeys(sess); err != nil {
			logger.Errorf("SessionSetup2: deriveKeys failed: %v", err)
			c.removeSession(sess.ID)
			return c.writeSessionSetupReply(ctx, h, sess.ID, smb.StatusLogonFailure, nil, sess)
		}
		// Derive S2C/C2S cipher keys when encryption is supported. Sets
		// SessionFlagEncryptData on success so the dispatch path engages
		// TransformHeader on subsequent traffic.
		if err := c.deriveEncryptionKeys(sess); err != nil {
			logger.Errorf("SessionSetup2: deriveEncryptionKeys failed: %v", err)
			c.removeSession(sess.ID)
			return c.writeSessionSetupReply(ctx, h, sess.ID, smb.StatusLogonFailure, nil, sess)
		}
	}

	logger.Debugf("SessionSetup2 from %s SessionID=%d: status=0x%08x user=%q domain=%q flags=0x%x signing=%t, isGuest=%v, isNullAuth=%v",
		c.RemoteAddr, sess.ID, status, sess.Username, sess.Domain, sess.Flags, sess.SigningActive, sess.Flags&smb.SessionFlagIsGuest == smb.SessionFlagIsGuest, sess.Flags&smb.SessionFlagIsNull == smb.SessionFlagIsNull)

	return c.writeSessionSetupReply(ctx, h, sess.ID, status, out, sess)
}

// verifyAndCapture wires the configured Authenticator into the SPNEGO
// acceptor's NTLMAuthCallback shape, and fires OnCredentialCaptured with the
// pre-formatted hashcat string regardless of the verify outcome.
func (c *Conn) verifyAndCapture(sess *Session, auth *ntlmssp.Authenticate, chal [8]byte) ([]byte, uint32) {
	cfg := c.Server.Config

	cred := BuildCredential(c, auth, chal)
	if cb := cfg.OnCredentialCaptured; cb != nil {
		cb(c, cred)
	}

	// Anonymous handshakes have nothing to verify.
	if sess.NTLMServer != nil && sess.NTLMServer.IsAnonymous() {
		if cfg.AllowAnonymous {
			return nil, smb.StatusOk
		}
		return nil, smb.StatusLogonFailure
	}

	auther := cfg.authenticator()
	return auther.Verify(c, auth, chal)
}

// writeSessionSetupReply serializes a SessionSetup response. securityBlob,
// when non-nil, is sent verbatim — callers (the SPNEGO acceptor) are
// responsible for producing fully-formed NegTokenResp bytes. nil produces an
// empty SecurityBlob.
//
// The pre-keys legs (SessionSetupNegotiate, plus any failure case where
// keys haven't been derived) are folded into the session preauth chain so
// the eventual deriveKeys call has the right context. The final
// authenticated reply is signed via writeReply's normal path.
func (c *Conn) writeSessionSetupReply(ctx pduCtx, reqHdr *smb.Header, sessionID uint64, status uint32, securityBlob []byte, sess *Session) error {
	res := smb.SessionSetupRes{
		Header:        buildResponseHeader(reqHdr, status, sessionID, smb.CommandSessionSetup),
		StructureSize: 9,
	}

	if sess != nil {
		res.Flags = sess.Flags
	}

	if securityBlob != nil {
		res.SecurityBlob = securityBlob
	} else {
		if status == smb.StatusMoreProcessingRequired {
			return fmt.Errorf("internal: MoreProcessingRequired without securityBlob")
		}
		// Some clients expect a zero-length blob; the encoder handles it.
		res.SecurityBlob = []byte{}
	}

	// Final SessionSetup leg: sign whenever we *can* (signing keys derived,
	// not guest/null) — even when the inbound SessionSetup2 itself was not
	// signed. The client never has signing keys at send time but expects
	// the final reply to be signed (MS-SMB2 §3.3.5.5), so use canSign()
	// here rather than the per-request shouldSign().
	if sess != nil && sess.canSign() {
		return c.writeSignedReply(&res, sess)
	}

	// Otherwise this is a pre-keys leg: fold the outbound bytes into the
	// session preauth chain (when the session exists) so the next inbound
	// leg sees the correct context.
	if sess != nil {
		return c.writeReplyPreauth(ctx, &res, &sess.preauthChain)
	}
	return c.writeReply(ctx, &res)
}

// buildResponseHeader assembles an SMB2 header for a reply, echoing fields
// from the inbound request and setting SMB2_FLAGS_SERVER_TO_REDIR. command
// is provided explicitly because some SessionSetup paths (e.g. anonymous
// fast-path) construct replies without re-parsing the request.
func buildResponseHeader(reqHdr *smb.Header, status uint32, sessionID uint64, command uint16) smb.Header {
	return smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  reqHdr.CreditCharge,
		Status:        status,
		Command:       command,
		Credits:       1,
		Flags:         smb.SMB2_FLAGS_SERVER_TO_REDIR,
		MessageID:     reqHdr.MessageID,
		TreeID:        reqHdr.TreeID,
		SessionID:     sessionID,
		Signature:     make([]byte, 16),
	}
}
