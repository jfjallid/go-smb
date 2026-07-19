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
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/golog"
)

// maxNetBIOSPayload is the upper bound on a single SMB2 PDU after framing,
// per MS-SMB2 (24-bit length field).
const maxNetBIOSPayload = 0x00FFFFFF

// Conn is the per-connection state. Public so hooks can read or mutate it.
type Conn struct {
	Server     *Server
	RemoteAddr net.Addr

	// Negotiated parameters (filled by the Negotiate handler; per-session
	// signing/cipher state is held on each Session).
	Dialect            uint16
	SigningRequired    bool   // server-side policy from cfg, echoed in NegotiateRes.SecurityMode
	ClientSecurityMode uint16 // raw SecurityMode from the inbound NegotiateReq (drives Session.SigningRequired)
	SupportsEncryption bool
	ClientWantsEncrypt bool // client offered GlobalCapEncryption in NegotiateReq
	CipherID           uint16
	SigningID          uint16
	PreauthHashID      uint16
	ClientGUID         [16]byte

	// NegotiatedCapabilities and NegotiatedSecurityMode capture the exact
	// values emitted in NegotiateRes (post-OnNegotiate-hook). They are the
	// authoritative source for FSCTL_VALIDATE_NEGOTIATE_INFO replies — the
	// client uses them to detect a downgrade attack and any divergence from
	// what we actually sent will fail the check.
	NegotiatedCapabilities uint32
	NegotiatedSecurityMode uint16

	// preauthChain holds the running SHA-512 chain over Negotiate (req+res).
	// On the first SessionSetup leg this is copied into Session.preauthChain
	// and continues to be updated there until keys are derived. Only used
	// when the negotiated dialect is SMB 3.1.1.
	preauthChain [64]byte

	nc       net.Conn
	writeMu  sync.Mutex
	closeMu  sync.Mutex
	closed   bool
	closeErr error

	sessionsMu    sync.Mutex
	sessions      map[uint64]*Session
	nextSessionID uint64

	// seenMsgIDs records the MessageIDs we've already accepted on this
	// connection. MS-SMB2 §3.3.5.2.3 requires the server to reject a
	// duplicate MessageId — clients that reuse one (or stay at the same
	// value across requests, e.g. when they forget to advance the counter
	// for a CreditCharge=0 Negotiate) are sequence-violators and a strict
	// server disconnects. The tracker bounds its memory (see msgIDTracker)
	// so a client that holds the connection open and keeps incrementing the
	// counter cannot grow it without limit.
	seenMsgIDs msgIDTracker

	// log is the per-connection logger, lazily derived from the configured
	// Logger with the remote address baked in as a prefix. Access through
	// c.logger().
	log Logger
}

// maxTrackedMsgIDs caps a single generation of the MessageId dedup set. Two
// generations are retained at most (see msgIDTracker), so worst-case memory is
// ~2*maxTrackedMsgIDs entries. The value is far larger than any realistic
// outstanding-request window (the server grants a tiny credit window), so a
// well-behaved client never trips the rotation, while a misbehaving one is
// capped instead of growing the set without bound.
const maxTrackedMsgIDs = 4096

// msgIDTracker is a memory-bounded set for MessageId duplicate detection. A
// naive "remember every MessageId forever" map grows without limit for a
// client that holds the connection open and keeps incrementing the counter
// (slow memory-exhaustion DoS, finding #3). Instead it keeps at most two
// generations: once cur fills to maxTrackedMsgIDs it is demoted to prev and a
// fresh cur is started, so retained entries never exceed 2*maxTrackedMsgIDs
// while any duplicate within at least the last maxTrackedMsgIDs distinct IDs
// is still detected — well beyond the sequence/credit window that legitimately
// bounds in-flight MessageIds. The mutex guards against any future concurrent
// dispatch; today serve() drives a single goroutine per connection.
type msgIDTracker struct {
	mu   sync.Mutex
	cur  map[uint64]struct{}
	prev map[uint64]struct{}
}

// seen reports whether id was already accepted on this connection, recording
// it as seen when it was not.
func (t *msgIDTracker) seen(id uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.cur[id]; ok {
		return true
	}
	if _, ok := t.prev[id]; ok {
		return true
	}
	if t.cur == nil {
		t.cur = make(map[uint64]struct{})
	} else if len(t.cur) >= maxTrackedMsgIDs {
		t.prev = t.cur
		t.cur = make(map[uint64]struct{}, maxTrackedMsgIDs)
	}
	t.cur[id] = struct{}{}
	return false
}

// connLogger derives a per-connection logger that carries the remote address
// as a message prefix. When the configured Logger is a *golog.MyLogger (the
// default), a detached child is returned via golog's With; custom Logger
// implementations are returned unchanged (and continue to receive the remote
// address as an explicit argument where it matters).
func connLogger(base Logger, remote net.Addr) Logger {
	if ml, ok := base.(*golog.MyLogger); ok {
		return ml.With("[" + remote.String() + "]")
	}
	return base
}

// logger returns the connection's logger, deriving and caching it on first
// use. Handlers use this so every line is tagged with the remote address.
func (c *Conn) logger() Logger {
	if c.log == nil {
		c.log = connLogger(c.Server.Config.logger(), c.RemoteAddr)
	}
	return c.log
}

// pduCtx carries per-request state through the dispatch chain. The signing
// decision is per-request (MS-SMB2 §3.3.4.1.1) and an encrypted inbound
// requires an encrypted reply (§3.3.4.1.4); both flags travel with the
// request rather than living on the connection so handlers, reply emitters,
// and any future async dispatch paths see consistent values without sharing
// mutable connection-level state.
type pduCtx struct {
	// signed is true when the inbound PDU arrived plaintext with
	// SMB2_FLAGS_SIGNED set. The reply must mirror this flag.
	signed bool
	// encrypted is true when the inbound PDU arrived inside a
	// TransformHeader. The reply must be encrypted regardless of
	// Session.EncryptData.
	encrypted bool
	// chain accumulates outbound PDUs for the current inbound chain. When
	// non-nil, reply emitters append into it (deferring signing until flush)
	// instead of writing directly to the socket. dispatchSMB2Inner creates
	// the chain on entry and flushes on the way out, so handlers — and any
	// hook that runs through the normal write path — produce well-formed
	// compounded replies for compounded requests, and unchanged single-PDU
	// behavior for non-compounded requests. A nil chain (used by early-exit
	// paths that construct their own pduCtx{}) means "write immediately".
	chain *chainState
}

// chainState holds the outbound side of a compound chain in progress, plus
// the carry-over state needed to honor SMB2_FLAGS_RELATED_OPERATIONS on
// subsequent inbound PDUs (MS-SMB2 §3.3.5.2.7). The state is allocated by
// dispatchSMB2Inner and discarded once flushChain has written the bytes.
type chainState struct {
	// pdus is the list of unsigned reply PDUs in order. Each is a complete
	// SMB2 PDU (header + body); NextCommand and Signature fields are
	// finalized at flush time so signing covers the correct bytes.
	pdus []chainPDU
	// lastReplySessionID / lastReplyTreeID are taken from the most recent
	// reply header and substituted into the next inbound PDU when it carries
	// FLAGS_RELATED_OPERATIONS. Per the spec the carry-over is from the
	// previous *successful* reply; we use the reply header values verbatim
	// (handlers set them appropriately on error too).
	lastReplySessionID uint64
	lastReplyTreeID    uint32
	// lastCreateFID is the FileId from the most recent successful Create
	// reply in this chain. A subsequent related PDU whose FileId is the
	// all-ones sentinel (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF) substitutes
	// this value before handler dispatch.
	lastCreateFID [16]byte
	hasLastFID    bool
}

// chainPDU is a single reply PDU queued in chainState. sign records whether
// the PDU must carry a signature at flush time (driven by the per-request
// shouldSign() outcome or canSign() for SessionSetup-completion frames);
// signing is deferred so it covers the final NextCommand value.
//
// signed mirrors the inbound's FLAGS_SIGNED bit at the moment this reply
// was queued. It's recorded per-PDU because dispatchSMB2Inner receives ctx
// by value (the chain itself is a pointer, but scalar fields stay local) —
// so by flush time the outer dispatchSMB2Chain frame has lost the bit. The
// per-request signing decision (MS-SMB2 §3.3.4.1.1) is captured at append
// time and consulted in flushChain.
type chainPDU struct {
	bytes  []byte
	sign   bool
	signed bool
}

func newConn(s *Server, nc net.Conn) *Conn {
	return &Conn{
		Server:     s,
		RemoteAddr: nc.RemoteAddr(),
		nc:         nc,
	}
}

// close closes the underlying net.Conn idempotently.
func (c *Conn) close() {
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	c.closeErr = c.nc.Close()
}

// serve is the per-connection main loop: read framed PDUs, dispatch, write
// replies until the connection is closed or a fatal error occurs.
func (c *Conn) serve() {
	logger := c.logger()
	defer func() {
		// A malformed PDU can drive a hand-rolled parser into a panic (e.g. an
		// out-of-range slice). Recover here so a single bad connection cannot
		// take down the whole server; the connection is still torn down below.
		if r := recover(); r != nil {
			logger.Errorf("recovered from panic while serving connection: %v", r)
		}
		c.cleanupSessions()
		if cb := c.Server.Config.OnDisconnect; cb != nil {
			cb(c)
		}
		c.close()
	}()

	logger.Debugf("client connected")

	if cb := c.Server.Config.OnConnect; cb != nil {
		if err := cb(c); err != nil {
			logger.Errorf("OnConnect rejected: %v", err)
			return
		}
	}

	for {
		pkt, err := readPacket(c.nc)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				logger.Debugf("read error: %v", err)
			}
			return
		}
		if len(pkt) == 0 {
			continue
		}

		if cb := c.Server.Config.OnRawRequest; cb != nil {
			handled, err := cb(c, pkt)
			if err != nil {
				logger.Errorf("OnRawRequest aborted connection: %v", err)
				return
			}
			if handled {
				continue
			}
		}

		if err := c.dispatch(pkt); err != nil {
			logger.Debugf("dispatch error: %v", err)
			return
		}
	}
}

// readPacket reads a single NetBIOS-framed SMB packet from conn. The leading
// 4 bytes are the big-endian payload length (top byte ignored / reserved).
// This mirrors smb.readPacket in connection.go but is duplicated here so the
// server package does not depend on unexported client-side helpers.
func readPacket(conn net.Conn) ([]byte, error) {
	var size uint32
	if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size > maxNetBIOSPayload {
		return nil, errInvalidNetBIOS
	}
	pkt := make([]byte, size)
	if _, err := io.ReadFull(conn, pkt); err != nil {
		return nil, err
	}
	return pkt, nil
}

// sendPacket writes a single NetBIOS-framed SMB packet onto the connection.
// The 4-byte length prefix is added here. If the packet's SessionID maps to
// a session with SessionFlagEncryptData set the buffer is wrapped in a
// TransformHeader (signing is skipped — the AEAD tag carries integrity). If
// the session is signed but not encrypted the buffer is signed in place
// before being written. Concurrent calls are serialized. ctx supplies the
// per-request signed/encrypted state from the inbound PDU so the reply can
// mirror it (MS-SMB2 §3.3.4.1.1, §3.3.4.1.4).
func (c *Conn) sendPacket(ctx pduCtx, buf []byte) error {
	out, encrypted, err := c.maybeEncrypt(ctx, buf)
	if err != nil {
		return err
	}
	if !encrypted {
		c.maybeSign(ctx, buf)
		out = buf
	}
	return c.sendPacketUnsigned(out)
}

// sendPacketUnsigned bypasses the auto-sign path; used by writeSignedReply
// where the caller has already signed.
func (c *Conn) sendPacketUnsigned(buf []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(buf)))

	var w bytes.Buffer
	w.Grow(4 + len(buf))
	w.Write(hdr)
	w.Write(buf)

	_, err := c.nc.Write(w.Bytes())
	return err
}

// maybeSign auto-signs SMB2 PDUs whose SessionID maps to a session with
// signing keys derived (i.e. not Negotiate, not pre-auth SessionSetup). ctx
// carries the inbound-was-signed flag so the reply mirrors per MS-SMB2
// §3.3.4.1.1.
func (c *Conn) maybeSign(ctx pduCtx, buf []byte) {
	if len(buf) < 64 || string(buf[0:4]) != smb.ProtocolSmb2 {
		return
	}
	sid := binary.LittleEndian.Uint64(buf[40:48])
	if sid == 0 {
		return
	}
	sess := c.session(sid)
	if sess == nil || !sess.shouldSign(ctx) {
		return
	}
	sess.signPDU(buf)
}

// maybeEncrypt wraps an outbound SMB2 PDU in a TransformHeader when the
// owning session has negotiated encryption (SessionFlagEncryptData) or the
// inbound request itself was encrypted. The second return value reports
// whether wrapping happened, so the caller can skip signing on encrypted
// frames (MS-SMB2 §3.3.4.1.4: signing and encryption are mutually exclusive
// on a given message).
func (c *Conn) maybeEncrypt(ctx pduCtx, buf []byte) ([]byte, bool, error) {
	if len(buf) < 64 || string(buf[0:4]) != smb.ProtocolSmb2 {
		return buf, false, nil
	}
	sid := binary.LittleEndian.Uint64(buf[40:48])
	if sid == 0 {
		return buf, false, nil
	}
	sess := c.session(sid)
	if sess == nil || sess.encrypter == nil {
		return buf, false, nil
	}
	// Encrypt when the session has opted in (RequireEncryption / per-tree
	// encryption) OR when the inbound request itself arrived encrypted —
	// per MS-SMB2 §3.3.4.1.4 the response to an encrypted request MUST also
	// be encrypted.
	if sess.Flags&smb.SessionFlagEncryptData == 0 && !ctx.encrypted {
		return buf, false, nil
	}
	// MS-SMB2 §3.3.4.1.4: when the trigger is Session.EncryptData (not a
	// per-request "request was encrypted" mirror), SMB2 NEGOTIATE and
	// SMB2 SESSION_SETUP responses are EXEMPT from encryption. Without this
	// exemption an encrypted SessionSetup-completion reply would land on a
	// pre-session client (no decrypt path until enableSession() runs) and
	// be unparseable.
	cmd := binary.LittleEndian.Uint16(buf[12:14])
	if !ctx.encrypted && (cmd == smb.CommandNegotiate || cmd == smb.CommandSessionSetup) {
		return buf, false, nil
	}
	out, err := encryptOutbound(sess, buf)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// writeReply marshals a response struct and sends it, applying any
// OnRawResponse hook between marshal and wire-write. Used for unsigned or
// pre-auth replies. ctx is the per-PDU context from the inbound request so
// the reply can mirror its signed/encrypted state. When ctx.chain is set
// (the normal dispatch path) the bytes are queued for compound-aware flush
// instead of sent immediately.
func (c *Conn) writeReply(ctx pduCtx, res any) error {
	buf, err := encoder.Marshal(res)
	if err != nil {
		return err
	}
	if cb := c.Server.Config.OnRawResponse; cb != nil {
		buf, err = cb(c, buf)
		if err != nil {
			return err
		}
	}
	return c.appendOrSend(ctx, buf, signAuto)
}

// writeSignedReply is the writeReply variant that forces signing on the
// outbound PDU. Used by SessionSetup completion where the spec demands the
// final reply itself carry a signature even when the inbound was not signed
// (MS-SMB2 §3.3.5.5). Callers must guarantee sess.canSign() — this path is
// not used outside the SessionSetup completion handler. The sess argument
// is the signer; we don't look it up by SessionID because the SessionSetup2
// completion path runs before any subsequent inbound has a chance to
// reference the session via the connection table.
func (c *Conn) writeSignedReply(res any, sess *Session) error {
	buf, err := encoder.Marshal(res)
	if err != nil {
		return err
	}
	if cb := c.Server.Config.OnRawResponse; cb != nil {
		buf, err = cb(c, buf)
		if err != nil {
			return err
		}
	}
	sess.signPDU(buf)
	return c.sendPacketUnsigned(buf)
}

// writeRawError builds a minimal SMB2 header-only error response for an
// inbound packet. Used by OnUnknownCommand default and other early-exit paths.
// reqHdr is the inbound header (so we can echo MessageID / TreeID / SessionID).
func (c *Conn) writeRawError(ctx pduCtx, reqHdr *smb.Header, status uint32) error {
	resHdr := smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  reqHdr.CreditCharge,
		Status:        status,
		Command:       reqHdr.Command,
		Credits:       grantedCredits(reqHdr),
		Flags:         smb.SMB2_FLAGS_SERVER_TO_REDIR,
		MessageID:     reqHdr.MessageID,
		TreeID:        reqHdr.TreeID,
		SessionID:     reqHdr.SessionID,
		Signature:     make([]byte, 16),
	}
	hdrBytes, err := encoder.Marshal(resHdr)
	if err != nil {
		return err
	}
	// SMB2 ERROR Response (MS-SMB2 2.2.2): StructureSize=9, ErrorContextCount=0,
	// Reserved=0, ByteCount=0, ErrorData=[1 byte zero per spec when ByteCount=0].
	body := []byte{
		9, 0, // StructureSize
		0,          // ErrorContextCount
		0,          // Reserved
		0, 0, 0, 0, // ByteCount=0
		0, // ErrorData (1 byte to satisfy spec when no error context)
	}
	out := append(hdrBytes, body...)
	if cb := c.Server.Config.OnRawResponse; cb != nil {
		out, err = cb(c, out)
		if err != nil {
			return err
		}
	}
	return c.appendOrSend(ctx, out, signAuto)
}

// signMode controls how appendOrSend / flushChain decide whether to stamp a
// signature on a queued reply PDU.
type signMode int

const (
	// signAuto: sign at flush time iff the session's shouldSign() says so
	// (per-request mirror; MS-SMB2 §3.3.4.1.1).
	signAuto signMode = iota
	// signForce: always sign (SessionSetup completion path).
	signForce
)

// appendOrSend either queues a fully-built reply PDU into the current
// dispatch chain (preferred — flushChain will sign and write) or, when no
// chain is active (early-exit paths that construct their own pduCtx{}),
// signs as appropriate and writes immediately. The two behaviors are
// observationally equivalent for non-compounded traffic; the chain path is
// what makes compounded replies emerge from existing handlers without
// per-handler changes.
func (c *Conn) appendOrSend(ctx pduCtx, pkt []byte, mode signMode) error {
	if ctx.chain == nil {
		// Detached write: behaves like the pre-compound code path. Used by
		// callers that synthesize their own pduCtx (e.g. early-error paths
		// in serve() before dispatch begins). signForce mirrors the old
		// writeSignedReply behavior.
		if mode == signForce {
			sid := binary.LittleEndian.Uint64(pkt[40:48])
			if sess := c.session(sid); sess != nil && sess.canSign() {
				sess.signPDU(pkt)
				return c.sendPacketUnsigned(pkt)
			}
		}
		return c.sendPacket(ctx, pkt)
	}
	// Queue for compound-aware flush. Remember the most-recent reply header
	// fields so the next inbound PDU's RELATED_OPERATIONS substitution sees
	// them. We also note the FileId of a Create reply so subsequent related
	// ops in the chain can use the 0xFF...FF sentinel.
	if len(pkt) >= 64 && string(pkt[0:4]) == smb.ProtocolSmb2 {
		cmd := binary.LittleEndian.Uint16(pkt[12:14])
		ctx.chain.lastReplyTreeID = binary.LittleEndian.Uint32(pkt[36:40])
		ctx.chain.lastReplySessionID = binary.LittleEndian.Uint64(pkt[40:48])
		if cmd == smb.CommandCreate {
			// CreateRes layout: header(64) + StructureSize(2) + ... +
			// FileId at body offset 64 (packet offset 128). Sanity-check
			// the length before reading.
			const fidOff = 64 + 64
			if len(pkt) >= fidOff+16 && binary.LittleEndian.Uint32(pkt[64+0:64+4])&0xFFFF == 89 {
				copy(ctx.chain.lastCreateFID[:], pkt[fidOff:fidOff+16])
				ctx.chain.hasLastFID = true
			}
		}
	}
	ctx.chain.pdus = append(ctx.chain.pdus, chainPDU{
		bytes:  pkt,
		sign:   mode == signForce,
		signed: ctx.signed,
	})
	return nil
}

// flushChain finalizes the in-progress compound chain: pads each PDU to an
// 8-byte boundary, fills in each PDU's NextCommand field, signs each PDU
// per-PDU after the NextCommand fixup (signing covers the whole final PDU
// per §3.1.4.1), then writes the whole compound via sendPacket so that
// encryption — if engaged — wraps the entire compound in a single
// TransformHeader (§3.1.4.3). When the chain holds zero or one PDU the
// fast path is taken and behavior is identical to the pre-compound code.
func (c *Conn) flushChain(ctx pduCtx, cs *chainState) error {
	if cs == nil || len(cs.pdus) == 0 {
		return nil
	}
	if len(cs.pdus) == 1 {
		p := cs.pdus[0]
		detached := ctx
		detached.chain = nil
		detached.signed = p.signed
		if p.sign {
			sid := binary.LittleEndian.Uint64(p.bytes[40:48])
			if sess := c.session(sid); sess != nil && sess.signer != nil {
				sess.signPDU(p.bytes)
				// Pre-signed: bypass sendPacket's maybeSign so we don't
				// re-sign. Still go through maybeEncrypt in case this is
				// a transport-encrypted session.
				out, encrypted, err := c.maybeEncrypt(detached, p.bytes)
				if err != nil {
					return err
				}
				if !encrypted {
					out = p.bytes
				}
				return c.sendPacketUnsigned(out)
			}
		}
		return c.sendPacket(detached, p.bytes)
	}

	// Multi-PDU: lay out all PDUs with inter-PDU 8-byte padding so each
	// header lands at an 8-aligned offset (clients verify this).
	starts := make([]int, len(cs.pdus))
	var out []byte
	for i, p := range cs.pdus {
		starts[i] = len(out)
		out = append(out, p.bytes...)
		if i < len(cs.pdus)-1 {
			if pad := (8 - (len(out) % 8)) % 8; pad > 0 {
				out = append(out, make([]byte, pad)...)
			}
		}
	}
	// NextCommand fixup for every PDU except the last.
	for i := 0; i < len(cs.pdus)-1; i++ {
		next := uint32(starts[i+1] - starts[i])
		binary.LittleEndian.PutUint32(out[starts[i]+20:starts[i]+24], next)
	}
	// Per-PDU signing. The signed region for each PDU is its bytes plus the
	// trailing inter-PDU padding (for all but the last PDU); MS-SMB2 §3.1.4.1
	// signs each segment with the header layout it has on the wire. The
	// per-request signed flag was captured at append time (p.signed) — the
	// outer ctx may have lost it because dispatch passes ctx by value.
	for i, p := range cs.pdus {
		var end int
		if i < len(cs.pdus)-1 {
			end = starts[i+1]
		} else {
			end = len(out)
		}
		seg := out[starts[i]:end]
		shouldSign := p.sign
		if !shouldSign && p.signed {
			pCtx := ctx
			pCtx.signed = true
			sid := binary.LittleEndian.Uint64(seg[40:48])
			if sess := c.session(sid); sess != nil && sess.shouldSign(pCtx) {
				shouldSign = true
			}
		}
		if shouldSign {
			sid := binary.LittleEndian.Uint64(seg[40:48])
			if sess := c.session(sid); sess != nil && sess.canSign() {
				sess.signPDU(seg)
			}
		}
	}
	// Apply transport encryption to the whole compound, if engaged.
	detached := ctx
	detached.chain = nil
	encOut, encrypted, err := c.maybeEncryptCompound(detached, out)
	if err != nil {
		return err
	}
	if !encrypted {
		encOut = out
	}
	return c.sendPacketUnsigned(encOut)
}

// maybeEncryptCompound is the compound-aware counterpart of maybeEncrypt.
// It decides whether to wrap the whole compound based on the first PDU's
// SessionID — every PDU in a compound shares the SessionID per spec.
func (c *Conn) maybeEncryptCompound(ctx pduCtx, buf []byte) ([]byte, bool, error) {
	if len(buf) < 64 || string(buf[0:4]) != smb.ProtocolSmb2 {
		return buf, false, nil
	}
	sid := binary.LittleEndian.Uint64(buf[40:48])
	if sid == 0 {
		return buf, false, nil
	}
	sess := c.session(sid)
	if sess == nil || sess.encrypter == nil {
		return buf, false, nil
	}
	if sess.Flags&smb.SessionFlagEncryptData == 0 && !ctx.encrypted {
		return buf, false, nil
	}
	// Negotiate/SessionSetup exemption (only relevant for non-mirror
	// encryption); see maybeEncrypt for context.
	cmd := binary.LittleEndian.Uint16(buf[12:14])
	if !ctx.encrypted && (cmd == smb.CommandNegotiate || cmd == smb.CommandSessionSetup) {
		return buf, false, nil
	}
	out, err := encryptOutbound(sess, buf)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

var errInvalidNetBIOS = errInvalidNetBIOSValue{}

type errInvalidNetBIOSValue struct{}

func (errInvalidNetBIOSValue) Error() string { return "invalid NetBIOS session message" }
