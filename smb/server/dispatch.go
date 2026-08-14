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
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/compress"
)

// allOnesFID is the SMB2 "use the FileId from the previous Create in this
// compound chain" sentinel (MS-SMB2 §3.3.5.2.7.2).
var allOnesFID = [16]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// dispatch routes a single inbound PDU. The server side dispatches by
// Command opcode (in contrast to the client, which dispatches inbound
// responses by MessageID). Returning a non-nil error closes the connection.
func (c *Conn) dispatch(raw []byte) error {
	if len(raw) < 4 {
		return fmt.Errorf("packet too short (%d bytes)", len(raw))
	}

	logger := c.logger()
	protID := string(raw[:4])

	switch protID {
	case smb.ProtocolSmb:
		// SMB1 multi-protocol-negotiate first packet. The only legitimate
		// SMB1 traffic we accept is the initial NEGOTIATE so we can answer
		// in SMB2. Anything else: drop the connection.
		return c.dispatchSMB1(raw)

	case smb.ProtocolSmb2:
		// Normal SMB2/3 PDU (possibly compounded).
		return c.dispatchSMB2Chain(raw, pduCtx{})

	case smb.ProtocolTransformHdr:
		// Encrypted SMB 3.x PDU: peel the TransformHeader, AEAD-decrypt
		// with the session's C2S key, then re-enter dispatch with the
		// plaintext SMB2 frame. AEAD authentication replaces signing on
		// the inner PDU (MS-SMB2 §3.3.4.1.4).
		plain, _, err := c.decryptInbound(raw)
		if err != nil {
			logger.Errorf("decrypt failed for %s: %v", c.RemoteAddr, err)
			return err
		}
		// A decrypted PDU may itself be a compression frame (compress then
		// encrypt on send); decompress before dispatching.
		if compress.IsCompressionFrame(plain) {
			plain, err = c.Compression.Decompress(plain)
			if err != nil {
				logger.Errorf("decompress failed for %s: %v", c.RemoteAddr, err)
				return err
			}
		}
		// MS-SMB2 §3.3.4.1.4: the response to an encrypted request MUST
		// be encrypted. Carry the flag through dispatch so the reply is
		// wrapped even when Session.EncryptData isn't set.
		return c.dispatchSMB2Chain(plain, pduCtx{encrypted: true})

	case smb.ProtocolCompressionHdr:
		// Compressed (unencrypted) SMB 3.1.1 PDU: decompress and re-dispatch
		// the reconstructed SMB2 frame.
		plain, err := c.Compression.Decompress(raw)
		if err != nil {
			logger.Errorf("decompress failed for %s: %v", c.RemoteAddr, err)
			return err
		}
		return c.dispatchSMB2Chain(plain, pduCtx{})

	default:
		logger.Errorf("unknown protocol id: %x", raw[:4])
		return fmt.Errorf("unknown protocol id %x", raw[:4])
	}
}

// dispatchSMB1 handles the SMB1 multi-protocol Negotiate Protocol packet that
// many clients send first. We respond in SMB2 and let the next round of
// dispatch run normally.
func (c *Conn) dispatchSMB1(raw []byte) error {
	if len(raw) < 36 {
		return fmt.Errorf("SMB1 packet too short")
	}
	var h smb.SMB1Header
	if err := h.UnmarshalBinary(raw[:32]); err != nil {
		return formatErr("decode SMB1 header", err)
	}
	if h.Command != smb.SMB1CommandNegotiate {
		return fmt.Errorf("unsupported SMB1 command 0x%x (only Negotiate accepted)", h.Command)
	}
	return c.handleSMB1Negotiate()
}

// dispatchSMB2Chain walks the inbound buffer, splitting it into individual
// PDUs using the NextCommand field of each header (MS-SMB2 §2.2.1.2). Each
// segment is dispatched in turn through dispatchSMB2Inner, with a shared
// chainState accumulating replies. After the last segment the chain is
// flushed: NextCommand fields are fixed up, each reply is signed per-PDU
// (signing covers the final NextCommand bytes), the whole compound is
// optionally wrapped in a single TransformHeader, and the framed packet is
// written to the wire. Non-compounded requests (the common case) result in
// a single-PDU chain that flushes identically to the pre-compound code path.
func (c *Conn) dispatchSMB2Chain(raw []byte, ctx pduCtx) error {
	chain := &chainState{}
	ctx.chain = chain

	rest := raw
	for len(rest) > 0 {
		// Each segment starts with a 64-byte SMB2 header. NextCommand is at
		// offset 20 within the header and gives the byte distance from the
		// start of this PDU to the start of the next one in the chain. The
		// last (or only) PDU has NextCommand=0 and consumes the remainder.
		if len(rest) < 64 {
			return fmt.Errorf("SMB2 chain segment too short (%d bytes)", len(rest))
		}
		next := int(binary.LittleEndian.Uint32(rest[20:24]))
		var seg []byte
		if next > 0 {
			if next < 64 || next > len(rest) {
				return fmt.Errorf("invalid NextCommand=%d (segment len=%d)", next, len(rest))
			}
			seg = rest[:next]
			rest = rest[next:]
		} else {
			seg = rest
			rest = nil
		}
		if err := c.dispatchSMB2Inner(seg, ctx); err != nil {
			return err
		}
	}
	return c.flushChain(ctx, chain)
}

func (c *Conn) dispatchSMB2Inner(raw []byte, ctx pduCtx) error {
	if len(raw) < 64 {
		return fmt.Errorf("SMB2 packet too short (%d bytes)", len(raw))
	}
	var h smb.Header
	if err := h.UnmarshalBinary(raw[:64]); err != nil {
		return formatErr("decode SMB2 header", err)
	}
	if h.StructureSize != 64 {
		return fmt.Errorf("invalid SMB2 header structure size %d", h.StructureSize)
	}

	// MS-SMB2 §3.3.5.2.3 — verify MessageId. The sentinel 0xFFFFFFFFFFFFFFFF
	// means "ignore this request" (used for unsolicited interim responses);
	// any other reused MessageId is a sequence violation and the server MUST
	// disconnect. Skipping this check leaves the server vulnerable to clients
	// (or buggy SMB stacks) that forget to advance the message counter, e.g.
	// after an SMB2 NegotiateReq with CreditCharge=0.
	//
	// CANCEL is the documented exception (§3.2.4.24): it intentionally reuses
	// the MessageId of the request it cancels, so it must not be flagged as a
	// duplicate.
	if !ctx.encrypted && h.Command != smb.CommandCancel {
		const ignoreMID = uint64(0xFFFFFFFFFFFFFFFF)
		if h.MessageID != ignoreMID {
			if c.seenMsgIDs.seen(h.MessageID) {
				c.logger().Errorf(
					"duplicate MessageId %d from %s (cmd=0x%x); disconnecting",
					h.MessageID, c.RemoteAddr, h.Command)
				return fmt.Errorf("duplicate MessageId %d", h.MessageID)
			}
		}
	}

	// Track whether this plaintext inbound carried FLAGS_SIGNED so the
	// outbound path can mirror it (§3.3.4.1.1: signing is decided
	// per-request). Encrypted frames have signing=N/A — AEAD replaces it.
	if !ctx.encrypted && h.Flags&smb.SMB2_FLAGS_SIGNED != 0 {
		ctx.signed = true
	}

	// SMB2_FLAGS_RELATED_OPERATIONS: this PDU's SessionID / TreeID and (if
	// the FID is the all-ones sentinel) FileId are inherited from the prior
	// reply in the same chain. Per §3.3.5.2.7.2 the substitution happens
	// after signature verification (which uses the wire bytes verbatim) but
	// before handler dispatch. We work on a copy so the signature path keeps
	// seeing the as-received buffer.
	if !ctx.encrypted && h.Flags&smb.SMB2_FLAGS_RELATED_OPERATIONS != 0 && ctx.chain != nil {
		patched := make([]byte, len(raw))
		copy(patched, raw)
		binary.LittleEndian.PutUint32(patched[36:40], ctx.chain.lastReplyTreeID)
		binary.LittleEndian.PutUint64(patched[40:48], ctx.chain.lastReplySessionID)
		h.TreeID = ctx.chain.lastReplyTreeID
		h.SessionID = ctx.chain.lastReplySessionID
		if ctx.chain.hasLastFID {
			if off, ok := fileIDOffset(h.Command); ok && off+16 <= len(patched) {
				var got [16]byte
				copy(got[:], patched[off:off+16])
				if got == allOnesFID {
					copy(patched[off:off+16], ctx.chain.lastCreateFID[:])
				}
			}
		}
		raw = patched
	}

	// Verify inbound signature if this is a post-auth command on a signed
	// session. Negotiate (no session), Cancel (per spec) and pre-auth
	// SessionSetup are skipped by shouldVerify (no keys yet). Encrypted
	// frames bypass signature checks entirely (AEAD already authenticated).
	if !ctx.encrypted && h.SessionID != 0 && h.Command != smb.CommandNegotiate {
		if sess := c.session(h.SessionID); sess != nil && sess.shouldVerify() {
			// If the session has negotiated encryption, every inbound
			// PDU MUST arrive inside a TransformHeader. A plaintext
			// SMB2 frame on such a session is a protocol violation.
			// MS-SMB2 §3.3.5.2.4: on a signature/required-signing/encryption
			// violation the server SHOULD send STATUS_ACCESS_DENIED and then
			// disconnect. Without the disconnect a signing-required client
			// would silently drop the unsigned reject and hang waiting for
			// a response.
			if sess.Flags&smb.SessionFlagEncryptData != 0 {
				c.logger().Errorf("inbound plaintext PDU on encrypted session (cmd=0x%x)", h.Command)
				if err := c.writeRawError(ctx, &h, smb.StatusAccessDenied); err != nil {
					return err
				}
				return fmt.Errorf("disconnecting %s: plaintext PDU on encrypted session", c.RemoteAddr)
			}
			if h.Flags&smb.SMB2_FLAGS_SIGNED == 0 {
				if sess.SigningRequired {
					c.logger().Errorf("inbound PDU not signed (cmd=0x%x)", h.Command)
					if err := c.writeRawError(ctx, &h, smb.StatusAccessDenied); err != nil {
						return err
					}
					return fmt.Errorf("disconnecting %s: signing required but inbound PDU was unsigned", c.RemoteAddr)
				}
			} else if !sess.verifyPDU(raw) {
				c.logger().Errorf("inbound signature mismatch (cmd=0x%x)", h.Command)
				if err := c.writeRawError(ctx, &h, smb.StatusAccessDenied); err != nil {
					return err
				}
				return fmt.Errorf("disconnecting %s: inbound signature verification failed", c.RemoteAddr)
			}
		}
	}

	// Per-tree encryption enforcement (MS-SMB2 §3.3.5.2.11). When the
	// referenced tree's share has EncryptData=TRUE, every PDU against
	// that tree must arrive inside a TransformHeader. The session-level
	// gate above already covers SessionFlagEncryptData; this branch
	// catches the per-share case where session-level encryption was
	// never engaged but the share still demands it. TreeConnect is
	// exempt (the share lookup happens inside the handler) and so are
	// session-less commands (h.TreeID == 0). Reject without disconnect:
	// the violation is per-request, not session-wide.
	if !ctx.encrypted && h.TreeID != 0 && h.Command != smb.CommandTreeConnect {
		if sess := c.session(h.SessionID); sess != nil {
			if t := sess.tree(h.TreeID); t != nil && t.Share.EncryptData {
				c.logger().Errorf("inbound plaintext PDU on encrypted share %q from %s (cmd=0x%x tree=%d)",
					t.Share.Name, c.RemoteAddr, h.Command, h.TreeID)
				return c.writeRawError(ctx, &h, smb.StatusAccessDenied)
			}
		}
	}

	switch h.Command {
	case smb.CommandNegotiate:
		return c.handleNegotiate(ctx, raw, &h)
	case smb.CommandSessionSetup:
		return c.handleSessionSetup(ctx, raw, &h)
	case smb.CommandLogoff:
		return c.handleLogoff(ctx, &h)
	case smb.CommandTreeConnect:
		return c.handleTreeConnect(ctx, raw, &h)
	case smb.CommandTreeDisconnect:
		return c.handleTreeDisconnect(ctx, &h)
	case smb.CommandCreate:
		return c.handleCreate(ctx, raw, &h)
	case smb.CommandClose:
		return c.handleClose(ctx, raw, &h)
	case smb.CommandRead:
		return c.handleRead(ctx, raw, &h)
	case smb.CommandWrite:
		return c.handleWrite(ctx, raw, &h)
	case smb.CommandFlush:
		return c.handleFlush(ctx, raw, &h)
	case smb.CommandQueryInfo:
		return c.handleQueryInfo(ctx, raw, &h)
	case smb.CommandSetInfo:
		return c.handleSetInfo(ctx, raw, &h)
	case smb.CommandQueryDirectory:
		return c.handleQueryDirectory(ctx, raw, &h)
	case smb.CommandIOCtl:
		return c.handleIoCtl(ctx, raw, &h)
	case smb.CommandChangeNotify:
		return c.handleChangeNotify(ctx, raw, &h)
	case smb.CommandEcho:
		return c.handleEcho(ctx, &h)
	case smb.CommandCancel:
		return c.handleCancel(ctx, &h)
	default:
		return c.handleUnknownCommand(ctx, &h, raw[64:])
	}
}

// fileIDOffset returns the packet-offset of the FileId field for commands
// that carry one in the request body (header is 64 bytes; offset given is
// from the start of the *packet*, not the start of the body). Used by the
// SMB2_FLAGS_RELATED_OPERATIONS substitution path so the inbound 0xFF...FF
// sentinel is replaced with the previous Create's FID before handler
// dispatch.
func fileIDOffset(cmd uint16) (int, bool) {
	switch cmd {
	case smb.CommandClose, smb.CommandFlush, smb.CommandQueryDirectory, smb.CommandIOCtl:
		return 64 + 8, true
	case smb.CommandRead, smb.CommandWrite, smb.CommandSetInfo:
		return 64 + 16, true
	case smb.CommandQueryInfo:
		return 64 + 24, true
	}
	return 0, false
}

// handleLogoff tears down the session whose SessionID is in the header. The
// reply is a minimal LogoffRes with StatusOk.
func (c *Conn) handleLogoff(ctx pduCtx, h *smb.Header) error {
	cfg := c.Server.Config
	if sess := c.removeSession(h.SessionID); sess != nil {
		if cb := cfg.OnLogoff; cb != nil {
			cb(c, sess)
		}
	}
	res := smb.LogoffRes{
		Header:        buildResponseHeader(h, smb.StatusOk, h.SessionID, smb.CommandLogoff),
		StructureSize: 4,
	}
	return c.writeReply(ctx, &res)
}

// handleUnknownCommand provides the default reply for any opcode not handled
// by the current build. Returns STATUS_NOT_SUPPORTED unless OnUnknownCommand
// overrides it.
func (c *Conn) handleUnknownCommand(ctx pduCtx, h *smb.Header, body []byte) error {
	if cb := c.Server.Config.OnUnknownCommand; cb != nil {
		st, err := cb(c, h, body)
		if err != nil {
			return err
		}
		if st != nil {
			return c.writeRawError(ctx, h, st.Code)
		}
	}
	return c.writeRawError(ctx, h, smb.StatusNotSupported)
}
