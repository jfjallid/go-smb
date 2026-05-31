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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// validateNegotiateAlignment enforces the MS-SMB2 §2.2.3 wire-format
// invariants the loose UnmarshalBinary doesn't catch: NegotiateContextOffset
// must be 8-byte aligned from the start of the SMB2 header and lie within
// the buffer; each negotiate context's start position must also be 8-byte
// aligned. Returns an error suitable for STATUS_INVALID_PARAMETER. Lenient
// servers (including go-smb's own decoder before this check) silently accept
// unaligned offsets and parse contexts at whatever position the offset points
// to — Windows servers reject the request, so we should too.
func validateNegotiateAlignment(raw []byte) error {
	// SMB2 header is 64 bytes; NegotiateReq fixed body is 36 bytes
	// (StructureSize..Reserved2). Anything shorter can't carry the fields
	// we need to look at.
	const headerLen = 64
	const fixedBody = 36
	if len(raw) < headerLen+fixedBody {
		return fmt.Errorf("NegotiateReq too short: %d bytes", len(raw))
	}
	body := raw[headerLen:]
	dialectCount := binary.LittleEndian.Uint16(body[2:4])
	ctxOffset := binary.LittleEndian.Uint32(body[28:32])
	ctxCount := binary.LittleEndian.Uint16(body[32:34])

	// Non-3.1.1 paths advertise no contexts; nothing further to check.
	if ctxCount == 0 {
		return nil
	}
	if ctxOffset%8 != 0 {
		return fmt.Errorf("NegotiateContextOffset=%d not 8-byte aligned", ctxOffset)
	}
	// The offset must sit at or past the end of the dialect list — clients
	// that point it into the fixed body or into the dialects are malformed.
	minOffset := uint32(headerLen + fixedBody + 2*uint32(dialectCount))
	if ctxOffset < minOffset {
		return fmt.Errorf("NegotiateContextOffset=%d overlaps dialects (min %d)",
			ctxOffset, minOffset)
	}
	if uint64(ctxOffset) > uint64(len(raw)) {
		return fmt.Errorf("NegotiateContextOffset=%d past end of buffer (%d)",
			ctxOffset, len(raw))
	}
	// Walk the context list and verify each subsequent context is 8-aligned.
	off := int(ctxOffset)
	for i := uint16(0); i < ctxCount; i++ {
		if off%8 != 0 {
			return fmt.Errorf("context %d at offset %d not 8-byte aligned", i, off)
		}
		if off+8 > len(raw) {
			return fmt.Errorf("context %d header truncated at offset %d", i, off)
		}
		dataLen := int(binary.LittleEndian.Uint16(raw[off+2 : off+4]))
		next := off + 8 + dataLen
		if next > len(raw) {
			return fmt.Errorf("context %d data truncated (offset=%d len=%d buf=%d)",
				i, off, dataLen, len(raw))
		}
		// Pad next up to 8-byte boundary, unless this is the last context.
		if i+1 < ctxCount && next%8 != 0 {
			next += 8 - (next % 8)
		}
		off = next
	}
	return nil
}

// handleSMB1Negotiate is the response to the multi-protocol Negotiate Protocol
// packet many clients send first. The canonical reply (mirroring Samba and
// Windows) is an SMB2 NegotiateRes with DialectRevision = DialectSmb2_ALL
// (0x02FF), signaling "I speak SMB2 — please re-negotiate using SMB2". The
// client then sends a real SMB2 NegotiateReq and dispatchSMB2 handles it.
func (c *Conn) handleSMB1Negotiate() error {
	c.Server.Config.logger().Debugf("SMB1 multi-proto Negotiate from %s -> 0x%04x",
		c.RemoteAddr, smb.DialectSmb2_ALL)
	res := smb.NewNegotiateRes()
	res.Header.Command = smb.CommandNegotiate
	res.DialectRevision = smb.DialectSmb2_ALL
	res.SecurityMode = smb.SecurityModeSigningEnabled
	if c.Server.Config.SigningRequired {
		res.SecurityMode |= smb.SecurityModeSigningRequired
	}
	// SMB1->SMB2 upgrade reply: the chosen dialect is 0x02FF ("any SMB2"),
	// so we don't know whether the client will then negotiate 2.0.2 or
	// something later. Keep the conservative 64 KiB defaults here — the
	// real per-dialect picks happen in buildNegotiateRes when the client
	// follows up with a real NegotiateReq.
	res.MaxReadSize = orDefault(c.Server.Config.MaxReadSize, 65536)
	res.MaxWriteSize = orDefault(c.Server.Config.MaxWriteSize, 65536)
	res.MaxTransactSize = orDefault(c.Server.Config.MaxTransactSize, 65536)

	guid := c.Server.resolvedServerGUID()
	res.ServerGuid = make([]byte, 16)
	copy(res.ServerGuid, guid[:])

	now := ntlmssp.ConvertToFileTime(time.Now())
	res.SystemTime = now
	res.ServerStartTime = now

	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}
	// SMB1 multi-proto reply has no inbound SMB2 PDU to mirror, hence
	// zero pduCtx — signing/encryption are unconditionally off here.
	return c.writeReply(pduCtx{}, &res)
}

// handleNegotiate parses the SMB2 NegotiateReq and replies with NegotiateRes.
func (c *Conn) handleNegotiate(ctx pduCtx, raw []byte, h *smb.Header) error {
	logger := c.Server.Config.logger()
	if err := validateNegotiateAlignment(raw); err != nil {
		logger.Errorf("Negotiate from %s rejected: %v", c.RemoteAddr, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	var req smb.NegotiateReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		return formatErr("decode NegotiateReq", err)
	}
	logger.Debugf("NegotiateReq from %s: dialects=%v", c.RemoteAddr, req.Dialects)

	// Capture the client GUID for later phases (preauth integrity hash, etc.).
	if len(req.ClientGuid) == 16 {
		copy(c.ClientGUID[:], req.ClientGuid)
	}
	// Track whether the client capability set advertises encryption. Some
	// configurations (e.g. cfg.RequireEncryption) need this to decide
	// whether to enable encryption on the session at SessionSetup time.
	c.ClientWantsEncrypt = req.Capabilities&smb.GlobalCapEncryption != 0
	// Capture the client's SecurityMode so SessionSetup can compute
	// Session.SigningRequired per MS-SMB2 §3.3.5.5.3 (server-required OR
	// client-required).
	c.ClientSecurityMode = req.SecurityMode

	res, err := c.buildNegotiateRes(&req)
	if err != nil {
		return err
	}

	if cb := c.Server.Config.OnNegotiate; cb != nil {
		if err := cb(c, &req, res); err != nil {
			return err
		}
	}

	// Persist the negotiated dialect on Conn so later phases (SessionSetup,
	// signing/encryption setup) can read it without re-parsing.
	c.Dialect = res.DialectRevision
	c.SigningRequired = res.SecurityMode&smb.SecurityModeSigningRequired != 0
	c.SupportsEncryption = res.Capabilities&smb.GlobalCapEncryption != 0
	// Capture the exact values the client will see in NegotiateRes so the
	// FSCTL_VALIDATE_NEGOTIATE_INFO reply can echo them back verbatim. Done
	// after OnNegotiate so any hook mutations are reflected.
	c.NegotiatedCapabilities = res.Capabilities
	c.NegotiatedSecurityMode = res.SecurityMode

	// Echo MessageID/SessionID/TreeID from the request header, which
	// buildNegotiateRes does not yet know about.
	res.Header.MessageID = h.MessageID
	res.Header.SessionID = h.SessionID
	res.Header.TreeID = h.TreeID
	res.Header.CreditCharge = h.CreditCharge
	if res.Header.Credits == 0 {
		res.Header.Credits = 1
	}

	// SMB 3.1.1 preauth integrity hash: fold both the inbound NegotiateReq
	// and the outbound NegotiateRes into the connection-level chain.
	c.updatePreauthChainConn(raw)
	return c.writeReplyPreauth(ctx, res, &c.preauthChain)
}

// writeReplyPreauth marshals a response, applies hooks, then folds the
// outbound bytes into the supplied preauth chain (when 3.1.1 / SHA-512) and
// finally writes the packet. Used by Negotiate / SessionSetup handlers
// during preauth message exchange. These PDUs are never part of a compound
// chain in practice (clients send Negotiate/SessionSetup standalone), so we
// bypass the chain accumulator and write immediately — folding the same
// bytes into the preauth hash that go onto the wire.
func (c *Conn) writeReplyPreauth(ctx pduCtx, res interface{}, chain *[64]byte) error {
	buf, err := encodeForWire(res)
	if err != nil {
		return err
	}
	if cb := c.Server.Config.OnRawResponse; cb != nil {
		buf, err = cb(c, buf)
		if err != nil {
			return err
		}
	}
	if chain != nil && c.Dialect == smb.DialectSmb_3_1_1 && c.PreauthHashID == smb.SHA512 {
		updatePreauthChain(chain, buf)
	}
	// Detach the ctx so sendPacket writes directly rather than queuing on
	// the chain — preauth bytes must hit the wire before the next inbound
	// leg arrives, and pre-auth PDUs are never compounded.
	detached := ctx
	detached.chain = nil
	return c.sendPacket(detached, buf)
}

// encodeForWire is a tiny indirection so handlers can share the marshal call
// even when they need to inspect the bytes (preauth hash, signing).
func encodeForWire(res interface{}) ([]byte, error) {
	return encoder.Marshal(res)
}

// buildNegotiateRes picks the highest mutually-supported dialect and assembles
// a NegotiateRes. It does NOT populate MessageID/SessionID — handleNegotiate
// fills those from the inbound header.
func (c *Conn) buildNegotiateRes(req *smb.NegotiateReq) (*smb.NegotiateRes, error) {
	cfg := c.Server.Config
	logger := cfg.logger()

	// Pick the highest mutually-supported dialect.
	allowed := cfg.dialectsAllowed()
	chosen := uint16(0)
search:
	for _, want := range allowed {
		for _, got := range req.Dialects {
			if want == got || got == smb.DialectSmb2_ALL {
				chosen = want
				break search
			}
		}
	}
	if chosen == 0 {
		logger.Errorf("no mutually supported dialect; client offered %v, we allow %v", req.Dialects, allowed)
		return nil, fmt.Errorf("no mutually supported dialect")
	}

	res := smb.NewNegotiateRes()
	res.Header.Command = smb.CommandNegotiate
	res.DialectRevision = chosen

	res.SecurityMode = smb.SecurityModeSigningEnabled
	if cfg.SigningRequired {
		res.SecurityMode |= smb.SecurityModeSigningRequired
	}

	// Buffer-size advertisement scales with dialect. SMB 2.0.2 is capped at
	// 64 KiB; SMB 2.1 and later support the LargeMTU capability which lets
	// the server raise the ceiling. Default to 1 MiB on LargeMTU-capable
	// dialects (Windows-compatible) and 64 KiB otherwise. Callers can
	// override via cfg.MaxReadSize / cfg.MaxWriteSize / cfg.MaxTransactSize;
	// any override is clamped to the absolute server ceiling so a stray
	// value cannot make the per-PDU allocator a DoS vector.
	defaultBuf := uint32(65536)
	if chosen >= smb.DialectSmb_2_1 {
		defaultBuf = 1 << 20
	}
	res.MaxReadSize = capBufSize(orDefault(cfg.MaxReadSize, defaultBuf))
	res.MaxWriteSize = capBufSize(orDefault(cfg.MaxWriteSize, defaultBuf))
	res.MaxTransactSize = capBufSize(orDefault(cfg.MaxTransactSize, defaultBuf))

	res.Capabilities = 0
	if chosen >= smb.DialectSmb_2_1 {
		res.Capabilities |= smb.GlobalCapLargeMTU
	}
	if cfg.encryptionSupported() && chosen >= smb.DialectSmb_3_0 {
		res.Capabilities |= smb.GlobalCapEncryption
		// SMB 3.0 / 3.0.2 advertise encryption purely via the
		// capability bit; AES-128-CCM is the only allowed cipher
		// for those dialects (MS-SMB2 §3.3.5.4). 3.1.1 selects via
		// EncryptionContext below.
		if chosen != smb.DialectSmb_3_1_1 {
			c.CipherID = smb.AES128CCM
		}
	}

	guid := c.Server.resolvedServerGUID()
	res.ServerGuid = make([]byte, 16)
	copy(res.ServerGuid, guid[:])

	now := ntlmssp.ConvertToFileTime(time.Now())
	res.SystemTime = now
	res.ServerStartTime = now

	// SecurityBlob: NegTokenInit advertising NTLMSSP (and Kerberos in v1.1+).
	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}

	if chosen == smb.DialectSmb_3_1_1 {
		if err := c.populateNegotiateContexts(req, &res); err != nil {
			return nil, err
		}
		// MS-SMB2 §2.2.4: NegotiateContextOffset MUST point to an 8-byte
		// aligned position from the start of the SMB2 header. Pre-context
		// bytes total 64 (header) + 64 (fixed body) + len(SecurityBlob).
		// Insert padding so ContextList lands on an 8-byte boundary.
		secLen, err := marshalLen(res.SecurityBlob)
		if err != nil {
			return nil, err
		}
		preCtx := 64 + 64 + secLen
		pad := (8 - (preCtx % 8)) % 8
		if pad > 0 {
			res.Padding = make([]byte, pad)
		}
	} else if chosen == smb.DialectSmb_2_0_2 {
		res.ContextList = nil
	}

	return &res, nil
}

// marshalLen returns the marshaled byte length of v without retaining the
// buffer. Used for offset/alignment calculations against variable-length
// fields like SecurityBlob.
func marshalLen(v interface{}) (int, error) {
	buf, err := encoder.Marshal(v)
	if err != nil {
		return 0, err
	}
	return len(buf), nil
}

// populateNegotiateContexts sets up the NegContext list for a 3.1.1 reply by
// echoing the chosen preauth integrity hash, picking a cipher from the
// client's offered list, and selecting a signing algorithm.
func (c *Conn) populateNegotiateContexts(req *smb.NegotiateReq, res *smb.NegotiateRes) error {
	cfg := c.Server.Config
	logger := cfg.logger()

	var (
		chosenCipher    uint16
		chosenSign      uint16 = smb.AES_CMAC
		chosenHash      uint16
		clientSalt      []byte
		clientNetName   []byte // raw bytes from NetNameNegotiateContextId
		compressionSeen bool
	)

	for _, ctx := range req.ContextList {
		switch ctx.ContextType {
		case smb.PreauthIntegrityCapabilities:
			var pic smb.PreauthIntegrityContext
			if err := encoder.Unmarshal(ctx.Data, &pic); err != nil {
				// MS-SMB2 §3.3.5.4: a malformed negotiate context fails
				// negotiation rather than silently degrading.
				logger.Errorf("decode PreauthIntegrityContext: %v", err)
				return fmt.Errorf("decode PreauthIntegrityContext: %w", err)
			}
			for _, h := range pic.HashAlgorithms {
				if h == smb.SHA512 {
					chosenHash = smb.SHA512
					break
				}
			}
			clientSalt = pic.Salt

		case smb.EncryptionCapabilities:
			var ec smb.EncryptionContext
			if err := encoder.Unmarshal(ctx.Data, &ec); err != nil {
				logger.Errorf("decode EncryptionContext: %v", err)
				return fmt.Errorf("decode EncryptionContext: %w", err)
			}
			if cfg.encryptionSupported() {
				// Prefer the client's first listed cipher we recognize.
				for _, ci := range ec.Ciphers {
					switch ci {
					case smb.AES128GCM, smb.AES256GCM, smb.AES128CCM, smb.AES256CCM:
						chosenCipher = ci
					}
					if chosenCipher != 0 {
						break
					}
				}
			}

		case smb.SigningCapabilities:
			var sc smb.SigningContext
			if err := encoder.Unmarshal(ctx.Data, &sc); err != nil {
				logger.Errorf("decode SigningContext: %v", err)
				return fmt.Errorf("decode SigningContext: %w", err)
			}
			// Honor the client's preference order: pick the first algorithm
			// they listed that we know how to do. The set of algorithms we
			// handle on 3.1.1 is AES_CMAC (default), HMAC_SHA256 (downlevel
			// option), and AES_GMAC (Windows 11 / Server 2022 preferred).
			for _, alg := range sc.SigningAlgorithms {
				if alg == smb.AES_CMAC || alg == smb.HMAC_SHA256 || alg == smb.AES_GMAC {
					chosenSign = alg
					break
				}
			}

		case smb.NetNameNegotiateContextId:
			// MS-SMB2 §2.2.3.1.4 / §3.3.5.4: the client sends its idea of the
			// server name as UTF-16. The server SHOULD echo it back so the
			// client can detect that it really reached the intended host
			// (used by macOS clients for keyring matching). Keep the raw
			// bytes verbatim — we don't validate them.
			clientNetName = append([]byte(nil), ctx.Data...)

		case smb.CompressionCapabilities:
			// MS-SMB2 §2.2.3.1.3: client offers compression algorithms. We
			// don't implement compression but the spec lets us reply with
			// an empty algorithm list so the client knows we considered it.
			compressionSeen = true
		}
	}

	if chosenHash == 0 {
		// SMB 3.1.1 mandates preauth integrity. Fail negotiation.
		return fmt.Errorf("client did not offer SHA-512 preauth integrity hash")
	}
	c.PreauthHashID = chosenHash
	c.CipherID = chosenCipher
	c.SigningID = chosenSign
	// Preauth anti-downgrade (MS-SMB2 §3.1.5.2 + §3.3.5.4): the chain is
	// fed through updatePreauthChainConn (Negotiate req+res) and
	// updatePreauthChainSession (each SessionSetup leg) and consumed by
	// deriveKeys / deriveEncryptionKeys to compute the per-session signing
	// and encryption keys (sign.go, encrypt.go). Anti-downgrade is enforced
	// *implicitly* through those derivations: a peer that altered any
	// Negotiate / SessionSetup context on the wire would compute a
	// different chain and therefore mismatching keys, so the first post-auth
	// PDU fails signature verification (dispatchSMB2Inner -> writeRawError
	// STATUS_ACCESS_DENIED, disconnect). The client salt is captured for
	// completeness even though we do not rely on its content beyond
	// echoing a fresh server salt back.
	_ = clientSalt

	pic := smb.PreauthIntegrityContext{
		HashAlgorithmCount: 1,
		HashAlgorithms:     []uint16{chosenHash},
		SaltLength:         32,
		Salt:               make([]byte, 32),
	}
	if _, err := rand.Read(pic.Salt); err != nil {
		return formatErr("rand for preauth salt", err)
	}
	picBuf, err := encoder.Marshal(pic)
	if err != nil {
		return formatErr("marshal PreauthIntegrityContext", err)
	}
	res.ContextList = append(res.ContextList, smb.NegContext{
		ContextType: smb.PreauthIntegrityCapabilities,
		Data:        picBuf,
		DataLength:  uint16(len(picBuf)),
		Padd:        make([]byte, padTo8(len(picBuf))),
	})

	if chosenCipher != 0 {
		ec := smb.EncryptionContext{
			CipherCount: 1,
			Ciphers:     []uint16{chosenCipher},
		}
		ecBuf, err := encoder.Marshal(ec)
		if err != nil {
			return formatErr("marshal EncryptionContext", err)
		}
		res.ContextList = append(res.ContextList, smb.NegContext{
			ContextType: smb.EncryptionCapabilities,
			Data:        ecBuf,
			DataLength:  uint16(len(ecBuf)),
			Padd:        make([]byte, padTo8(len(ecBuf))),
		})
	}

	sc := smb.SigningContext{
		SigningAlgorithmCount: 1,
		SigningAlgorithms:     []uint16{chosenSign},
	}
	scBuf, err := encoder.Marshal(sc)
	if err != nil {
		return formatErr("marshal SigningContext", err)
	}
	res.ContextList = append(res.ContextList, smb.NegContext{
		ContextType: smb.SigningCapabilities,
		Data:        scBuf,
		DataLength:  uint16(len(scBuf)),
		Padd:        make([]byte, padTo8(len(scBuf))),
	})

	// CompressionCapabilities: reply with an empty algorithm list when the
	// client offered one. ServerCompressionContext layout (MS-SMB2 §2.2.3.1.3):
	// CompressionAlgorithmCount(2) + Padding(2) + Flags(4) + Algorithms[].
	if compressionSeen {
		comp := make([]byte, 8)
		// CompressionAlgorithmCount=0, Padding=0, Flags=0 → all zero.
		res.ContextList = append(res.ContextList, smb.NegContext{
			ContextType: smb.CompressionCapabilities,
			Data:        comp,
			DataLength:  uint16(len(comp)),
			Padd:        make([]byte, padTo8(len(comp))),
		})
	}

	// NetNameNegotiateContextId: echo client-supplied bytes verbatim. Wire
	// format is just the UTF-16 server name, no length prefix.
	if len(clientNetName) > 0 {
		res.ContextList = append(res.ContextList, smb.NegContext{
			ContextType: smb.NetNameNegotiateContextId,
			Data:        clientNetName,
			DataLength:  uint16(len(clientNetName)),
			// Last context overall — strip trailing padding.
		})
	}

	// The last context must not have trailing padding; clear it so the
	// encoder doesn't emit zeros past the final DataLength byte.
	if n := len(res.ContextList); n > 0 {
		res.ContextList[n-1].Padd = nil
	}

	res.NegotiateContextCount = uint16(len(res.ContextList))
	return nil
}

func orDefault(v, def uint32) uint32 {
	if v == 0 {
		return def
	}
	return v
}

// maxAdvertisedBufSize bounds the MaxRead/Write/Transact values regardless
// of caller configuration. Anything bigger and a misbehaving (or hostile)
// client could allocate big buffers per-PDU. 8 MiB is the conventional
// ceiling Windows servers use.
const maxAdvertisedBufSize uint32 = 8 * 1024 * 1024

func capBufSize(v uint32) uint32 {
	if v > maxAdvertisedBufSize {
		return maxAdvertisedBufSize
	}
	return v
}

func padTo8(n int) int {
	r := n % 8
	if r == 0 {
		return 0
	}
	return 8 - r
}
