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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

// SMBPassthrough handles a SOCKS-fronted SMB conversation by raw-forwarding
// PDUs over the pooled upstream *smb.Connection. The local-side Negotiate and
// SessionSetup are answered with synthetic responses (we never derive keys on
// the SOCKS side, so signing/encryption stay off). Subsequent PDUs are
// forwarded to the upstream with TreeID/SessionID/FileID translation.
//
// If Resolve is set, the pooled session is selected on SessionSetup leg 2
// using the username/domain parsed out of the inbound NTLMSSP AUTHENTICATE.
// Otherwise the pre-set Upstream field is used unconditionally.
type SMBPassthrough struct {
	Local    net.Conn
	Target   string // upstream "host:port" the SOCKS client asked for (used by Resolve)
	Upstream *pooledSession
	Resolve  func(target, domain, user string) *pooledSession
	Logger   server.Logger

	localSessionID    uint64
	upstreamSessionID uint64

	tableMu sync.Mutex
	trees   map[uint32]uint32   // local TID -> upstream TID
	files   map[[16]byte][]byte // local FileID -> upstream FileID (16 bytes)

	nextTID  uint32
	nextFile uint64 // counter for synthesizing local FileIDs
}

// Run drives the local-side handshake then forwards subsequent PDUs to
// Upstream until the local connection closes or the upstream errors.
func (p *SMBPassthrough) Run(ctx context.Context) error {
	if p.Resolve == nil && (p.Upstream == nil || p.Upstream.Conn == nil) {
		return fmt.Errorf("nil upstream and no Resolve")
	}
	if p.Logger == nil {
		p.Logger = log
	}
	// Local session ID is invented for the SOCKS client; it has no relation to
	// the upstream's session ID (which we only learn after Resolve). A random
	// value with a recognizable high-bit marker keeps logs readable.
	var sid [8]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return fmt.Errorf("rand for local session ID: %w", err)
	}
	p.localSessionID = binary.LittleEndian.Uint64(sid[:])&0x00FFFFFFFFFFFFFF | 0xC0FFEE0000000000
	if p.Upstream != nil && p.Upstream.Conn != nil {
		p.upstreamSessionID = p.Upstream.Conn.UpstreamSessionID()
	}
	p.trees = map[uint32]uint32{}
	p.files = map[[16]byte][]byte{}
	p.nextTID = 1

	// Stage 1: Negotiate.
	pkt, err := readNetBIOSPacket(p.Local)
	if err != nil {
		return fmt.Errorf("read Negotiate: %w", err)
	}
	if !isSMB2(pkt) {
		// Some clients open with SMB1 multi-protocol Negotiate — answer with
		// an SMB2 NegotiateRes carrying DialectRevision = SMB2_ALL so the
		// client retries in SMB2.
		if len(pkt) >= 4 && string(pkt[:4]) == "\xffSMB" {
			if err := p.writeMultiProtoNeg(); err != nil {
				return fmt.Errorf("write multi-proto neg: %w", err)
			}
			pkt, err = readNetBIOSPacket(p.Local)
			if err != nil {
				return fmt.Errorf("read second Negotiate: %w", err)
			}
		} else {
			return fmt.Errorf("expected SMB2 Negotiate, got % x", pkt)
		}
	}
	// The local client is operator-coerced but its framing is still untrusted;
	// a short packet must not reach the SMB2 header/body parsers in reply*.
	if len(pkt) < 64 {
		return fmt.Errorf("short Negotiate PDU (%d bytes)", len(pkt))
	}
	if cmdOf(pkt) != smb.CommandNegotiate {
		return fmt.Errorf("expected Negotiate, got command 0x%04x", cmdOf(pkt))
	}
	if err := p.replyNegotiate(pkt); err != nil {
		return fmt.Errorf("reply Negotiate: %w", err)
	}

	// Stage 2: SessionSetup leg 1 (NTLMSSP NEGOTIATE -> CHALLENGE).
	pkt, err = readNetBIOSPacket(p.Local)
	if err != nil {
		return fmt.Errorf("read SessionSetup1: %w", err)
	}
	if len(pkt) < 64 {
		return fmt.Errorf("short SessionSetup1 PDU (%d bytes)", len(pkt))
	}
	if cmdOf(pkt) != smb.CommandSessionSetup {
		return fmt.Errorf("expected SessionSetup1, got command 0x%04x", cmdOf(pkt))
	}
	if err := p.replySessionSetup1(pkt); err != nil {
		return fmt.Errorf("reply SessionSetup1: %w", err)
	}

	// Stage 3: SessionSetup leg 2.
	pkt, err = readNetBIOSPacket(p.Local)
	if err != nil {
		return fmt.Errorf("read SessionSetup2: %w", err)
	}
	if len(pkt) < 64 {
		return fmt.Errorf("short SessionSetup2 PDU (%d bytes)", len(pkt))
	}
	if cmdOf(pkt) != smb.CommandSessionSetup {
		return fmt.Errorf("expected SessionSetup2, got command 0x%04x", cmdOf(pkt))
	}
	if err := p.replySessionSetup2(pkt); err != nil {
		return fmt.Errorf("reply SessionSetup2: %w", err)
	}
	// Resolve may have refused to bind an upstream (no match); replySession-
	// Setup2 already wrote a LOGON_FAILURE for the client. Stop without
	// touching the upstream.
	if p.Upstream == nil || p.Upstream.Conn == nil {
		return nil
	}

	// Stage 4: forwarding loop.
	for {
		pkt, err = readNetBIOSPacket(p.Local)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read forwarded PDU: %w", err)
		}
		if !isSMB2(pkt) || len(pkt) < 64 {
			return fmt.Errorf("forwarding loop: not an SMB2 PDU")
		}
		if err := p.forward(pkt); err != nil {
			return err
		}
	}
}

// forward translates and forwards one PDU. Locally-handled commands (Echo,
// Logoff) reply directly without touching the upstream.
func (p *SMBPassthrough) forward(pkt []byte) error {
	cmd := cmdOf(pkt)
	switch cmd {
	case smb.CommandEcho:
		return p.replyEcho(pkt)
	case smb.CommandLogoff:
		return p.replyLogoff(pkt)
	case smb.CommandCancel:
		// Cancel has no response; quietly drop.
		return nil
	}

	// Translate per-command body fields outbound (local -> upstream). For
	// Close we stash the local FileID so we can drop the mapping after the
	// upstream confirms success.
	var closeLocalFID [16]byte
	if cmd == smb.CommandClose {
		off, _ := requestFileIDOffset(cmd)
		if len(pkt) >= off+16 {
			copy(closeLocalFID[:], pkt[off:off+16])
		}
	}
	if err := p.translateBodyOutbound(cmd, pkt); err != nil {
		return fmt.Errorf("translate outbound: %w", err)
	}

	// Translate header fields (MessageID + TreeID + SessionID). The local
	// MessageID lives at offset 24 (8 bytes LE); SendRawPDU rewrites it to
	// the upstream connection's next outbound id, and the upstream's reply
	// carries that upstream id — we must stamp the local id back into the
	// response so the SOCKS client recognizes its own outstanding request.
	localMID := binary.LittleEndian.Uint64(pkt[24:32])
	localTID := binary.LittleEndian.Uint32(pkt[36:40])
	if cmd != smb.CommandTreeConnect {
		upstreamTID, ok := p.lookupTree(localTID)
		if !ok && localTID != 0 {
			return p.replyError(pkt, smb.StatusInvalidParameter)
		}
		binary.LittleEndian.PutUint32(pkt[36:40], upstreamTID)
	}
	binary.LittleEndian.PutUint64(pkt[40:48], p.upstreamSessionID)
	// Zero the signature region; SendRawPDU will (no-op) re-sign per the
	// upstream connection's negotiated state. The relay forces signing off.
	for i := 48; i < 64; i++ {
		pkt[i] = 0
	}

	p.Upstream.mu.Lock()
	p.Upstream.Touch()
	resp, err := p.Upstream.Conn.SendRawPDU(pkt)
	p.Upstream.mu.Unlock()
	if err != nil {
		// Upstream connection is broken — flag the pooled session dead so
		// subsequent SOCKS connections route to a sibling (if any) and drop
		// this SOCKS connection. The prune sweep will close + evict the dead
		// entry.
		p.Upstream.MarkDead()
		return fmt.Errorf("upstream SendRawPDU: %w", err)
	}
	if len(resp) < 64 || !isSMB2(resp) {
		p.Upstream.MarkDead()
		return fmt.Errorf("upstream returned malformed PDU (%d bytes)", len(resp))
	}

	// Translate header back (upstream -> local): MessageID + SessionID.
	binary.LittleEndian.PutUint64(resp[24:32], localMID)
	binary.LittleEndian.PutUint64(resp[40:48], p.localSessionID)
	respCmd := cmdOf(resp)
	respStatus := binary.LittleEndian.Uint32(resp[8:12])
	if cmd == smb.CommandTreeConnect && respStatus == smb.StatusOk {
		upstreamTID := binary.LittleEndian.Uint32(resp[36:40])
		newLocalTID := p.allocTree(upstreamTID)
		binary.LittleEndian.PutUint32(resp[36:40], newLocalTID)
	} else if cmd == smb.CommandTreeDisconnect && respStatus == smb.StatusOk {
		p.dropTree(localTID)
		binary.LittleEndian.PutUint32(resp[36:40], localTID)
	} else {
		// Echo back the local TID so the client sees its own TreeID.
		binary.LittleEndian.PutUint32(resp[36:40], localTID)
	}

	// Translate response body (FileID swaps for Create/Close/IoCtl etc.).
	if err := p.translateBodyInbound(respCmd, cmd, resp, respStatus); err != nil {
		return fmt.Errorf("translate inbound: %w", err)
	}
	if cmd == smb.CommandClose && respStatus == smb.StatusOk {
		p.dropFile(closeLocalFID)
	}

	// Zero the signature region in the response (the local client doesn't
	// verify — we negotiated signing off).
	for i := 48; i < 64; i++ {
		resp[i] = 0
	}

	if err := writeNetBIOSPacket(p.Local, resp); err != nil {
		return fmt.Errorf("write forwarded reply: %w", err)
	}
	return nil
}

// translateBodyOutbound rewrites local FileIDs in the PDU body to upstream
// FileIDs in place. No-op for commands that don't carry a FileID.
func (p *SMBPassthrough) translateBodyOutbound(cmd uint16, pkt []byte) error {
	off, ok := requestFileIDOffset(cmd)
	if !ok {
		return nil
	}
	if len(pkt) < off+16 {
		return fmt.Errorf("PDU too short for FileID at +%d (cmd=0x%04x)", off, cmd)
	}
	var local [16]byte
	copy(local[:], pkt[off:off+16])
	upstream, ok := p.lookupFile(local)
	if !ok {
		return fmt.Errorf("forwarding cmd 0x%04x with unknown local FileID %s", cmd, hex.EncodeToString(local[:]))
	}
	copy(pkt[off:off+16], upstream)
	return nil
}

// translateBodyInbound rewrites upstream FileIDs in the response body back to
// local FileIDs. For Create responses we allocate a new local FileID.
func (p *SMBPassthrough) translateBodyInbound(respCmd uint16, reqCmd uint16, resp []byte, status uint32) error {
	switch respCmd {
	case smb.CommandCreate:
		if status != smb.StatusOk {
			return nil
		}
		const off = 64 + 64 // 64-byte header + 64 bytes of CreateRes preamble = FileID at +128
		if len(resp) < off+16 {
			return fmt.Errorf("CreateRes too short")
		}
		var upstreamFID [16]byte
		copy(upstreamFID[:], resp[off:off+16])
		localFID := p.allocFile(upstreamFID)
		copy(resp[off:off+16], localFID[:])
	case smb.CommandClose:
		// CloseRes carries no FileID; mapping cleanup happens in forward().
	case smb.CommandIOCtl:
		// IoCtlRes has FileID at offset 64+8 = 72. Rewrite back to local.
		const off = 64 + 8
		if len(resp) < off+16 {
			return nil
		}
		var upstreamFID [16]byte
		copy(upstreamFID[:], resp[off:off+16])
		// Find the local FileID that maps to this upstream FileID (linear
		// scan; the mapping tables are tiny).
		if local, ok := p.findLocalByUpstream(upstreamFID); ok {
			copy(resp[off:off+16], local[:])
		}
	}
	return nil
}

// dropFile removes the local->upstream FileID mapping for the supplied local
// FileID. Idempotent.
func (p *SMBPassthrough) dropFile(local [16]byte) {
	p.tableMu.Lock()
	delete(p.files, local)
	p.tableMu.Unlock()
}

// findLocalByUpstream returns the local FileID that maps to the given upstream
// FileID, or zero/false if not found.
func (p *SMBPassthrough) findLocalByUpstream(upstream [16]byte) ([16]byte, bool) {
	p.tableMu.Lock()
	defer p.tableMu.Unlock()
	for local, up := range p.files {
		if len(up) == 16 && [16]byte(*(*[16]byte)(up)) == upstream {
			return local, true
		}
	}
	return [16]byte{}, false
}

// requestFileIDOffset returns the byte offset (from the start of the PDU)
// where the FileID field lives in the body of the named request, or 0+false
// if the request type doesn't carry one.
func requestFileIDOffset(cmd uint16) (int, bool) {
	const hdr = 64
	switch cmd {
	case smb.CommandClose:
		return hdr + 8, true
	case smb.CommandRead:
		return hdr + 16, true
	case smb.CommandWrite:
		return hdr + 16, true
	case smb.CommandQueryDirectory:
		return hdr + 8, true
	case smb.CommandQueryInfo:
		return hdr + 24, true
	case smb.CommandSetInfo:
		return hdr + 16, true
	case smb.CommandIOCtl:
		return hdr + 8, true
	case smb.CommandFlush:
		return hdr + 8, true
	}
	return 0, false
}

// lookupTree looks up a local TID in the translation map.
func (p *SMBPassthrough) lookupTree(localTID uint32) (uint32, bool) {
	p.tableMu.Lock()
	defer p.tableMu.Unlock()
	v, ok := p.trees[localTID]
	return v, ok
}

func (p *SMBPassthrough) allocTree(upstreamTID uint32) uint32 {
	p.tableMu.Lock()
	defer p.tableMu.Unlock()
	id := p.nextTID
	p.nextTID++
	p.trees[id] = upstreamTID
	return id
}

func (p *SMBPassthrough) dropTree(localTID uint32) {
	p.tableMu.Lock()
	defer p.tableMu.Unlock()
	delete(p.trees, localTID)
}

// lookupFile returns the upstream FileID bytes for the given local FileID.
func (p *SMBPassthrough) lookupFile(local [16]byte) ([]byte, bool) {
	p.tableMu.Lock()
	defer p.tableMu.Unlock()
	v, ok := p.files[local]
	return v, ok
}

// allocFile assigns a fresh local FileID and stores the local->upstream
// mapping. Returns the synthesized local FileID.
func (p *SMBPassthrough) allocFile(upstream [16]byte) [16]byte {
	var local [16]byte
	p.tableMu.Lock()
	p.nextFile++
	binary.LittleEndian.PutUint64(local[:8], p.nextFile)
	binary.LittleEndian.PutUint64(local[8:], 0xCAFEBABEDEADBEEF)
	stored := make([]byte, 16)
	copy(stored, upstream[:])
	p.files[local] = stored
	p.tableMu.Unlock()
	return local
}

// replyEcho replies StatusOk to a local Echo without touching the upstream.
func (p *SMBPassthrough) replyEcho(req []byte) error {
	resp := buildResponseHeader(req, smb.CommandEcho, smb.StatusOk, p.localSessionID)
	resp = append(resp, []byte{4, 0, 0, 0}...) // StructureSize=4, Reserved=0
	return writeNetBIOSPacket(p.Local, resp)
}

// replyLogoff replies StatusOk and closes the local connection (passthrough
// returns when readNetBIOSPacket sees EOF). Upstream session is preserved.
func (p *SMBPassthrough) replyLogoff(req []byte) error {
	resp := buildResponseHeader(req, smb.CommandLogoff, smb.StatusOk, p.localSessionID)
	resp = append(resp, []byte{4, 0, 0, 0}...) // StructureSize=4, Reserved=0
	if err := writeNetBIOSPacket(p.Local, resp); err != nil {
		return err
	}
	return io.EOF
}

// replyError sends an SMB2 error response with the given NT status.
func (p *SMBPassthrough) replyError(req []byte, status uint32) error {
	resp := buildResponseHeader(req, cmdOf(req), status, p.localSessionID)
	// SMB2 ERROR Response (MS-SMB2 2.2.2) — minimal.
	body := []byte{
		9, 0, // StructureSize
		0,          // ErrorContextCount
		0,          // Reserved
		0, 0, 0, 0, // ByteCount=0
		0, // ErrorData
	}
	resp = append(resp, body...)
	return writeNetBIOSPacket(p.Local, resp)
}

// replyNegotiate writes a synthetic SMB 2.1 NegotiateRes to the local client.
// SecurityMode = 0 (signing off), no encryption, NTLMSSP only.
func (p *SMBPassthrough) replyNegotiate(req []byte) error {
	res := smb.NewNegotiateRes()
	res.Header = parseHeader(req)
	res.Header.Status = smb.StatusOk
	res.Header.Command = smb.CommandNegotiate
	res.Header.Flags = smb.SMB2_FLAGS_SERVER_TO_REDIR
	res.Header.Credits = 1
	res.DialectRevision = smb.DialectSmb_2_1
	res.SecurityMode = smb.SecurityModeSigningEnabled
	res.Capabilities = smb.GlobalCapLargeMTU
	res.MaxReadSize = 65536
	res.MaxWriteSize = 65536
	res.MaxTransactSize = 65536
	res.SystemTime = ntlmssp.ConvertToFileTime(time.Now())
	res.ServerStartTime = res.SystemTime

	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		return fmt.Errorf("rand for ServerGuid: %w", err)
	}
	res.ServerGuid = guid

	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}

	buf, err := encoder.Marshal(&res)
	if err != nil {
		return err
	}
	return writeNetBIOSPacket(p.Local, buf)
}

// writeMultiProtoNeg writes the SMB2_ALL "please re-negotiate in SMB2" reply
// for the legacy SMB1 multi-protocol Negotiate prologue.
func (p *SMBPassthrough) writeMultiProtoNeg() error {
	res := smb.NewNegotiateRes()
	res.Header = smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		Status:        smb.StatusOk,
		Command:       smb.CommandNegotiate,
		Credits:       1,
		Flags:         smb.SMB2_FLAGS_SERVER_TO_REDIR,
		Signature:     make([]byte, 16),
	}
	res.DialectRevision = smb.DialectSmb2_ALL
	res.SecurityMode = smb.SecurityModeSigningEnabled
	res.MaxReadSize = 65536
	res.MaxWriteSize = 65536
	res.MaxTransactSize = 65536
	res.SystemTime = ntlmssp.ConvertToFileTime(time.Now())
	res.ServerStartTime = res.SystemTime
	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		return fmt.Errorf("rand for ServerGuid: %w", err)
	}
	res.ServerGuid = guid
	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}
	buf, err := encoder.Marshal(&res)
	if err != nil {
		return err
	}
	return writeNetBIOSPacket(p.Local, buf)
}

// replySessionSetup1 builds a synthetic NTLMSSP CHALLENGE wrapped in a
// NegTokenResp and replies with STATUS_MORE_PROCESSING_REQUIRED. The
// challenge is opaque to us — we never validate the corresponding
// AUTHENTICATE.
func (p *SMBPassthrough) replySessionSetup1(req []byte) error {
	var ssreq smb.SessionSetupReq
	if err := encoder.Unmarshal(req, &ssreq); err != nil {
		return err
	}

	srv := &ntlmssp.Server{
		TargetName:    "GO-SMB-RELAY",
		NetBIOSName:   "GO-SMB-RELAY",
		NetBIOSDomain: "WORKGROUP",
	}

	// Peel the inner NTLMSSP NEGOTIATE token out of NegTokenInit.
	var init gss.NegTokenInit
	if err := encoder.Unmarshal(ssreq.SecurityBlob, &init); err != nil {
		return fmt.Errorf("decode NegTokenInit: %w", err)
	}
	if len(init.Data.MechToken) == 0 {
		return fmt.Errorf("SessionSetup1: empty MechToken")
	}
	chall, err := srv.AcceptNegotiate(init.Data.MechToken)
	if err != nil {
		return fmt.Errorf("AcceptNegotiate: %w", err)
	}

	resp := gss.NegTokenResp{
		State:         asn1.Enumerated(gss.GssStateAcceptIncomplete),
		SupportedMech: gss.NtLmSSPMechTypeOid,
		ResponseToken: chall,
	}
	respBytes, err := encoder.Marshal(&resp)
	if err != nil {
		return err
	}

	return p.writeSessionSetupRes(req, smb.StatusMoreProcessingRequired, 0, respBytes, p.localSessionID)
}

// replySessionSetup2 parses the inbound NTLMSSP AUTHENTICATE to learn the
// username/domain the SOCKS client is asserting, optionally calls Resolve to
// bind a pooled upstream session, then replies STATUS_OK (or
// STATUS_LOGON_FAILURE if no matching pool entry exists). SessionFlagIsGuest
// is set so the client knows signing/encryption are off.
func (p *SMBPassthrough) replySessionSetup2(req []byte) error {
	if p.Resolve != nil {
		domain, user, err := extractAuthUser(req)
		if err != nil {
			p.Logger.Debugf("extract AUTHENTICATE user: %v", err)
		}
		p.Upstream = p.Resolve(p.Target, domain, user)
		if p.Upstream == nil || p.Upstream.Conn == nil {
			p.Logger.Debugf("no pooled session for target=%s user=%s\\%s", p.Target, domain, user)
			// Reply LOGON_FAILURE so the SOCKS client sees auth rejection
			// rather than a stalled connection.
			return p.writeSessionSetupRes(req, smb.StatusLogonFailure, 0, nil, p.localSessionID)
		}
		p.upstreamSessionID = p.Upstream.Conn.UpstreamSessionID()
	}
	resp := gss.NegTokenResp{
		State: asn1.Enumerated(gss.GssStateAcceptCompleted),
	}
	respBytes, err := encoder.Marshal(&resp)
	if err != nil {
		return err
	}
	return p.writeSessionSetupRes(req, smb.StatusOk, smb.SessionFlagIsGuest, respBytes, p.localSessionID)
}

// extractAuthUser peels the inbound NTLMSSP AUTHENTICATE out of the
// SessionSetup leg-2 blob and returns the asserted (domain, user) pair as
// UTF-8 strings.
func extractAuthUser(req []byte) (domain, user string, err error) {
	var ssreq smb.SessionSetupReq
	if err = encoder.Unmarshal(req, &ssreq); err != nil {
		return "", "", fmt.Errorf("decode SessionSetupReq: %w", err)
	}
	var resp gss.NegTokenResp
	if err = encoder.Unmarshal(ssreq.SecurityBlob, &resp); err != nil {
		return "", "", fmt.Errorf("decode NegTokenResp: %w", err)
	}
	if len(resp.ResponseToken) == 0 {
		return "", "", fmt.Errorf("empty ResponseToken")
	}
	var auth ntlmssp.Authenticate
	if err = encoder.Unmarshal(resp.ResponseToken, &auth); err != nil {
		return "", "", fmt.Errorf("decode NTLMSSP Authenticate: %w", err)
	}
	user, _ = encoder.FromUnicodeString(auth.UserName)
	domain, _ = encoder.FromUnicodeString(auth.DomainName)
	return domain, user, nil
}

// writeSessionSetupRes assembles and sends a SessionSetupRes.
func (p *SMBPassthrough) writeSessionSetupRes(req []byte, status uint32, flags uint16, blob []byte, sessionID uint64) error {
	res := smb.SessionSetupRes{
		Header:        parseHeader(req),
		StructureSize: 9,
		Flags:         flags,
		SecurityBlob:  blob,
	}
	res.Header.Status = status
	res.Header.Command = smb.CommandSessionSetup
	res.Header.Flags = smb.SMB2_FLAGS_SERVER_TO_REDIR
	res.Header.Credits = 1
	res.Header.SessionID = sessionID
	res.Header.Signature = make([]byte, 16)

	buf, err := encoder.Marshal(&res)
	if err != nil {
		return err
	}
	return writeNetBIOSPacket(p.Local, buf)
}

// readNetBIOSPacket reads one NetBIOS-framed SMB packet from c.
func readNetBIOSPacket(c net.Conn) ([]byte, error) {
	var size uint32
	if err := binary.Read(c, binary.BigEndian, &size); err != nil {
		return nil, err
	}
	if size > 0x00FFFFFF {
		return nil, fmt.Errorf("invalid NetBIOS frame length 0x%x", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writeNetBIOSPacket writes one NetBIOS-framed SMB packet to c.
func writeNetBIOSPacket(c net.Conn, pkt []byte) error {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(pkt)))
	if _, err := c.Write(hdr); err != nil {
		return err
	}
	_, err := c.Write(pkt)
	return err
}

// isSMB2 reports whether buf begins with the SMB2 protocol id.
func isSMB2(buf []byte) bool {
	return len(buf) >= 4 && string(buf[:4]) == smb.ProtocolSmb2
}

// cmdOf returns the SMB2 Command field of the supplied PDU, or 0xffff if the
// buffer is too short.
func cmdOf(buf []byte) uint16 {
	if len(buf) < 14 {
		return 0xffff
	}
	return binary.LittleEndian.Uint16(buf[12:14])
}

// parseHeader unmarshals the SMB2 header out of an inbound PDU. Used by the
// synthetic-reply paths to echo MessageID/CreditCharge/etc. A short or
// malformed PDU yields a zero header; we log because reaching this with bad
// input means an upstream framing bug, not a wire-level adversarial input
// (callers already gate on NetBIOS framing).
func parseHeader(pkt []byte) smb.Header {
	var h smb.Header
	if len(pkt) < 64 {
		log.Errorf("parseHeader called with short pkt (%d bytes)", len(pkt))
		return h
	}
	if err := encoder.Unmarshal(pkt[:64], &h); err != nil {
		log.Errorf("parseHeader decode: %v", err)
	}
	return h
}

// buildResponseHeader emits the 64-byte SMB2 response header bytes for an
// inbound request, returning a fresh slice with the body length to follow.
func buildResponseHeader(req []byte, command uint16, status uint32, sessionID uint64) []byte {
	h := parseHeader(req)
	out := smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  h.CreditCharge,
		Status:        status,
		Command:       command,
		Credits:       1,
		Flags:         smb.SMB2_FLAGS_SERVER_TO_REDIR,
		MessageID:     h.MessageID,
		TreeID:        h.TreeID,
		SessionID:     sessionID,
		Signature:     make([]byte, 16),
	}
	buf, err := encoder.Marshal(out)
	if err != nil {
		// Caller would already be in trouble; return an empty buffer.
		return nil
	}
	return buf
}
