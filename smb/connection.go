// Copyright (c) 2016 Hiroshi Ioka. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   - Redistributions of source code must retain the above copyright
//
// notice, this list of conditions and the following disclaimer.
//   - Redistributions in binary form must reproduce the above
//
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package smb

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
	"golang.org/x/net/proxy"
)

type requestResponse struct {
	msgId        uint64
	asyncId      uint64
	creditCharge uint16
	pkt          []byte // Request packet
	recv         chan []byte
	err          error
}

type outstandingRequests struct {
	m        sync.Mutex
	requests map[uint64]*requestResponse
}

type Connection struct {
	*Session
	outstandingRequests       *outstandingRequests
	conn                      net.Conn
	preauthIntegrityHashId    uint16
	preauthIntegrityHashValue [64]byte
	capabilities              uint32
	cipherId                  uint16
	signingId                 uint16 // For windows 11 and windows server 2022 and later
	offeredDialects           []uint16
	wdone                     chan struct{}
	rdone                     chan struct{}
	write                     chan []byte
	werr                      chan error
	m                         sync.Mutex
	err                       error
	useProxy                  bool
	_useSession               int32
}

func (c *Connection) useSession() bool {
	return atomic.LoadInt32(&c._useSession) != 0
}

func (c *Connection) enableSession() {
	atomic.StoreInt32(&c._useSession, 1)
}

func (c *Connection) disableSession() {
	atomic.StoreInt32(&c._useSession, 0)
}

// MarkAuthenticated promotes a manually-driven SessionSetup to authenticated
// state on this Connection. Intended for relay flows that drive
// SendSessionSetup{1,2}WithToken/Blob themselves: after a successful upstream
// SessionSetup2 the connection holds the negotiated SessionID, but the
// in-process flags (isAuthenticated, authUsername, useSession) are unset
// because the relay drove the exchange directly. Calling this finishes the
// promotion so subsequent TreeConnect / OpenFile calls work normally.
func (c *Connection) MarkAuthenticated(authUsername string) {
	c.authUsername = authUsername
	c.isAuthenticated = true
	c.enableSession()
}

// Update the Initiator used for authentication.
// Calling this function when already logged in will kill the existing session.
func (c *Connection) SetInitiator(initiator gss.Mechanism) error {
	if c.useSession() {
		c.Logoff()
	}
	c.options.Initiator = initiator
	return nil
}

/*Retrieve packets from the write channel and put them to the wire.*/
func (c *Connection) runSender() {
	for {
		select {
		case <-c.wdone:
			return
		case pkt := <-c.write:
			_, err := c.conn.Write(pkt)

			c.werr <- err
		}
	}
}

func readPacket(conn net.Conn) (packet []byte, err error) {
	var size uint32
	if err = binary.Read(conn, binary.BigEndian, &size); err != nil {
		if !errors.Is(err, net.ErrClosed) {
			log.Debugf("Error reading packet: %s\n", err)
		}
		return
	}

	if size > 0x00FFFFFF {
		log.Errorln("Error: Invalid NetBIOS Session message")
		// Don't return the error, instead try to read the next packet
		return
	}

	packet = make([]byte, size)
	l, err := io.ReadFull(conn, packet)
	if err != nil {
		return
	}
	if uint32(l) != size {
		log.Errorln("Error: Message size invalid")
		// Don't return the error, instead try to read the next packet
		return
	}
	return
}

/*
Read packets from the wire. If the message id matches that of the
outstandingRequests map, clear the packet from the map and forward the
packet down the recv channel.
*/
func (c *Connection) runReceiver() {
	var err error
	var encrypted bool
	defer func() {
		// A malformed packet from a malicious or buggy server could drive a
		// parser into a panic (e.g. an out-of-range slice). Recover here so a
		// single bad packet cannot crash the whole client process, and tear
		// the connection down cleanly so callers blocked on a response are
		// released rather than hanging forever.
		if r := recover(); r != nil {
			log.Errorf("runReceiver: recovered from panic: %v\n", r)
			perr := fmt.Errorf("runReceiver panic: %v", r)
			c.m.Lock()
			c.outstandingRequests.shutdown(perr)
			c.err = perr
			c.m.Unlock()
			close(c.wdone)
		}
	}()
	for {
		data, err := readPacket(c.conn)
		if err != nil {
			// Error is handled at the end of the method.
			break
		}
		// A frame must carry at least the 4-byte protocol id; anything
		// shorter (including an empty keep-alive) cannot be a valid SMB PDU.
		if len(data) < 4 {
			continue
		}

		hasSession := c.useSession()

		protID := data[0:4]
		switch string(protID) {
		default:
			log.Errorln("Error: Protocol not implemented")
			continue // No need to crash because of invalid packet
		case ProtocolSmb:
		case ProtocolSmb2:
		case ProtocolTransformHdr:
		}

		var h Header

		if hasSession {
			switch string(protID) {
			case ProtocolTransformHdr:
				if len(data) < 52 {
					log.Errorln("Skip: Packet too short to contain a transform header")
					continue
				}
				tHdr := NewTransformHeader()
				if err = encoder.Unmarshal(data[:52], &tHdr); err != nil {
					log.Errorln("Skip: Failed to decode transform header of packet")
					continue
				}
				// Check encrypted flag
				if tHdr.Flags != 0x0001 {
					log.Errorln("Skip: Failed to parse transform header of packet. Encrypted flag is not set")
					continue
				}
				// Check sessionID
				if tHdr.SessionId != c.sessionID {
					log.Errorf("Skip: Unknown session id %d expected %d\n", h.SessionID, c.sessionID)
					continue
				}
				// Attempt decryption
				data, err = c.decrypt(data)
				if err != nil {
					log.Errorf("Skip: Failed to decrypt packet with error: %s\n", err)
					continue
				}
				encrypted = true

				fallthrough
			case ProtocolSmb2:
				if len(data) < 64 {
					log.Errorln("Skip: Packet too short to contain an SMB2 header")
					continue
				}
				if err = encoder.Unmarshal(data[:64], &h); err != nil {
					log.Errorln("Skip: Failed to decode header of packet")
					continue
				}
				// Check structure size
				if h.StructureSize != 64 {
					log.Errorln("Skip: Invalid structure size of packet")
					continue
				}
				// Check sessionID
				if h.SessionID != c.sessionID {
					log.Errorf("Skip: Unknown session id %d expected %d\n", h.SessionID, c.sessionID)
					continue
				}
			}

			/*
			   Encrypted PDUs carry their own AEAD integrity and never set
			   SMB2_FLAGS_SIGNED, so the signature check only applies to
			   plaintext PDUs.
			   If dialect is 3.1.1, check the signature of every non-encrypted PDU.
			   If dialect is NOT 3.1.1, check signing only if required.
			*/
			if !encrypted && (((c.dialect == DialectSmb_3_1_1) && (c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0)) || ((c.dialect != DialectSmb_3_1_1) && c.Session.isSigningRequired.Load())) {
				// When server responds with StatusPending, the packet signature is the same as on the
				// last packet and the signing flag is not set
				if h.Status != StatusPending {
					if (h.Flags & SMB2_FLAGS_SIGNED) != SMB2_FLAGS_SIGNED {
						err = fmt.Errorf("signing is required but PDU is not signed; closing connection")
						log.Errorln(err)
						break
					} else {
						if !c.verify(data) {
							err = fmt.Errorf("signing is required and invalid signature found; closing connection")
							log.Errorln(err)
							break
						}
					}
				}
			}
		} else {
			// First check if this is SMBv1 instead of SMB2
			if string(data[0:4]) == ProtocolSmb {
				// If Protocol is SMB1 which is not implemented, skip processing the packet and return the data.
				// We assume that this is the first packet with MessageID 0, part of the Negotiate Protocol flow.
				// So we don't care about unmarshalling the packet into a SMBv1 header and only pop MessageID 0
				// from outstandingRequests
			} else {
				if len(data) < 64 {
					log.Errorln("Skip: Packet too short to contain an SMB2 header")
					continue
				}
				if err = encoder.Unmarshal(data[:64], &h); err != nil {
					log.Errorln("Skip: Failed to decode header of packet")
					continue
				}
				// Check structure size
				if h.StructureSize != 64 {
					log.Errorln("Skip: Invalid structure size of packet")
					continue
				}
			}
		}

		// MS-SMB2 §3.2.5.19/20: an unsolicited server packet (oplock or lease
		// break notification) carries the reserved MessageId 0xFFFFFFFFFFFFFFFF
		// and matches no outstanding request. Route it to the break handler
		// instead of dropping it as "not found".
		if h.MessageID == unsolicitedMessageID {
			c.handleServerBreak(data)
			continue
		}

		rr, ok := c.outstandingRequests.pop(h.MessageID)
		if !ok {
			log.Errorf("Message Id (%d) not found in outstanding packets!\n", h.MessageID)
			continue
		}
		// MS-SMB2 §3.2.5.1.4: every response — including STATUS_PENDING interim
		// responses — grants credits via its Credits field. Account them
		// centrally so blocked senders can proceed.
		if c.Session != nil && c.Session.creditMgr != nil {
			c.Session.creditMgr.grant(h.Credits)
		}
		if h.Status == StatusPending {
			// There are two types of SMB Headers depending on if Async flag is set.
			// non-async header uses 4 bytes Reserved and 4 bytes Tree ID in the same
			// position as the Async header uses 8 bytes AsyncId.
			// Parse async id from Reserved and TreeID
			asyncIdBytes := make([]byte, 8)
			binary.LittleEndian.PutUint32(asyncIdBytes, h.Reserved)
			binary.LittleEndian.PutUint32(asyncIdBytes[4:], h.TreeID)
			rr.asyncId = binary.LittleEndian.Uint64(asyncIdBytes)
			c.outstandingRequests.set(h.MessageID, rr)
		} else {
			rr.recv <- data
		}
	}
	// Clean exit
	select {
	case <-c.rdone:
		err = nil
	default:
		log.Debugln(err)
	}

	// Wake any sender blocked waiting for credits BEFORE taking c.m. A sender
	// parked in reserve() holds c.m for the duration of makeRequestResponse, so
	// acquiring c.m here first would deadlock against it — and the very call
	// that would release it (shutdown) sits past that lock. The credit manager
	// has its own lock, so this is safe to do outside c.m.
	if c.Session != nil && c.Session.creditMgr != nil {
		c.Session.creditMgr.shutdown()
	}

	c.m.Lock()
	defer c.m.Unlock()

	c.outstandingRequests.shutdown(err)

	c.err = err

	close(c.wdone)
}

func newOutstandingRequests() *outstandingRequests {
	return &outstandingRequests{
		requests: make(map[uint64]*requestResponse, 0),
	}
}

func (r *outstandingRequests) pop(msgId uint64) (rr *requestResponse, ok bool) {
	r.m.Lock()
	defer r.m.Unlock()
	rr, ok = r.requests[msgId]
	if !ok {
		return
	}
	delete(r.requests, msgId)

	return
}

func (r *outstandingRequests) set(msgId uint64, rr *requestResponse) {
	r.m.Lock()
	defer r.m.Unlock()
	r.requests[msgId] = rr
}

func (r *outstandingRequests) shutdown(err error) {
	r.m.Lock()
	defer r.m.Unlock()
	for _, rr := range r.requests {
		rr.err = err
		close(rr.recv)
	}
}

func NewConnection(opt Options) (c *Connection, err error) {

	if err := validateOptions(opt); err != nil {
		return nil, err
	}
	c = &Connection{
		outstandingRequests: newOutstandingRequests(),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
	}

	c.Session = &Session{
		isSigningRequired: atomic.Bool{},
		isAuthenticated:   false,
		isSigningDisabled: opt.DisableSigning,
		clientGuid:        make([]byte, 16),
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		options:           opt,
		trees:             make(map[string]*treeConnect),
		// MS-SMB2 §3.2.4.1.6: the connection starts with a sequence window of
		// 1 credit so the initial NEGOTIATE can be sent before any grant.
		creditMgr: newCreditManager(1),
	}
	c.Session.isSigningRequired.Store(opt.RequireMessageSigning)

	if opt.ProxyDialer != nil {
		c.useProxy = true
		ctx, cancel := context.WithTimeout(context.Background(), opt.DialTimeout)
		defer cancel()
		c.conn, err = opt.ProxyDialer.(proxy.ContextDialer).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
		if err != nil {
			return
		}
	} else {
		c.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port), opt.DialTimeout)
		if err != nil {
			return
		}
	}

	// ClientGuid MUST be a generated GUID for SMB 2.1+ (MS-SMB2 §2.2.3). The
	// SMB1 multi-protocol NegotiateReq does not carry a ClientGuid field, so
	// randomizing unconditionally is safe for all paths.
	if _, err = rand.Read(c.Session.clientGuid); err != nil {
		log.Debugln(err)
		return
	}
	// Run sender and receiver go routines
	go c.runSender()
	go c.runReceiver()

	log.Traceln("Negotiating protocol")
	err = c.NegotiateProtocol()
	if err != nil {
		return
	}
	// Determine if signing is required but client wants to disable it
	if opt.DisableSigning && c.isSigningRequired.Load() && (!c.supportsEncryption) {
		err = fmt.Errorf("signing is required and cannot be disabled")
		return
	} else if opt.DisableSigning && opt.DisableEncryption && (c.dialect == DialectSmb_3_1_1) {
		err = fmt.Errorf("signing or encryption is required when using SMB 3.1.1")
		return
	}
	if !opt.ManualLogin {
		err = c.SessionSetup()
		if err != nil {
			return
		}
		log.Debugf("isSigningRequired: %v, RequireMessageSigning: %v, EncryptData: %v, IsNullSession: %v, IsGuestSession: %v\n", c.isSigningRequired.Load(), c.options.RequireMessageSigning, c.Session.sessionFlags&SessionFlagEncryptData == SessionFlagEncryptData, c.Session.sessionFlags&SessionFlagIsNull == SessionFlagIsNull, c.Session.sessionFlags&SessionFlagIsGuest == SessionFlagIsGuest)
	}

	return c, nil
}

// makeRequestResponse stamps the connection's next MessageID, CreditRequest,
// and signature/encryption onto an already-marshalled request buffer and
// registers it in the outstanding set. credited indicates the caller already
// reserved this request's credits via reserveForSend (see send); it gates the
// "ask for more" CreditRequest so only credit-managed requests advertise a
// growth target. Credit reservation itself is deliberately NOT done here: it
// can block, and this runs under c.m.
func (c *Connection) makeRequestResponse(buf []byte, credited bool) (rr *requestResponse, err error) {
	var h1 SMB1Header
	var h Header
	var smb1 bool
	var creditCharge uint16
	var messageID uint64

	if buf[0] == 0xff {
		// SMB1 header
		smb1 = true
		err = encoder.Unmarshal(buf[:32], &h1)
		if err != nil {
			log.Debugln(err)
			return
		}
	} else {
		// SMB2 header
		err = encoder.Unmarshal(buf[:64], &h)
		if err != nil {
			log.Debugln(err)
			log.Noticeln(err)
			return
		}
	}
	//NOTE Perhaps support Cancel requests?

	// Make sure the same messageID is not used twice. Might result in wasted messageIDs though.
	c.lock.Lock()
	messageID = c.messageID
	if !smb1 {
		h.MessageID = messageID
		creditCharge = h.CreditCharge
		// MS-SMB2 §3.2.4.1.6: MessageIDs must monotonically increase across
		// the connection. CreditCharge=0 is valid for SMB2 Negotiate (dialect
		// not yet known so multi-credit can't apply), but it still consumes
		// one sequence slot — otherwise the next request reuses this ID,
		// which strict servers (Windows) treat as a protocol violation and
		// answer with TCP RST.
		bump := uint64(h.CreditCharge)
		if bump == 0 {
			bump = 1
		}
		c.messageID += bump
	} else {
		// Assumed to be the SMB1 Negotiate Request
		creditCharge = 1
		c.messageID += 1
	}
	c.lock.Unlock()

	// "Ask for more": advertise a CreditRequest that both covers what this
	// request consumes and refills the window toward the target, so the granted
	// balance grows and holds instead of draining. Only for credit-managed
	// (reserved) requests — the handshake sets its own Credits.
	if credited && c.Session != nil && c.Session.creditMgr != nil {
		h.Credits = c.Session.creditMgr.requestSize(h.CreditCharge, c.Session.creditTarget())
	}

	if !smb1 {
		var hBuf []byte
		hBuf, err = encoder.Marshal(h)
		if err != nil {
			log.Debugln(err)
			return rr, err
		}
		copy(buf[:64], hBuf[:64])
	}

	if c.Session != nil {
		if h.Command != CommandSessionSetup {
			// Encrypt when the session default requires it OR the specific
			// share this request targets was flagged ENCRYPT_DATA by the
			// server (MS-SMB2 §3.2.5.5). TreeConnect itself carries TreeId 0
			// and so follows only the session-global rule.
			encrypt := c.Session.sessionFlags&SessionFlagEncryptData != 0 ||
				(c.Session.treeIdEncrypts(h.TreeID) && c.Session.canEncrypt())
			if encrypt {
				buf, err = c.encrypt(buf)
				if err != nil {
					return
				}
			} else if !c.Session.isSigningDisabled || (c.dialect == DialectSmb_3_1_1) {
				// Must sign or encrypt with SMB 3.1.1
				// TODO fix this control to check if encryption is performed instead.
				if c.Session.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
					if c.signer != nil {
						buf, err = c.sign(buf)
						if err != nil {
							return
						}
					}
				}
			}
		}
	}

	rr = &requestResponse{
		msgId:        messageID,
		creditCharge: creditCharge,
		pkt:          buf,
		recv:         make(chan []byte, 1),
	}
	c.outstandingRequests.set(messageID, rr)

	return
}

func (c *Connection) sendrecv(req any) (buf []byte, err error) {
	// Debug breadcrumb at the layer seam: every smb session operation
	// passes through here, so a single hook shows where errors originate
	// without duplicate Error logging at each call site.
	defer func() {
		if err != nil {
			log.Debugln(err)
		}
	}()
	rr, err := c.send(req)
	if err != nil {
		return
	}
	return c.recv(rr)
}

// SendRawPDU forwards an opaque SMB2 PDU (header + body) on this Connection
// and blocks for the reply. The MessageID in the header is rewritten to this
// Connection's next outbound id; signing / encryption are applied per the
// connection's negotiated state. Intended for relay / passthrough use cases
// (e.g. the SMB SOCKS proxy in relay/) where a PDU produced for one
// connection must be forwarded over another. The caller owns translation of
// any TreeID/FileID fields embedded in the body before/after this call.
//
// pdu must begin with the 4-byte SMB2 protocol id (0xfe S M B); a private
// copy is made so the caller's buffer is left untouched.
func (c *Connection) SendRawPDU(pdu []byte) ([]byte, error) {
	if len(pdu) < 64 || string(pdu[0:4]) != ProtocolSmb2 {
		return nil, fmt.Errorf("SendRawPDU: not an SMB2 PDU")
	}
	buf := make([]byte, len(pdu))
	copy(buf, pdu)
	rr, err := c.sendRawBytes(buf)
	if err != nil {
		return nil, err
	}
	return c.recv(rr)
}

// peekSMB2Header reads the Command and CreditCharge fields from an
// already-marshalled SMB2 header without a full unmarshal. Field offsets are
// fixed by MS-SMB2 §2.2.1.2: CreditCharge at byte 6, Command at byte 12.
func peekSMB2Header(buf []byte) (command, creditCharge uint16) {
	creditCharge = binary.LittleEndian.Uint16(buf[6:8])
	command = binary.LittleEndian.Uint16(buf[12:14])
	return
}

// reserveForSend reserves the credits an outbound request will consume BEFORE
// the caller takes c.m. Reserving here — rather than inside makeRequestResponse
// under c.m — is essential: reserve can block waiting for the server to grant
// credits, and blocking while holding c.m would serialize every other sender
// behind the wait and deadlock the receiver's teardown (which needs c.m to run
// the shutdown that would unblock the wait). It returns the reserved charge and
// whether a reservation was made; SMB1 and the NEGOTIATE / SESSION_SETUP
// handshake are exempt (they run inside the initial sequence window, and gating
// them would deadlock connection setup).
func (c *Connection) reserveForSend(buf []byte) (charge uint16, credited bool, err error) {
	if len(buf) < 64 || buf[0] == 0xff {
		return 0, false, nil
	}
	if c.Session == nil || c.Session.creditMgr == nil {
		return 0, false, nil
	}
	command, creditCharge := peekSMB2Header(buf)
	switch command {
	case CommandNegotiate, CommandSessionSetup:
		return 0, false, nil
	}
	if err = c.Session.creditMgr.reserve(creditCharge, c.Session.creditReserveTimeout()); err != nil {
		return 0, false, err
	}
	return creditCharge, true, nil
}

// sendRawBytes is the bytes-only twin of send: it skips the encoder.Marshal
// step (caller has already produced the wire bytes) and lets
// makeRequestResponse stamp the MessageID / signature / encryption in place.
func (c *Connection) sendRawBytes(buf []byte) (*requestResponse, error) {
	charge, credited, err := c.reserveForSend(buf)
	if err != nil {
		return nil, err
	}
	// Return the reservation unless the request is handed to the write channel:
	// a request that never reaches the server gets no response to grant its
	// credits back, so releasing here keeps the window from leaking. The wdone
	// paths already had creditMgr.shutdown unblock every waiter, so this release
	// is a harmless no-op there.
	handedOff := false
	defer func() {
		if credited && !handedOff && c.Session != nil && c.Session.creditMgr != nil {
			c.Session.creditMgr.release(charge)
		}
	}()

	c.m.Lock()
	defer c.m.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	select {
	case <-c.wdone:
		return nil, nil
	default:
	}

	rr, err := c.makeRequestResponse(buf, credited)
	if err != nil {
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(rr.pkt))); err != nil {
		return nil, err
	}

	select {
	case c.write <- append(b.Bytes(), rr.pkt...):
		select {
		case err = <-c.werr:
			if err != nil {
				c.outstandingRequests.pop(rr.msgId)
				return nil, err
			}
		case <-c.wdone:
			c.outstandingRequests.pop(rr.msgId)
			return nil, nil
		}
	case <-c.wdone:
		c.outstandingRequests.pop(rr.msgId)
		return nil, nil
	}
	handedOff = true
	return rr, nil
}

func (c *Connection) send(req any) (rr *requestResponse, err error) {
	buf, err := encoder.Marshal(req)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	charge, credited, err := c.reserveForSend(buf)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}
	// See sendRawBytes: hand the reservation back on every path that doesn't
	// deliver the request to the write channel.
	handedOff := false
	defer func() {
		if credited && !handedOff && c.Session != nil && c.Session.creditMgr != nil {
			c.Session.creditMgr.release(charge)
		}
	}()

	c.m.Lock()
	defer c.m.Unlock()
	if c.err != nil {
		return nil, c.err
	}

	select {
	case <-c.wdone:
		return
	default:
		//Do nothing
	}

	rr, err = c.makeRequestResponse(buf, credited)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(rr.pkt))); err != nil {
		log.Debugln(err)
		return
	}

	select {
	case c.write <- append(b.Bytes(), rr.pkt...):
		select {
		case err = <-c.werr:
			if err != nil {
				c.outstandingRequests.pop(rr.msgId)
				return nil, err
			}
		case <-c.wdone:
			c.outstandingRequests.pop(rr.msgId)
			return nil, nil
		}
	case <-c.wdone:
		c.outstandingRequests.pop(rr.msgId)
		return nil, nil
	}

	handedOff = true
	return
}

func (c *Connection) recv(rr *requestResponse) (buf []byte, err error) {
	if rr == nil {
		return nil, fmt.Errorf("remote connection has closed")
	}
	select {
	case <-c.rdone:
		c.outstandingRequests.pop(rr.msgId)
	case buf = <-rr.recv:
		if rr.err != nil {
			return nil, rr.err
		}
		if len(buf) == 0 {
			// Most likely received a TCP Reset
			return nil, fmt.Errorf("remote connection has closed")
		}
		return buf, nil
	}

	return
}
