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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/jfjallid/go-smb/smb/encoder"
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

/*Retrieve packets from the write channel and put them to the wire.*/
func (conn *Connection) runSender() {
	for {
		select {
		case <-conn.wdone:
			return
		case pkt := <-conn.write:
			_, err := conn.conn.Write(pkt)

			conn.werr <- err
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
		log.Errorln(err)
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
	for {
		data, err := readPacket(c.conn)
		if err != nil {
			// Error is handled at the end of the method.
			break
		}
		if len(data) == 0 {
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

			// When server responds with StatusPending, the packet signature is the same as on the
			// last packet and the signing flag is not set
			if c.Session.IsSigningRequired.Load() && !encrypted && (h.Status != StatusPending) {
				//TODO Change this logic. Should verify signatures that are present but not enforce them to be present unless required?
				if (h.Flags & SMB2_FLAGS_SIGNED) != SMB2_FLAGS_SIGNED {
					err = fmt.Errorf("Skip: Signing is required but PDU is not signed")
					log.Errorln(err)
					continue
				} else {
					if !c.verify(data) {
						err = fmt.Errorf("Skip: Signing is required and invalid signature found")
						log.Errorln(err)
						continue
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
				if err = encoder.Unmarshal(data[:64], &h); err != nil {
					fmt.Println("Skip: Failed to decode header of packet")
					continue
				}
				// Check structure size
				if h.StructureSize != 64 {
					log.Errorln("Skip: Invalid structure size of packet")
					continue
				}
			}
		}

		rr, ok := c.outstandingRequests.pop(h.MessageID)
		if !ok {
			fmt.Printf("Message Id (%d) not found in outstanding packets!\n", h.MessageID)
			continue
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
		log.Errorln(err)
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
		IsSigningRequired: atomic.Bool{},
		IsAuthenticated:   false,
		IsSigningDisabled: opt.DisableSigning,
		clientGuid:        make([]byte, 16),
		securityMode:      0,
		messageID:         0,
		sessionID:         0,
		dialect:           0,
		options:           opt,
		trees:             make(map[string]uint32),
	}
	c.Session.IsSigningRequired.Store(opt.RequireMessageSigning)

	if opt.ProxyDialer != nil {
		c.useProxy = true
		// No DialTimeout supported
		c.conn, err = opt.ProxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		c.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port), opt.DialTimeout)
		if err != nil {
			return
		}
	}

	// SMB Dialects other than 3.x requires clientGuid to be zero
	if !opt.ForceSMB2 {
		_, err = rand.Read(c.Session.clientGuid)
		if err != nil {
			log.Debugln(err)
			return
		}
	} else {
		c.Session.options.DisableEncryption = true
	}

	// Run sender and receiver go routines
	go c.runSender()
	go c.runReceiver()

	log.Debugln("Negotiating protocol")
	err = c.NegotiateProtocol()
	if err != nil {
		return
	}
	err = c.SessionSetup()
	if err != nil {
		return
	}
	log.Debugf("IsSigningRequired: %v, RequireMessageSigning: %v, EncryptData: %v, IsNullSession: %v, IsGuestSession: %v\n", c.IsSigningRequired.Load(), c.options.RequireMessageSigning, c.Session.sessionFlags&SessionFlagEncryptData == SessionFlagEncryptData, c.Session.sessionFlags&SessionFlagIsNull == SessionFlagIsNull, c.Session.sessionFlags&SessionFlagIsGuest == SessionFlagIsGuest)

	return c, nil
}

func (c *Connection) makeRequestResponse(buf []byte) (rr *requestResponse, err error) {
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
		c.messageID += uint64(h.CreditCharge)
	} else {
		// Assumed to be the SMB1 Negotiate Request
		creditCharge = 1
		c.messageID += 1
	}
	c.lock.Unlock()

	if !smb1 {
		hBuf, err := encoder.Marshal(h)
		if err != nil {
			log.Debugln(err)
			return rr, err
		}
		copy(buf[:64], hBuf[:64])
	}

	if c.Session != nil {
		if h.Command != CommandSessionSetup {
			if c.Session.sessionFlags&SessionFlagEncryptData != 0 {
				buf, err = c.encrypt(buf)
				if err != nil {
					log.Errorln(err)
					return
				}
			} else if !c.Session.IsSigningDisabled || (c.dialect == DialectSmb_3_1_1) {
				// Must sign or encrypt with SMB 3.1.1
				// TODO fix this control to check if encryption is performed instead.
				if c.Session.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
					if c.signer != nil {
						buf, err = c.sign(buf)
						if err != nil {
							log.Errorln(err)
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

func (c *Connection) sendrecv(req interface{}) (buf []byte, err error) {
	rr, err := c.send(req)
	if err != nil {
		return
	}
	return c.recv(rr)
}

func (c *Connection) send(req interface{}) (rr *requestResponse, err error) {

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

	buf, err := encoder.Marshal(req)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	rr, err = c.makeRequestResponse(buf)
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

	return
}

func (c *Connection) recv(rr *requestResponse) (buf []byte, err error) {
	select {
	case buf = <-rr.recv:
		if rr.err != nil {
			return nil, rr.err
		}
		return buf, nil
	case <-c.rdone:
		c.outstandingRequests.pop(rr.msgId)
	}

	return
}
