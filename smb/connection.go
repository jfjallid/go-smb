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

/*
	Read packets from the wire. If the message id matches that of the outstandingRequests map,

clear the packet from the map and forward the packet down the recv channel.
*/
func (c *Connection) runReceiver() {
	var err error
	var size uint32
    var encrypted bool
	for {
		if err = binary.Read(c.conn, binary.BigEndian, &size); err != nil {
			// Error is handled at the end of the method.
			break
		}

		if size > 0x00FFFFFF {
			log.Errorln("Error: Invalid NetBIOS Session message")
			continue
		}

		data := make([]byte, size)
		l, err := io.ReadFull(c.conn, data)
		if err != nil {
			// Error is handled at the end of the method.
			break
		}
		if uint32(l) != size {
			log.Errorln("Error: Message size invalid")
			continue
		}

		hasSession := c.useSession()

		protID := data[0:4]
		switch string(protID) {
		default:
			log.Errorln("Error: Protocol not implemented")
			continue // No need to crash because of invalid packet
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

			if c.Session.IsSigningRequired && !encrypted {
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

func NewConnection(opt Options, debug bool) (c *Connection, err error) {

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

	c.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port), opt.DialTimeout)
	if err != nil {
		return
	}

	c.Session = &Session{
		IsSigningRequired: opt.RequireMessageSigning,
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

	return c, nil
}

func (c *Connection) makeRequestResponse(buf []byte) (rr *requestResponse, err error) {
	var h Header
	err = encoder.Unmarshal(buf[:64], &h)
	if err != nil {
		log.Debugln(err)
		return
	}
	//NOTE Perhaps support Cancel requests?

	// Make sure the same messageID is not used twice. Might result in wasted messageIDs though.
	c.lock.Lock()
	h.MessageID = c.messageID
	c.messageID += uint64(h.CreditCharge)
	c.lock.Unlock()
	hBuf, err := encoder.Marshal(h)
	if err != nil {
		log.Debugln(err)
		return
	}
	copy(buf[:64], hBuf[:64])

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
		msgId:        h.MessageID,
		creditCharge: h.CreditCharge,
		pkt:          buf,
		recv:         make(chan []byte, 1),
	}
	c.outstandingRequests.set(h.MessageID, rr)

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
