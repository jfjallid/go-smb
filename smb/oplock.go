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

package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb/encoder"
)

// unsolicitedMessageID is the reserved MessageId (MS-SMB2 §3.2.5.19) the server
// uses for packets that are not a reply to a client request — currently oplock
// and lease break notifications.
const unsolicitedMessageID = uint64(0xFFFFFFFFFFFFFFFF)

// OplockBreakHandler is consulted when the server sends an unsolicited oplock
// break notification. It returns the oplock level the client wishes to retain
// (typically OpLockLevelII or OpLockLevelNone); the connection sends the
// matching acknowledgment. A nil handler acknowledges down to OpLockLevelNone.
type OplockBreakHandler func(c *Connection, notification OplockBreak) byte

// SetOplockBreakHandler registers a callback for server oplock break
// notifications. Passing nil restores the default (acknowledge down to None).
func (s *Session) SetOplockBreakHandler(h OplockBreakHandler) {
	s.oplockBreakHandler = h
}

// parseOplockBreak decodes an unsolicited break packet. It reports ok=false for
// a lease break (StructureSize 44) or any malformed/unknown body — the client
// does not request leases yet, so only oplock breaks (StructureSize 24) are
// modeled.
func parseOplockBreak(data []byte) (OplockBreak, bool) {
	if len(data) < 66 {
		log.Errorln("oplock break notification too short")
		return OplockBreak{}, false
	}
	if structSize := binary.LittleEndian.Uint16(data[64:66]); structSize != 24 {
		log.Debugf("ignoring unmodeled server break (structureSize=%d)\n", structSize)
		return OplockBreak{}, false
	}
	var nb OplockBreak
	if err := encoder.Unmarshal(data, &nb); err != nil {
		log.Errorf("failed to decode oplock break notification: %v\n", err)
		return OplockBreak{}, false
	}
	return nb, true
}

// handleServerBreak processes an unsolicited oplock break notification received
// on the read loop: it decides the acknowledgment level (via the registered
// handler or the default) and sends the acknowledgment from a separate
// goroutine so the read loop is not blocked.
func (c *Connection) handleServerBreak(data []byte) {
	nb, ok := parseOplockBreak(data)
	if !ok {
		return
	}
	ackLevel := byte(OpLockLevelNone)
	if c.Session != nil && c.Session.oplockBreakHandler != nil {
		ackLevel = c.Session.oplockBreakHandler(c, nb)
	}
	go func() {
		if _, err := c.send(c.Session.NewOplockBreakAck(nb.FileId, ackLevel)); err != nil {
			log.Debugf("oplock break ack send failed: %v\n", err)
		}
	}()
}

// SendCancel sends an SMB2 CANCEL for the in-flight request identified by msgId
// (and asyncId, which is 0 unless the target returned a STATUS_PENDING interim
// response). It is fire-and-forget: the server does not answer the CANCEL
// itself but instead completes the target request early with STATUS_CANCELLED
// on the target's original MessageId, which the normal receive path delivers.
//
// The CANCEL deliberately reuses the target's MessageId and therefore must not
// allocate a fresh id or register a new outstanding request, so it bypasses the
// usual send path.
func (c *Connection) SendCancel(msgId, asyncId uint64) error {
	if c.Session == nil {
		return fmt.Errorf("SendCancel: no session")
	}
	req := c.Session.NewCancelReq(msgId, asyncId)
	buf, err := encoder.Marshal(req)
	if err != nil {
		return err
	}
	// A CANCEL is signed when signing is in force but never encrypted — it must
	// be processed by the server independently of the target. sign() special-
	// cases CommandCancel so the signature is computed correctly.
	if !c.Session.isSigningDisabled && c.signer != nil &&
		c.Session.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
		buf, err = c.sign(buf)
		if err != nil {
			return err
		}
	}

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		return err
	}

	c.m.Lock()
	defer c.m.Unlock()
	if c.err != nil {
		return c.err
	}
	select {
	case c.write <- append(b.Bytes(), buf...):
		select {
		case err = <-c.werr:
			return err
		case <-c.wdone:
			return nil
		}
	case <-c.wdone:
		return nil
	}
}
