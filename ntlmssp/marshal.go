// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

// Hand-written wire marshalling for the NTLMSSP messages, replacing the
// reflection-based smb/encoder engine. MS-NLMP describes every variable-length
// payload with a (Len, MaxLen, BufferOffset) triple pointing into the tail of
// the message; appendPayloadDesc emits one such triple and the Marshal methods
// append the payloads in struct-declaration order so the offsets stay
// self-consistent.
package ntlmssp

import (
	"encoding/binary"
	"fmt"
)

// Fixed (pre-payload) sizes of the three NTLMSSP messages, in bytes. Payload
// offsets are measured from the start of the message, so these double as the
// offset of the first payload byte.
const (
	headerSize          = 12 // Signature(8) + MessageType(4)
	negotiateFixedSize  = 40
	challengeFixedSize  = 56
	authenticateMinSize = 64
)

// appendPayloadDesc appends the Len/MaxLen/BufferOffset triple describing a
// payload of length bytes located at offset. An absent (zero-length) payload is
// described with a zero offset, which is what this package has always put on
// the wire; MaxLen is always equal to Len, as Windows does for these messages.
func appendPayloadDesc(buf []byte, length, offset int) []byte {
	buf = binary.LittleEndian.AppendUint16(buf, uint16(length))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(length))
	if length == 0 {
		offset = 0
	}
	return binary.LittleEndian.AppendUint32(buf, uint32(offset))
}

// payload returns the length bytes at offset within buf. It reports an error
// rather than slicing out of range: every offset/length pair here is
// peer-controlled, and these decoders run on connections that have not
// authenticated yet.
func payload(buf []byte, field string, offset uint32, length uint16) ([]byte, error) {
	if !withinBuf(len(buf), offset, length) {
		return nil, fmt.Errorf("%s field offset %d/length %d is outside the %d-byte message", field, offset, length, len(buf))
	}
	if length == 0 {
		return nil, nil
	}
	return buf[offset : uint32(length)+offset], nil
}

func (s *Header) MarshalBinary() ([]byte, error) {
	if len(s.Signature) != 8 {
		return nil, fmt.Errorf("NTLMSSP header signature must be 8 bytes, got %d", len(s.Signature))
	}
	buf := make([]byte, 0, headerSize)
	buf = append(buf, s.Signature...)
	return binary.LittleEndian.AppendUint32(buf, s.MessageType), nil
}

func (s *Header) UnmarshalBinary(buf []byte) error {
	if len(buf) < headerSize {
		return fmt.Errorf("NTLMSSP header requires %d bytes, got %d", headerSize, len(buf))
	}
	s.Signature = buf[:8]
	s.MessageType = binary.LittleEndian.Uint32(buf[8:12])
	return nil
}

func (s *AvPair) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 4+len(s.Value))
	buf = binary.LittleEndian.AppendUint16(buf, s.AvID)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Value)))
	return append(buf, s.Value...), nil
}

func (s *AvPair) UnmarshalBinary(buf []byte) error {
	if len(buf) < 4 {
		return fmt.Errorf("AvPair requires 4 bytes, got %d", len(buf))
	}
	s.AvID = binary.LittleEndian.Uint16(buf[:2])
	s.AvLen = binary.LittleEndian.Uint16(buf[2:4])
	if int(s.AvLen) > len(buf)-4 {
		return fmt.Errorf("AvPair value length %d exceeds the %d remaining bytes", s.AvLen, len(buf)-4)
	}
	s.Value = buf[4 : 4+s.AvLen]
	return nil
}

func (s *AvPairSlice) MarshalBinary() ([]byte, error) {
	var buf []byte
	for i := range *s {
		pair, err := (*s)[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pair...)
	}
	return buf, nil
}

// UnmarshalBinary parses buf as a sequence of AV_PAIRs filling the whole slice.
// buf must be exactly the TargetInfo window: the caller (Challenge) is the one
// holding the offset/length that delimits it.
func (s *AvPairSlice) UnmarshalBinary(buf []byte) error {
	slice := []AvPair{}
	for off := 0; off < len(buf); {
		var pair AvPair
		if err := pair.UnmarshalBinary(buf[off:]); err != nil {
			return err
		}
		slice = append(slice, pair)
		// A pair always occupies at least its 4-byte preamble, so off strictly
		// increases and the loop terminates.
		off += int(pair.Size())
	}
	*s = slice
	return nil
}

func (s *Negotiate) MarshalBinary() ([]byte, error) {
	hdr, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, negotiateFixedSize+len(s.DomainName)+len(s.Workstation))
	buf = append(buf, hdr...)
	buf = binary.LittleEndian.AppendUint32(buf, s.NegotiateFlags)
	buf = appendPayloadDesc(buf, len(s.DomainName), negotiateFixedSize)
	buf = appendPayloadDesc(buf, len(s.Workstation), negotiateFixedSize+len(s.DomainName))
	buf = binary.LittleEndian.AppendUint64(buf, s.Version)
	buf = append(buf, s.DomainName...)
	buf = append(buf, s.Workstation...)
	return buf, nil
}

func (s *Negotiate) UnmarshalBinary(buf []byte) error {
	if len(buf) < negotiateFixedSize {
		return fmt.Errorf("NTLMSSP NEGOTIATE requires %d bytes, got %d", negotiateFixedSize, len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	s.NegotiateFlags = binary.LittleEndian.Uint32(buf[12:16])
	s.DomainNameLen = binary.LittleEndian.Uint16(buf[16:18])
	s.DomainNameMaxLen = binary.LittleEndian.Uint16(buf[18:20])
	s.DomainNameBufferOffset = binary.LittleEndian.Uint32(buf[20:24])
	s.WorkstationLen = binary.LittleEndian.Uint16(buf[24:26])
	s.WorkstationMaxLen = binary.LittleEndian.Uint16(buf[26:28])
	s.WorkstationBufferOffset = binary.LittleEndian.Uint32(buf[28:32])
	s.Version = binary.LittleEndian.Uint64(buf[32:40])

	var err error
	if s.DomainName, err = payload(buf, "DomainName", s.DomainNameBufferOffset, s.DomainNameLen); err != nil {
		return err
	}
	if s.Workstation, err = payload(buf, "Workstation", s.WorkstationBufferOffset, s.WorkstationLen); err != nil {
		return err
	}
	return nil
}

func (s *Challenge) MarshalBinary() ([]byte, error) {
	hdr, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	var info []byte
	if s.TargetInfo != nil {
		if info, err = s.TargetInfo.MarshalBinary(); err != nil {
			return nil, err
		}
	}

	buf := make([]byte, 0, challengeFixedSize+len(s.TargetName)+len(info))
	buf = append(buf, hdr...)
	buf = appendPayloadDesc(buf, len(s.TargetName), challengeFixedSize)
	buf = binary.LittleEndian.AppendUint32(buf, s.NegotiateFlags)
	buf = binary.LittleEndian.AppendUint64(buf, s.ServerChallenge)
	buf = binary.LittleEndian.AppendUint64(buf, s.Reserved)
	// TargetInfo carries a real offset whenever the pointer is non-nil, even for
	// an empty pair list — unlike the []byte payloads above, which describe
	// "absent" with a zero offset. Preserved deliberately: this is the wire form
	// the package has always emitted and peers accept it.
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(info)))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(info)))
	if s.TargetInfo == nil {
		buf = binary.LittleEndian.AppendUint32(buf, 0)
	} else {
		buf = binary.LittleEndian.AppendUint32(buf, uint32(challengeFixedSize+len(s.TargetName)))
	}
	buf = binary.LittleEndian.AppendUint64(buf, s.Version)
	buf = append(buf, s.TargetName...)
	buf = append(buf, info...)
	return buf, nil
}

func (s *Challenge) UnmarshalBinary(buf []byte) error {
	if len(buf) < challengeFixedSize {
		return fmt.Errorf("NTLMSSP CHALLENGE requires %d bytes, got %d", challengeFixedSize, len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	s.TargetNameLen = binary.LittleEndian.Uint16(buf[12:14])
	s.TargetNameMaxLen = binary.LittleEndian.Uint16(buf[14:16])
	s.TargetNameBufferOffset = binary.LittleEndian.Uint32(buf[16:20])
	s.NegotiateFlags = binary.LittleEndian.Uint32(buf[20:24])
	s.ServerChallenge = binary.LittleEndian.Uint64(buf[24:32])
	s.Reserved = binary.LittleEndian.Uint64(buf[32:40])
	s.TargetInfoLen = binary.LittleEndian.Uint16(buf[40:42])
	s.TargetInfoMaxLen = binary.LittleEndian.Uint16(buf[42:44])
	s.TargetInfoBufferOffset = binary.LittleEndian.Uint32(buf[44:48])
	s.Version = binary.LittleEndian.Uint64(buf[48:56])

	var err error
	if s.TargetName, err = payload(buf, "TargetName", s.TargetNameBufferOffset, s.TargetNameLen); err != nil {
		return err
	}
	// The offset/length delimiting TargetInfo are server-controlled; payload
	// bounds-checks them before AvPairSlice walks the window.
	info, err := payload(buf, "TargetInfo", s.TargetInfoBufferOffset, s.TargetInfoLen)
	if err != nil {
		return err
	}
	s.TargetInfo = new(AvPairSlice)
	return s.TargetInfo.UnmarshalBinary(info)
}
