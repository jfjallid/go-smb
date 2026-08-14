// MIT License
//
// Copyright (c) 2017 stacktitan
// Copyright (c) 2023 Jimmy Fjällid for contributions adding SMB 3.1.1 support
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
package ntlmssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const Signature = "NTLMSSP\x00"

const (
	WINDOWS_MAJOR_VERSION_5  = 0x05
	WINDOWS_MAJOR_VERSION_6  = 0x06
	WINDOWS_MAJOR_VERSION_10 = 0x0a
	WINDOWS_MINOR_VERSION_0  = 0x00
	WINDOWS_MINOR_VERSION_1  = 0x01
	WINDOWS_MINOR_VERSION_2  = 0x02
	WINDOWS_MINOR_VERSION_3  = 0x03
)

const NTLMSSP_REVISION_W2K3 = 0x0f

const (
	_ uint32 = iota
	TypeNtLmNegotiate
	TypeNtLmChallenge
	TypeNtLmAuthenticate
)

const (
	FlgNegUnicode       uint32 = 1 << iota //If set, requests Unicode character set encoding. NTLMSSP_NEGOTIATE_UNICODE
	FlgNegOEM                              //If set, requests OEM character set encoding. NTLM_NEGOTIATE_OEM
	FlgNegRequestTarget                    //If set, a TargetName field of the CHALLENGE_MESSAGE (section 2.2.1.2) MUST be supplied. NTLMSSP_REQUEST_TARGET.
	FlgNegReserved10
	FlgNegSign     //If set, requests session key negotiation for message signatures. NTLMSSP_NEGOTIATE_SIGN
	FlgNegSeal     //If set, requests session key negotiation for message confidentiality. NTLMSSP_NEGOTIATE_SEAL
	FlgNegDatagram //If set, requests connectionless authentication
	FlgNegLmKey    //If set, requests LAN Manager (LM) session key computation.
	FlgNegReserved9
	FlgNegNtLm //If set, requests usage of the NTLM v1 session security protocol.
	FlgNegReserved8
	FlgNegAnonymous              //If set, the connection SHOULD be anonymous.
	FlgNegOEMDomainSupplied      //If set, the domain name is provided.
	FlgNegOEMWorkstationSupplied //This flag indicates whether the Workstation field is present.
	FlgNegReserved7
	FlgNegAlwaysSign       //If set, a session key is generated regardless of the states of NTLMSSP_NEGOTIATE_SIGN and NTLMSSP_NEGOTIATE_SEAL
	FlgNegTargetTypeDomain //If set, TargetName MUST be a domain name.
	FlgNegTargetTypeServer //If set, TargetName MUST be a server name.
	FlgNegReserved6
	FlgNegExtendedSessionSecurity //If set, requests usage of the NTLM v2 session security.
	FlgNegIdentify                //If set, requests an identify level token.
	FlgNegReserved5
	FlgNegRequestNonNtSessionKey //If set, requests the usage of the LMOWF.
	FlgNegTargetInfo             //If set, indicates that the TargetInfo fields in the CHALLENGE_MESSAGE are populated.
	FlgNegReserved4
	FlgNegVersion //If set, requests the protocol version number. The data corresponding to this flag is provided in the Version field.
	FlgNegReserved3
	FlgNegReserved2
	FlgNegReserved1
	FlgNeg128     //If set, requests 128-bit session key negotiation.
	FlgNegKeyExch //If set, requests an explicit key exchange. This capability SHOULD be used because it improves security for message integrity or confidentiality.
	FlgNeg56      //If set, requests 56-bit encryption
)

const (
	MsvAvEOL uint16 = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDnsComputerName
	MsvAvDnsDomainName
	MsvAvDnsTreeName
	MsvAvFlags
	MsvAvTimestamp
	MsvAvSingleHost
	MsvAvTargetName
	MsvAvChannelBindings
)

type Version struct {
	ProductMajorVersion byte
	ProductMinorVersion byte
	ProductBuild        uint16
	Reserved            []byte
	NTLMRevisionCurrent byte
}

type Header struct {
	Signature   []byte
	MessageType uint32
}

type Negotiate struct { // 28 + size of DomainName and Workstation
	Header
	NegotiateFlags          uint32
	DomainNameLen           uint16
	DomainNameMaxLen        uint16
	DomainNameBufferOffset  uint32
	WorkstationLen          uint16
	WorkstationMaxLen       uint16
	WorkstationBufferOffset uint32
	Version                 uint64
	DomainName              []byte
	Workstation             []byte
}

type Challenge struct { // 44 + TargetName + TargetInfo
	Header
	TargetNameLen          uint16
	TargetNameMaxLen       uint16
	TargetNameBufferOffset uint32
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32
	Version                uint64
	TargetName             []byte
	TargetInfo             *AvPairSlice
}

type Authenticate struct {
	Header
	LmChallengeResponseLen                uint16
	LmChallengeResponseMaxLen             uint16
	LmChallengeResponseBufferOffset       uint32
	NtChallengeResponseLen                uint16
	NtChallengeResponseMaxLen             uint16
	NtChallengResponseBufferOffset        uint32
	DomainNameLen                         uint16
	DomainNameMaxLen                      uint16
	DomainNameBufferOffset                uint32
	UserNameLen                           uint16
	UserNameMaxLen                        uint16
	UserNameBufferOffset                  uint32
	WorkstationLen                        uint16
	WorkstationMaxLen                     uint16
	WorkstationBufferOffset               uint32
	EncryptedRandomSessionKeyLen          uint16
	EncryptedRandomSessionKeyMaxLen       uint16
	EncryptedRandomSessionKeyBufferOffset uint32
	NegotiateFlags                        uint32
	Version                               uint64 //`smb:"omitempty:0"` // Added for SMB 3.1.1
	MIC                                   []byte // Added for SMB 3.1.1
	DomainName                            []byte
	UserName                              []byte
	Workstation                           []byte
	LmChallengeResponse                   []byte
	NtChallengeResponse                   []byte
	EncryptedRandomSessionKey             []byte
}

func (s *Authenticate) MarshalBinary() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, 64))
	le := binary.LittleEndian
	offset := 64 // Start of payload bytes
	if s.Version != 0 {
		offset += 8
	}
	if len(s.MIC) != 0 {
		offset += 16
	}

	// Encode header signature
	err := binary.Write(w, le, s.Header.Signature[:8])
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	// Encode header message type
	err = binary.Write(w, le, s.Header.MessageType)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	if len(s.LmChallengeResponse) == 0 {
		// Anonymous auth attempt
		// Encode empty LM ChallengeResponse
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		// Encode LM ChallengeResponse
		err = binary.Write(w, le, uint16(len(s.LmChallengeResponse)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
		err = binary.Write(w, le, uint16(len(s.LmChallengeResponse)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		lmBufferOffset := offset + len(s.DomainName) + len(s.UserName) + len(s.Workstation) + len(s.EncryptedRandomSessionKey)
		err = binary.Write(w, le, uint32(lmBufferOffset))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}
	if len(s.NtChallengeResponse) == 0 {
		// Anonymous auth attempt
		// Encode empty NT ChallengeResponse
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		// Encode NT ChallengeResponse
		err = binary.Write(w, le, uint16(len(s.NtChallengeResponse)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
		err = binary.Write(w, le, uint16(len(s.NtChallengeResponse)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
		ntBufferOffset := offset + len(s.DomainName) + len(s.UserName) + len(s.Workstation) + len(s.EncryptedRandomSessionKey) + len(s.LmChallengeResponse)
		err = binary.Write(w, le, uint32(ntBufferOffset))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode DomainName
	if len(s.DomainName) == 0 {
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		err = binary.Write(w, le, uint16(len(s.DomainName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint16(len(s.DomainName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint32(offset))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode UserName
	if len(s.UserName) == 0 {
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		err = binary.Write(w, le, uint16(len(s.UserName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint16(len(s.UserName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint32(offset+len(s.DomainName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode Workstation
	if len(s.Workstation) == 0 {
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		err = binary.Write(w, le, uint16(len(s.Workstation)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint16(len(s.Workstation)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint32(offset+len(s.DomainName)+len(s.UserName)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode EncryptedRandomSessionKey
	if len(s.EncryptedRandomSessionKey) == 0 {
		buf := make([]byte, 8)
		buf[4] = byte(offset)
		err = binary.Write(w, le, buf)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	} else {
		err = binary.Write(w, le, uint16(len(s.EncryptedRandomSessionKey)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint16(len(s.EncryptedRandomSessionKey)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}

		err = binary.Write(w, le, uint32(offset+len(s.DomainName)+len(s.UserName)+len(s.Workstation)))
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode NegotiateFlags
	err = binary.Write(w, le, s.NegotiateFlags)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	// Encode Version (Specific for SMB 3.1.1? So skip if 0)
	if s.Version != 0 {
		err = binary.Write(w, le, s.Version)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}
	// Encode MIC (Specific for SMB 3.1.1? So skip of empty)
	if len(s.MIC) != 0 {
		err = binary.Write(w, le, s.MIC[:16])
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	// Encode the payload buffers
	if len(s.DomainName) != 0 {
		err = binary.Write(w, le, s.DomainName)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	if len(s.UserName) != 0 {
		err = binary.Write(w, le, s.UserName)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	if len(s.Workstation) != 0 {
		err = binary.Write(w, le, s.Workstation)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	if len(s.EncryptedRandomSessionKey) != 0 {
		err = binary.Write(w, le, s.EncryptedRandomSessionKey)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	if len(s.LmChallengeResponse) != 0 {
		err = binary.Write(w, le, s.LmChallengeResponse)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	if len(s.NtChallengeResponse) != 0 {
		err = binary.Write(w, le, s.NtChallengeResponse)
		if err != nil {
			log.Debugln(err)
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// withinBuf reports whether a variable-length field of length bytes starting
// at offset fits entirely within a buffer of bufLen bytes. The comparison is
// done in uint64 so a wire-controlled uint32 offset added to a uint16 length
// cannot overflow and wrap past the guard (e.g. offset=0xFFFFFFFF, length=2
// would wrap to 1 in uint32 arithmetic and falsely pass).
func withinBuf(bufLen int, offset uint32, length uint16) bool {
	if bufLen < 0 {
		return false
	}
	return uint64(offset)+uint64(length) <= uint64(bufLen)
}

func (s *Authenticate) UnmarshalBinary(buf []byte) error {
	log.Traceln("In UnmarshalBinary for Authenticate")
	baseSize := authenticateMinSize
	bufLen := len(buf)
	if bufLen < baseSize {
		err := fmt.Errorf("authenticate buffer is only %d bytes, but at least 64 bytes is required to unmarshal", bufLen)
		return err
	}

	s.Signature = buf[:8]
	s.MessageType = binary.LittleEndian.Uint32(buf[8:12])
	s.LmChallengeResponseLen = binary.LittleEndian.Uint16(buf[12:14])
	s.LmChallengeResponseMaxLen = binary.LittleEndian.Uint16(buf[14:16])
	s.LmChallengeResponseBufferOffset = binary.LittleEndian.Uint32(buf[16:20])
	s.NtChallengeResponseLen = binary.LittleEndian.Uint16(buf[20:22])
	s.NtChallengeResponseMaxLen = binary.LittleEndian.Uint16(buf[22:24])
	s.NtChallengResponseBufferOffset = binary.LittleEndian.Uint32(buf[24:28])
	s.DomainNameLen = binary.LittleEndian.Uint16(buf[28:30])
	s.DomainNameMaxLen = binary.LittleEndian.Uint16(buf[30:32])
	s.DomainNameBufferOffset = binary.LittleEndian.Uint32(buf[32:36])
	s.UserNameLen = binary.LittleEndian.Uint16(buf[36:38])
	s.UserNameMaxLen = binary.LittleEndian.Uint16(buf[38:40])
	s.UserNameBufferOffset = binary.LittleEndian.Uint32(buf[40:44])
	s.WorkstationLen = binary.LittleEndian.Uint16(buf[44:46])
	s.WorkstationMaxLen = binary.LittleEndian.Uint16(buf[46:48])
	s.WorkstationBufferOffset = binary.LittleEndian.Uint32(buf[48:52])
	s.EncryptedRandomSessionKeyLen = binary.LittleEndian.Uint16(buf[52:54])
	s.EncryptedRandomSessionKeyMaxLen = binary.LittleEndian.Uint16(buf[54:56])
	s.EncryptedRandomSessionKeyBufferOffset = binary.LittleEndian.Uint32(buf[56:60])
	s.NegotiateFlags = binary.LittleEndian.Uint32(buf[60:64])

	offset := 64

	// Sum the field lengths in int (not uint16) so the running total cannot
	// wrap: each field is a uint16, so the sum of six of them plus the version
	// is well within int range, and the "at least N bytes" guard below stays
	// reliable.
	extraBytes := int(s.LmChallengeResponseLen) +
		int(s.NtChallengeResponseLen) +
		int(s.DomainNameLen) +
		int(s.UserNameLen) +
		int(s.WorkstationLen) +
		int(s.EncryptedRandomSessionKeyLen)

	// Sanity check that none of the offsets + lengths points outside the buffer.
	// withinBuf computes offset+length in uint64 so a wire-controlled offset
	// (e.g. 0xFFFFFFFF) cannot overflow uint32 and wrap past the comparison,
	// which would otherwise let the slices below panic on an OOB read.
	if !withinBuf(bufLen, s.LmChallengeResponseBufferOffset, s.LmChallengeResponseLen) {
		return fmt.Errorf("LmChallengeResponse field offset/length is outside buffer")
	}
	if !withinBuf(bufLen, s.NtChallengResponseBufferOffset, s.NtChallengeResponseLen) {
		return fmt.Errorf("NtChallengeResponse field offset/length is outside buffer")
	}
	if !withinBuf(bufLen, s.DomainNameBufferOffset, s.DomainNameLen) {
		return fmt.Errorf("DomainName field offset/length is outside buffer")
	}
	if !withinBuf(bufLen, s.UserNameBufferOffset, s.UserNameLen) {
		return fmt.Errorf("UserName field offset/length is outside buffer")
	}
	if !withinBuf(bufLen, s.WorkstationBufferOffset, s.WorkstationLen) {
		return fmt.Errorf("Workstation field offset/length is outside buffer")
	}
	if !withinBuf(bufLen, s.EncryptedRandomSessionKeyBufferOffset, s.EncryptedRandomSessionKeyLen) {
		return fmt.Errorf("EncryptedRandomSessionKey field offset/length is outside buffer")
	}

	unmarshalVersion := false
	if (s.NegotiateFlags & FlgNegVersion) == FlgNegVersion {
		// Also unmarshal version, so 8 bytes more
		unmarshalVersion = true
		extraBytes += 8
	}
	if baseSize+extraBytes > bufLen {
		err := fmt.Errorf("authenticate buffer is only %d bytes, but at least %d bytes is required to unmarshal all the specified custom length fields", bufLen, baseSize+extraBytes)
		return err
	}

	if unmarshalVersion {
		s.Version = binary.LittleEndian.Uint64(buf[offset : offset+8])
		offset += 8
	}

	if bufLen >= baseSize+extraBytes+16 {
		// Also unmarshal MIC
		s.MIC = buf[offset : offset+16]
		offset += 16
	}

	if s.LmChallengeResponseLen > 0 {
		s.LmChallengeResponse = buf[s.LmChallengeResponseBufferOffset : s.LmChallengeResponseBufferOffset+uint32(s.LmChallengeResponseLen)]
	}
	if s.NtChallengeResponseLen > 0 {
		s.NtChallengeResponse = buf[s.NtChallengResponseBufferOffset : s.NtChallengResponseBufferOffset+uint32(s.NtChallengeResponseLen)]
	}
	if s.DomainNameLen > 0 {
		s.DomainName = buf[s.DomainNameBufferOffset : s.DomainNameBufferOffset+uint32(s.DomainNameLen)]
	}
	if s.UserNameLen > 0 {
		s.UserName = buf[s.UserNameBufferOffset : s.UserNameBufferOffset+uint32(s.UserNameLen)]
	}
	if s.WorkstationLen > 0 {
		s.Workstation = buf[s.WorkstationBufferOffset : s.WorkstationBufferOffset+uint32(s.WorkstationLen)]
	}
	if s.EncryptedRandomSessionKeyLen > 0 {
		s.EncryptedRandomSessionKey = buf[s.EncryptedRandomSessionKeyBufferOffset : s.EncryptedRandomSessionKeyBufferOffset+uint32(s.EncryptedRandomSessionKeyLen)]
	}

	return nil
}

func NewChallenge() Challenge {
	return Challenge{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmChallenge,
		},
		TargetNameLen:          0,
		TargetNameMaxLen:       0,
		TargetNameBufferOffset: 0,
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegVersion |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegTargetTypeServer |
			FlgNegNtLm |
			FlgNegRequestTarget |
			FlgNegUnicode,
		ServerChallenge:        0,
		Reserved:               0,
		TargetInfoLen:          0,
		TargetInfoMaxLen:       0,
		TargetInfoBufferOffset: 0,
		Version:                0,
		TargetName:             []byte{},
		TargetInfo:             new(AvPairSlice),
	}
}

type AvPair struct {
	AvID  uint16
	AvLen uint16
	Value []byte
}
type AvPairSlice []AvPair

func (p AvPair) Size() uint64 {
	return uint64(binary.Size(p.AvID) + binary.Size(p.AvLen) + int(p.AvLen))
}
