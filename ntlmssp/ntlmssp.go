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
	"errors"
	"fmt"

	"github.com/jfjallid/go-smb/smb/encoder"
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

type addr struct {
	typ uint32
	val []byte
}

// channelBindings represents gss_channel_bindings_struct
type channelBindings struct {
	InitiatorAddress addr
	AcceptorAddress  addr
	AppData          []byte
}

type Version struct {
	ProductMajorVersion byte
	ProductMinorVersion byte
	ProductBuild        uint16
	Reserved            []byte `smb:"fixed:3"`
	NTLMRevisionCurrent byte
}

type Header struct {
	Signature   []byte `smb:"fixed:8"`
	MessageType uint32
}

type Negotiate struct { // 28 + size of DomainName and Workstation
	Header
	NegotiateFlags          uint32
	DomainNameLen           uint16 `smb:"len:DomainName"`
	DomainNameMaxLen        uint16 `smb:"len:DomainName"`
	DomainNameBufferOffset  uint32 `smb:"offset:DomainName"`
	WorkstationLen          uint16 `smb:"len:Workstation"`
	WorkstationMaxLen       uint16 `smb:"len:Workstation"`
	WorkstationBufferOffset uint32 `smb:"offset:Workstation"`
	Version                 uint64
	DomainName              []byte
	Workstation             []byte
}

type Challenge struct { // 44 + TargetName + TargetInfo
	Header
	TargetNameLen          uint16 `smb:"len:TargetName"`
	TargetNameMaxLen       uint16 `smb:"len:TargetName"`
	TargetNameBufferOffset uint32 `smb:"offset:TargetName"`
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16 `smb:"len:TargetInfo"`
	TargetInfoMaxLen       uint16 `smb:"len:TargetInfo"`
	TargetInfoBufferOffset uint32 `smb:"offset:TargetInfo"`
	Version                uint64
	TargetName             []byte
	TargetInfo             *AvPairSlice
}

type Authenticate struct {
	Header
	LmChallengeResponseLen                uint16 `smb:"len:LmChallengeResponse"`
	LmChallengeResponseMaxLen             uint16 `smb:"len:LmChallengeResponse"`
	LmChallengeResponseBufferOffset       uint32 `smb:"offset:LmChallengeResponse"`
	NtChallengeResponseLen                uint16 `smb:"len:NtChallengeResponse"`
	NtChallengeResponseMaxLen             uint16 `smb:"len:NtChallengeResponse"`
	NtChallengResponseBufferOffset        uint32 `smb:"offset:NtChallengeResponse"`
	DomainNameLen                         uint16 `smb:"len:DomainName"`
	DomainNameMaxLen                      uint16 `smb:"len:DomainName"`
	DomainNameBufferOffset                uint32 `smb:"offset:DomainName"`
	UserNameLen                           uint16 `smb:"len:UserName"`
	UserNameMaxLen                        uint16 `smb:"len:UserName"`
	UserNameBufferOffset                  uint32 `smb:"offset:UserName"`
	WorkstationLen                        uint16 `smb:"len:Workstation"`
	WorkstationMaxLen                     uint16 `smb:"len:Workstation"`
	WorkstationBufferOffset               uint32 `smb:"offset:Workstation"`
	EncryptedRandomSessionKeyLen          uint16 `smb:"len:EncryptedRandomSessionKey"`
	EncryptedRandomSessionKeyMaxLen       uint16 `smb:"len:EncryptedRandomSessionKey"`
	EncryptedRandomSessionKeyBufferOffset uint32 `smb:"offset:EncryptedRandomSessionKey"`
	NegotiateFlags                        uint32
	Version                               uint64 //`smb:"omitempty:0"` // Added for SMB 3.1.1
	MIC                                   []byte `smb:"fixed:16"` // Added for SMB 3.1.1
	DomainName                            []byte `smb:"unicode"`
	UserName                              []byte `smb:"unicode"`
	Workstation                           []byte `smb:"unicode"`
	LmChallengeResponse                   []byte
	NtChallengeResponse                   []byte
	EncryptedRandomSessionKey             []byte
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

//type MessageSignature struct {
//    Version     uint32
//    RandomPad   []byte `smb:"fixed:4"`
//    Checksum    []byte `smb:"fixed:4"`
//    SeqNum      uint32
//}
//
//func (self *MessageSignature) Bytes() []byte {
//    ret := make([]byte, 16)
//    binary.LittleEndian.PutUint32(ret, 0x00000001) // Must always be 1
//
//    w := bytes.NewBuffer(make([]byte, 0))
//    binary.Write(w, binary.LittleEndian, self.RandomPad)
//    copy(ret[4:8], w.Bytes()[:4])
//
//    w = bytes.NewBuffer(make([]byte, 0))
//    binary.Write(w, binary.LittleEndian, self.Checksum)
//    copy(ret[8:12], w.Bytes()[:4])
//
//    binary.LittleEndian.PutUint32(ret[12:], self.SeqNum)
//    return ret
//}
//
//type MessageSignatureExt struct {
//    Version     uint32
//    Checksum    []byte `smb:"fixed:8"`
//    SeqNum      uint32
//}
//
//func (self *MessageSignatureExt) Bytes() []byte {
//    ret := make([]byte, 16)
//    binary.LittleEndian.PutUint32(ret, 0x00000001) // Must always be 1
//
//    w := bytes.NewBuffer(make([]byte, 0))
//    binary.Write(w, binary.LittleEndian, self.Checksum)
//    copy(ret[4:12], w.Bytes()[:8])
//
//    binary.LittleEndian.PutUint32(ret[12:], self.SeqNum)
//    return ret
//}

type AvPair struct {
	AvID  uint16
	AvLen uint16 `smb:"len:Value"`
	Value []byte
}
type AvPairSlice []AvPair

func (p AvPair) Size() uint64 {
	return uint64(binary.Size(p.AvID) + binary.Size(p.AvLen) + int(p.AvLen))
}

func (s *AvPairSlice) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, pair := range *s {
		buf, err := encoder.Marshal(pair)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *AvPairSlice) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	slice := []AvPair{}
	l, ok := meta.Lens[meta.CurrField]
	if !ok {
		return errors.New(fmt.Sprintf("Cannot unmarshal field '%s'. Missing length\n", meta.CurrField))
	}
	o, ok := meta.Offsets[meta.CurrField]
	if !ok {
		return errors.New(fmt.Sprintf("Cannot unmarshal field '%s'. Missing offset\n", meta.CurrField))
	}
	for i := l; i > 0; {
		var avPair AvPair
		err := encoder.Unmarshal(meta.ParentBuf[o:o+i], &avPair)
		if err != nil {
			return err
		}
		slice = append(slice, avPair)
		size := avPair.Size()
		o += size
		i -= size
	}
	*s = slice
	return nil
}
