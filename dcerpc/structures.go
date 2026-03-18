// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
//
// The marshal/unmarshal of request and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit cumbersome
// to implement new features but for now that seems preferable to implementing
// a generic NDR encoder/decoder.

package dcerpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"
)

type ServiceBind struct {
	// callId always contains the last used value, so call Add(1) first
	callId    *atomic.Uint32 // Use it with callId.Add(1)
	transport DCERPCTransport
	// Presentation context ID for this binding (0 for initial bind)
	contextId uint16
	// Max size of fragment the server accepts
	maxFragTransmitSize uint16
	// Max size of fragment server should send
	maxFragReceiveSize uint16
	// Auth state (set by BindAuth, zero for unauthenticated Bind)
	authType      uint8
	authLevel     uint8
	authContextId uint32
	sealer        Sealer // non-nil when authLevel >= PktIntegrity
	// Next presentation context ID for AlterContext (shared across clones)
	nextContextId *uint16
}

// AuthVerifier represents the auth_verifier structure appended to DCERPC PDUs
// when authentication is used (MS-RPCE 2.2.2.11).
type AuthVerifier struct {
	AuthType      uint8
	AuthLevel     uint8
	AuthPadLength uint8
	AuthReserved  uint8  // Must be 0
	AuthContextId uint32
	AuthValue     []byte
}

func (s *AuthVerifier) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.AuthType)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.AuthLevel)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.AuthPadLength)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.AuthReserved)
	if err != nil {
		return
	}
	err = binary.Write(w, le, s.AuthContextId)
	if err != nil {
		return
	}
	_, err = w.Write(s.AuthValue)
	if err != nil {
		return
	}
	return w.Bytes(), nil
}

func (s *AuthVerifier) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 8 {
		return fmt.Errorf("Buffer is too small to unmarshal AuthVerifier")
	}
	r := bytes.NewReader(buf)
	err = binary.Read(r, le, &s.AuthType)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.AuthLevel)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.AuthPadLength)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.AuthReserved)
	if err != nil {
		return
	}
	err = binary.Read(r, le, &s.AuthContextId)
	if err != nil {
		return
	}
	remaining := len(buf) - 8
	if remaining > 0 {
		s.AuthValue = make([]byte, remaining)
		_, err = r.Read(s.AuthValue)
		if err != nil {
			return
		}
	}
	return
}

// Defined in C706 (DCE 1.1: Remote Procedure Call) section 12.6.3.1 as "common fields"
type Header struct {
	MajorVersion   byte // rpc_vers
	MinorVersion   byte // rpc_vers_minor
	Type           byte
	Flags          byte
	Representation uint32 // NDR data representation
	FragLength     uint16
	AuthLength     uint16
	CallId         uint32
}

type SyntaxId struct {
	UUID []byte // 16 bytes
	// Major version is encoded in the 16 least significant bits
	// Minor version is encoded in the 16 most significant bits
	Version uint32
}

/*
C706 Section 12.6.3.1

	typedef struct {
	  p_context_id_t p_cont_id;
	  u_int8 n_transfer_syn;               // number of items
	  u_int8 reserved;                     // alignment pad, m.b.z.
	  p_syntax_id_t abstract_syntax;       // transfer syntax list
	  p_syntax_id_t [size_is(n_transfer_syn)] transfer_syntaxes[];
	} p_cont_elem_t;
*/
type ContextItem struct {
	Id             uint16
	Count          byte // Used only for unmarshal; marshal computes from len(TransferSyntax)
	Reserved       byte // Alignment
	AbstractSyntax SyntaxId
	TransferSyntax []SyntaxId
}

/*
C706 Section 12.6.3.1

	typedef struct {
	  u_int8 n_context_elem;               // number of items
	  u_int8 reserved;                     // alignment pad, m.b.z.
	  u_short reserved2;                   // alignment pad, m.b.z.
	  p_cont_elem_t [size_is(n_cont_elem)] p_cont_elem[];
	} p_cont_list_t;
*/
type ContextList struct {
	Count     byte
	Reserved  byte   // Alignment
	Reserved2 uint16 // Alignment
	Items     []ContextItem
}

// C706 Section 12.6.4.3
type BindReq struct {
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32      // A value of 0 means a request for a new Association group
	ContextList     ContextList // p_cont_list_t
	AuthVerifier    *AuthVerifier // Optional, present when AuthLength != 0
}

/*
C706 12.6.3.1

	typedef struct {
	  p_cont_def_result_t result;
	  p_provider_reason_t reason; // only relevant if result != acceptance
	  p_syntax_id_t transfer_syntax; // tr syntax selected 0 if result not accepted
	} p_result_t;
*/
type ContextResItem struct {
	Result         resultType
	Reason         providerReason
	TransferSyntax SyntaxId
}

/*
C706 12.6.3.1

	typedef struct {
	  u_int8 n_results;        // count
	  u_int8 reserved;         // alignment pad, m.b.z.
	  u_int16 reserved2;       // alignment pad, m.b.z.
	  p_result_t [size_is(n_results)] p_results[];
	} p_result_list_t;
*/
type ContextResList struct {
	Results   byte   // Count of ContextResItem list
	Reserved  byte   // Alignment
	Reserved2 uint16 // Alignment
	Items     []ContextResItem
}

// C706 Section 12.6.4.4 (bind_ack)
type BindRes struct {
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32
	SecAddrLen      uint16
	SecAddr         []byte
	ResultList      ContextResList
	AuthVerifier    *AuthVerifier // Parsed when Header.AuthLength > 0
}

// Auth3Req represents the Auth3 PDU type (MS-RPCE 2.2.2.3).
// Not currently used — BindAuth uses AlterContext for the 3rd leg instead.
// Kept for reference; the server does not send a response to this PDU type.
type Auth3Req struct {
	Header                       // Type = PacketTypeAuth3
	MaxSendFragSize uint16       // Pad field (same layout as Bind)
	MaxRecvFragSize uint16       // Pad field
	AuthVerifier    AuthVerifier // Required
}

func (s *Auth3Req) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(hBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.MaxSendFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.MaxRecvFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Auth3 body is just the pad fields (4 bytes), no auth padding needed
	var authBuf []byte
	authBuf, err = s.AuthVerifier.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(authBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

// C706 Section 12.6.4.9
type RequestReq struct { // 24 + optional ObjectUUID (16) + len of Buffer
	Header // 16 bytes
	// AllocHint is an optional field useful for hinting required space when
	// sending fragmented requests
	AllocHint uint32
	ContextId uint16 // Data representation
	Opnum     uint16
	// Optional field object uuid_t (16 bytes)
	// Only present if PfcObjectUUID is set in the header flags
	ObjectUUID []byte
	Buffer     []byte
	// Auth verifier? An optional field if AuthLength != 0
}

// C706 Section 12.6.4.10
type RequestRes struct {
	Header // 16 bytes
	// This optional field AllocHint is used to hint about how much
	// contiguous space to allocate for fragmented requests.
	AllocHint   uint32
	ContextId   uint16
	CancelCount byte
	Reserved    byte
	Buffer      []byte
	// Auth verifier? An optional field if AuthLength != 0
}

func (s *Header) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	_, err = w.Write([]byte{s.MajorVersion, s.MinorVersion, s.Type, s.Flags})
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.Representation)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.FragLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.AuthLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.CallId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *Header) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 16 {
		return fmt.Errorf("Buffer is too small to unmarshal Header")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.MajorVersion)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.MinorVersion)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Type)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Flags)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Representation)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.FragLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.AuthLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.CallId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (s *ContextItem) MarshalBinary() (ret []byte, err error) {
	log.Traceln("In MarshalBinary for ContextItem")
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, s.Id)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, byte(len(s.TransferSyntax)))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, byte(0)) // Alignment
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.AbstractSyntax.UUID)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.AbstractSyntax.Version)
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := range s.TransferSyntax {
		err = binary.Write(w, le, s.TransferSyntax[i].UUID)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, s.TransferSyntax[i].Version)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func readContextItem(r *bytes.Reader, bo binary.ByteOrder) (res *ContextItem, err error) {
	log.Traceln("In readContextItem")
	res = &ContextItem{}
	err = binary.Read(r, bo, &res.Id)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, bo, &res.Count)
	if err != nil {
		log.Errorln(err)
		return
	}

	_, err = r.ReadByte() // Skip reserved
	if err != nil {
		log.Errorln(err)
		return
	}

	res.AbstractSyntax.UUID = make([]byte, 16)
	_, err = r.Read(res.AbstractSyntax.UUID)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, bo, &res.AbstractSyntax.Version)
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(res.Count); i++ {
		syntaxId := SyntaxId{UUID: make([]byte, 16)}
		_, err = r.Read(syntaxId.UUID)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, bo, &syntaxId.Version)
		if err != nil {
			log.Errorln(err)
			return
		}
		res.TransferSyntax = append(res.TransferSyntax, syntaxId)
	}
	return
}

func (s *ContextItem) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for ContextItem")
	r := bytes.NewReader(buf)

	result, err := readContextItem(r, le)
	if err != nil {
		log.Errorln(err)
		return
	}
	*s = *result
	return
}

func (s *ContextList) MarshalBinary() (ret []byte, err error) {
	log.Traceln("In MarshalBinary for ContextList")
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, byte(len(s.Items)))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, []byte{0, 0, 0}) // Alignment
	if err != nil {
		log.Errorln(err)
		return
	}
	var itemBuf []byte
	for i := range s.Items {
		itemBuf, err = s.Items[i].MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}
		_, err = w.Write(itemBuf)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return w.Bytes(), nil
}

func (s *ContextList) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for ContextList")
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &s.Count)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = r.Seek(3, io.SeekCurrent) // Skip alignment bytes
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(s.Count); i++ {
		item := &ContextItem{}
		item, err = readContextItem(r, le)
		if err != nil {
			log.Errorln(err)
			return
		}
		s.Items = append(s.Items, *item)
	}

	return nil
}

func (s *BindReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	log.Traceln("In MarshalBinary for BindReq")

	// Encode Header
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(hBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.MaxSendFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.MaxRecvFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.Association)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode Context Item list
	contextBuf := []byte{}
	contextBuf, err = s.ContextList.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(contextBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.AuthVerifier != nil {
		// Compute auth padding to align to 4-byte boundary
		bodyLen := w.Len()
		authPad := (4 - (bodyLen % 4)) % 4
		if authPad > 0 {
			_, err = w.Write(make([]byte, authPad))
			if err != nil {
				log.Errorln(err)
				return
			}
		}
		s.AuthVerifier.AuthPadLength = uint8(authPad)

		var authBuf []byte
		authBuf, err = s.AuthVerifier.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}
		_, err = w.Write(authBuf)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func (s *BindReq) UnmarshalBinary(buf []byte) (err error) {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of BindReq")
}

func readContextResItem(r *bytes.Reader, bo binary.ByteOrder) (res *ContextResItem, err error) {
	res = &ContextResItem{}
	err = binary.Read(r, le, &res.Result)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &res.Reason)
	if err != nil {
		log.Errorln(err)
		return
	}
	res.TransferSyntax.UUID = make([]byte, 16)
	err = binary.Read(r, le, &res.TransferSyntax.UUID)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &res.TransferSyntax.Version)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func readContextResList(r *bytes.Reader, bo binary.ByteOrder) (res *ContextResList, err error) {
	res = &ContextResList{}
	res.Results, err = r.ReadByte()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = r.Seek(3, io.SeekCurrent) // Skip alignment bytes
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := 0; i < int(res.Results); i++ {
		item := &ContextResItem{}
		item, err = readContextResItem(r, bo)
		if err != nil {
			log.Errorln(err)
			return
		}
		res.Items = append(res.Items, *item)
	}

	return
}

func (s *ContextResList) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for ContextResList")
	r := bytes.NewReader(buf)

	result, err := readContextResList(r, le)
	if err != nil {
		log.Errorln(err)
		return
	}
	*s = *result
	return
}

func (s *BindRes) MarshalBinary() (ret []byte, err error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BindRes")
}

func (s *BindRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for BindRes")
	err = s.Header.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip over header bytes
	r := bytes.NewReader(buf[16:])
	err = binary.Read(r, le, &s.MaxSendFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.MaxRecvFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.Association)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.SecAddrLen)
	if err != nil {
		log.Errorln(err)
		return
	}
	s.SecAddr = make([]byte, s.SecAddrLen)
	err = binary.Read(r, le, &s.SecAddr)
	if err != nil {
		log.Errorln(err)
		return
	}

	// From IDL:
	// u_int8 [size_is(align(4))] pad2
	// align(4) can be 0 if we are at the 4 byte boundary
	alignmentBytes := (4 - ((s.SecAddrLen + 2) % 4)) % 4
	_, err = r.Seek(int64(alignmentBytes), io.SeekCurrent) // Align to 4-byte boundary
	if err != nil {
		log.Errorln(err)
		return
	}

	resList := &ContextResList{}
	resList, err = readContextResList(r, le)
	if err != nil {
		log.Errorln(err)
		return
	}
	s.ResultList = *resList

	// Parse AuthVerifier if present
	if s.Header.AuthLength > 0 {
		// The auth verifier is at the end of the PDU: last AuthLength + 8 bytes
		// (8 bytes = auth verifier header: AuthType, AuthLevel, AuthPadLength, AuthReserved, AuthContextId)
		authTotalLen := int(s.Header.AuthLength) + 8
		if int(s.Header.FragLength) >= authTotalLen {
			authStart := int(s.Header.FragLength) - authTotalLen
			s.AuthVerifier = &AuthVerifier{}
			err = s.AuthVerifier.UnmarshalBinary(buf[authStart:s.Header.FragLength])
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	}
	return
}

func (s *RequestReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	log.Traceln("In MarshalBinary for RequestReq")

	// Encode Header
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(hBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.AllocHint)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, s.ContextId)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, s.Opnum)
	if err != nil {
		log.Errorln(err)
		return
	}
	if len(s.ObjectUUID) > 0 {
		_, err = w.Write(s.ObjectUUID)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	_, err = w.Write(s.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (s *RequestReq) UnmarshalBinary(buf []byte) (err error) {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RequestReq")
}

func (s *RequestRes) MarshalBinary() (ret []byte, err error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for RequestRes")
}

func (s *RequestRes) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for RequestRes")
	err = s.Header.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	if len(buf[16:]) < (int(s.Header.FragLength) - 24) {
		return fmt.Errorf("Provided buffer is too small to unmarshal a RequestRes")
	}
	// Skip over header bytes
	r := bytes.NewReader(buf[16:])
	err = binary.Read(r, le, &s.AllocHint)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &s.ContextId)
	if err != nil {
		log.Errorln(err)
		return
	}
	s.CancelCount, err = r.ReadByte()
	if err != nil {
		log.Errorln(err)
		return
	}
	s.Reserved, err = r.ReadByte()
	if err != nil {
		log.Errorln(err)
		return
	}
	s.Buffer = make([]byte, s.Header.FragLength-24)
	_, err = r.Read(s.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}
