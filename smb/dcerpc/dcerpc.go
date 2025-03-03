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
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/golog"
)

var (
	MSRPCUuidNdr                  = "8a885d04-1ceb-11c9-9fe8-08002b104860" // NDR Transfer Syntax version 2.0
	re           regexp.Regexp    = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)
	le           binary.ByteOrder = binary.LittleEndian
	log                           = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc")
)

// MSRPC Packet header common fields
const PDUHeaderCommonSize int = 16

// MSRPC Packet Types
const (
	PacketTypeRequest  uint8 = 0
	PacketTypeResponse uint8 = 2
	PacketTypeFault    uint8 = 3
	PacketTypeBind     uint8 = 11
	PacketTypeBindAck  uint8 = 12
)

// C706 Section 12.6.3.1 PFC Flags
const (
	PfcFirstFrag     uint8 = 0x1
	PfcLastFrag      uint8 = 0x2
	PfcPendingCancel uint8 = 0x4 // Cancel was pending at sender
	PfcReserved      uint8 = 0x8
	PfcConcMpx       uint8 = 0x10 // Support concurrent multiplexing of a single connection
	PfcDidNotExecute uint8 = 0x20
	PfcMaybe         uint8 = 0x40
	PfcObjectUUID    uint8 = 0x80
)

// Unused
//type RPCClient interface {
//	Bind(interface_uuid, transfer_uuid string) (bool, error)
//	//Write()
//}

type ServiceBind struct {
	// callId always contains the last used value, so call Add(1) first
	callId *atomic.Uint32 // Use it with callId.Add(1)
	f      *smb.File
	// Currently unused, but should probably be respected at some point
	maxFragTransmitSize uint16 // Max size of fragment the server accepts
	// Currently unused, but should probably be validated at some point
	maxFragReceiveSize uint16 // Max size of fragment server should send
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
	Count          byte // Determined by number of items in TransferSyntax list
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
	// Auth verifier? An optional field if AuthLength is != 0
	// Haven't implemented any support for that
}

// C706 Section 12.6.3.1 p_const_def_result_t enum
type resultType uint16

const (
	acceptance        resultType = iota // 0
	userRejection                       // 1
	providerRejection                   // 2
)

// C706 Section 12.6.3.1 p_provider_reason_t enum
type providerReason uint16

const (
	reasonNotSpecified                 providerReason = iota // 0
	abstractSyntaxNotSupported                               // 1
	proposedTransferSyntaxNotSupported                       // 2
	localLimitExceeded                                       // 3
)

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
	// Auth verifier? An optional field if AuthLength != 0
}

// C706 Section 12.6.4.9
type RequestReq struct { // 24 + optional fields + len of Buffer
	Header // 16 bytes
	// AllocHint is an optional field useful for hinting required space when
	// sending fragmented requests
	AllocHint uint32
	ContextId uint16 // Data representation
	Opnum     uint16
	// Optional field object uuid_t
	// Only present if PfcObjectUUID is set in the header flags
	Buffer []byte
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

func (self *Header) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)

	_, err = w.Write([]byte{self.MajorVersion, self.MinorVersion, self.Type, self.Flags})
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Representation)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.FragLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.AuthLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.CallId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *Header) UnmarshalBinary(buf []byte) (err error) {
	if len(buf) < 16 {
		return fmt.Errorf("Buffer is too small to unmarshal Header")
	}
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.MajorVersion)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.MinorVersion)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Type)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Flags)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Representation)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.FragLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.AuthLength)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.CallId)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *ContextItem) MarshalBinary() (ret []byte, err error) {
	log.Debugln("In MarshalBinary for ContextItem")
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, self.Id)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, byte(len(self.TransferSyntax)))
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, byte(0)) // Alignment
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.AbstractSyntax.UUID)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.AbstractSyntax.Version)
	if err != nil {
		log.Errorln(err)
		return
	}
	for i := range self.TransferSyntax {
		err = binary.Write(w, le, self.TransferSyntax[i].UUID)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, self.TransferSyntax[i].Version)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return w.Bytes(), nil
}

func readContextItem(r *bytes.Reader, bo binary.ByteOrder) (res *ContextItem, err error) {
	log.Debugln("In readContextItem")
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

func (self *ContextItem) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for ContextItem")
	r := bytes.NewReader(buf)

	self, err = readContextItem(r, le)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (self *ContextList) MarshalBinary() (ret []byte, err error) {
	log.Debugln("In MarshalBinary for ContextList")
	w := bytes.NewBuffer(ret)
	err = binary.Write(w, le, byte(len(self.Items)))
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
	for i := range self.Items {
		itemBuf, err = self.Items[i].MarshalBinary()
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

func (self *ContextList) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for ContextList")
	r := bytes.NewReader(buf)

	err = binary.Read(r, le, &self.Count)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = r.Seek(3, io.SeekCurrent) // Skip alignment bytes
	if err != nil {
		log.Errorln(err)
		return
	}

	for i := 0; i < int(self.Count); i++ {
		item := &ContextItem{}
		item, err = readContextItem(r, le)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Items = append(self.Items, *item)
	}

	return nil
}

func (self *BindReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	log.Debugln("In MarshalBinary for BindReq")

	// Encode Header
	hBuf, err := self.Header.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(hBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.MaxSendFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.MaxRecvFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Association)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Encode Context Item list
	contextBuf := []byte{}
	contextBuf, err = self.ContextList.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(contextBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *BindReq) UnmarshalBinary(buf []byte) (err error) {
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

func (self *ContextResList) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for ContextResList")
	r := bytes.NewReader(buf)

	self, err = readContextResList(r, le)
	return nil
}

func (self *BindRes) MarshalBinary() (ret []byte, err error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for BindRes")
}

func (self *BindRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for BindRes")
	err = self.Header.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip over header bytes
	r := bytes.NewReader(buf[16:])
	err = binary.Read(r, le, &self.MaxSendFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.MaxRecvFragSize)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.Association)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.SecAddrLen)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.SecAddr = make([]byte, self.SecAddrLen)
	err = binary.Read(r, le, &self.SecAddr)
	if err != nil {
		log.Errorln(err)
		return
	}

	alignmentBytes := 4 - ((self.SecAddrLen + 2) % 4)
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
	self.ResultList = *resList
	return
}

func (self *RequestReq) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	log.Debugln("In MarshalBinary for RequestReq")

	// Encode Header
	hBuf, err := self.Header.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(hBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, uint32(len(self.Buffer))) // AllocHint
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Write(w, le, self.ContextId)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.Opnum)
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(self.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	return w.Bytes(), nil
}

func (self *RequestReq) UnmarshalBinary(buf []byte) (err error) {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of RequestReq")
}

func (self *RequestRes) MarshalBinary() (ret []byte, err error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for RequestRes")
}

func (self *RequestRes) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for RequestRes")
	err = self.Header.UnmarshalBinary(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	if len(buf[16:]) < (int(self.Header.FragLength) - 24) {
		return fmt.Errorf("Provided buffer is too small to unmarshal a RequestRes")
	}
	// Skip over header bytes
	r := bytes.NewReader(buf[16:])
	err = binary.Read(r, le, &self.AllocHint)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ContextId)
	if err != nil {
		log.Errorln(err)
		return
	}
	self.CancelCount, err = r.ReadByte()
	if err != nil {
		log.Errorln(err)
		return
	}
	self.Reserved, err = r.ReadByte()
	if err != nil {
		log.Errorln(err)
		return
	}
	self.Buffer = make([]byte, self.Header.FragLength-24)
	_, err = r.Read(self.Buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func newHeader() Header {
	return Header{
		MajorVersion: 5,
		MinorVersion: 0,
		Type:         0,
		Flags:        PfcFirstFrag | PfcLastFrag,
		// At some point it might be worth to implement support for other
		// representations such as Big-Endian
		Representation: 0x00000010, // 0x10000000, // Little-endian, char = ASCII, float = IEEE
		FragLength:     72,         // Always 72
		AuthLength:     0,
		CallId:         0,
	}
}

func uuid_to_bin(uuid string) ([]byte, error) {
	//log.Debugln("In uuid_to_bin")

	if !strings.ContainsRune(uuid, '-') {
		return hex.DecodeString(uuid)
	}

	// Assume Variant 2 UUID
	matches := re.FindAllStringSubmatch(uuid, -1)
	if (len(matches) == 0) || (len(matches[0]) != 7) {
		return nil, fmt.Errorf("Failed to parse UUID v2 string")
	}
	uuid1, uuid2, uuid3, uuid4, uuid5, uuid6 := matches[0][1], matches[0][2], matches[0][3], matches[0][4], matches[0][5], matches[0][6]
	buf := make([]byte, 0)
	n, err := strconv.ParseUint(uuid1, 16, 32)
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint32(buf, uint32(n))
	n, err = strconv.ParseUint(uuid2, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid3, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.LittleEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid4, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid5, 16, 16)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint16(buf, uint16(n))
	n, err = strconv.ParseUint(uuid6, 16, 32)
	if err != nil {
		return nil, err
	}

	buf = binary.BigEndian.AppendUint32(buf, uint32(n))

	return buf, nil
}

func newBindReq(callId uint32, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string, maxTransmitSize, maxRecvSize uint16) (req *BindReq, err error) {
	log.Debugln("In newBindReq")

	srsv_uuid, err := uuid_to_bin(interface_uuid)
	if err != nil {
		log.Errorln(err)
		return
	}
	ndr_uuid, err := uuid_to_bin(transfer_uuid)
	if err != nil {
		log.Errorln(err)
		return
	}
	header := newHeader()
	header.Type = PacketTypeBind
	header.CallId = callId
	ctxItem := ContextItem{
		Id:    0,
		Count: 1,
		AbstractSyntax: SyntaxId{
			UUID:    srsv_uuid,
			Version: (uint32(minorVersion) << 16) | uint32(majorVersion),
		},
		TransferSyntax: []SyntaxId{
			SyntaxId{
				UUID:    ndr_uuid,
				Version: 2,
			},
		},
	}
	ctxList := ContextList{
		Count: 1,
		Items: []ContextItem{ctxItem},
	}
	req = &BindReq{
		Header:          header,
		MaxSendFragSize: maxTransmitSize,
		MaxRecvFragSize: maxRecvSize,
		Association:     0,
		ContextList:     ctxList,
	}
	return
}

func newRequestReq(callId uint32, op uint16) (*RequestReq, error) {
	header := newHeader()
	header.Type = PacketTypeRequest
	header.CallId = callId

	return &RequestReq{
		Header:    header,
		AllocHint: 0,
		ContextId: 0,
		Opnum:     op,
	}, nil
}

func Bind(f *smb.File, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string) (bind *ServiceBind, err error) {
	log.Debugln("In Bind")
	// Sanity check
	if f == nil {
		return nil, fmt.Errorf("File argument cannot be nil")
	}
	if !f.IsOpen() {
		return nil, fmt.Errorf("File must be opened before calling Bind")
	}
	callId := atomic.Uint32{}
	maxFragRxSize := uint16(4280)
	maxFragTxSize := uint16(4280)
	bindReq, err := newBindReq(callId.Add(1), interface_uuid, majorVersion, minorVersion, transfer_uuid, maxFragTxSize, maxFragRxSize)
	if err != nil {
		return
	}

	buf, err := bindReq.MarshalBinary()
	if err != nil {
		return
	}

	ioCtlReq, err := f.NewIoCTLReq(smb.FsctlPipeTransceive, buf)
	if err != nil {
		return
	}

	ioCtlRes, err := f.WriteIoCtlReq(ioCtlReq)
	if err != nil {
		return
	}

	var bindRes BindRes
	err = bindRes.UnmarshalBinary(ioCtlRes.Buffer)
	if err != nil {
		return
	}

	// Check if Bind was successful
	if bindRes.CallId != bindReq.CallId {
		return nil, fmt.Errorf("Received invalid callId: %d\n", bindRes.CallId)
	}
	if bindRes.Type != PacketTypeBindAck {
		return nil, fmt.Errorf("Invalid response from server: %v\n", bindRes)
	}
	if len(bindRes.ResultList.Items) == 0 {
		return nil, fmt.Errorf("Invalid response from server with no Context Items: %v\n", bindRes.ResultList)
	}
	// Perhaps add support for handling multiple Context Items in the result?
	if bindRes.ResultList.Items[0].Result != acceptance {
		errMsg := ""
		switch bindRes.ResultList.Items[0].Reason {
		case reasonNotSpecified:
			errMsg = "Reason not specified"
		case abstractSyntaxNotSupported:
			errMsg = "Abstract syntax not supported"
		case proposedTransferSyntaxNotSupported:
			errMsg = "Proposed transfer syntax not supported"
		case localLimitExceeded:
			errMsg = "Local limit exceeded"
		default:
			errMsg = fmt.Sprintf("Unknown reason: %d\n", bindRes.ResultList.Items[0].Reason)
		}
		return nil, fmt.Errorf("Server did not approve bind request with reason: \"%s\"\n", errMsg)
	}

	return &ServiceBind{
		callId:              &callId,
		f:                   f,
		maxFragReceiveSize:  bindRes.MaxSendFragSize,
		maxFragTransmitSize: bindRes.MaxRecvFragSize,
	}, nil
}

func (sb *ServiceBind) MakeIoCtlRequest(opcode uint16, innerBuf []byte) (result []byte, err error) {
	callId := sb.callId.Add(1)
	fragmentedResponse := false

	for {
		var resHeader Header
		var responseBuffer []byte
		if !fragmentedResponse {
			var req *RequestReq
			req, err = newRequestReq(callId, opcode)
			if err != nil {
				log.Errorln(err)
				return
			}

			req.Buffer = make([]byte, len(innerBuf))
			copy(req.Buffer, innerBuf)
			req.FragLength = uint16(len(innerBuf) + 24) // Includes header size

			// Encode DCERPC Request
			var buf []byte
			buf, err = req.MarshalBinary()
			if err != nil {
				log.Errorln(err)
				return
			}

			var ioCtlReq *smb.IoCtlReq
			ioCtlReq, err = sb.f.NewIoCTLReq(smb.FsctlPipeTransceive, buf)
			if err != nil {
				log.Errorln(err)
				return
			}

			//NOTE Might be a problem with exceeding a max payload size of 65536 for
			// servers that do not support multi-credit requests
			var ioCtlRes smb.IoCtlRes
			// Send DCERPC request inside SMB IoCTL Request
			ioCtlRes, err = sb.f.WriteIoCtlReq(ioCtlReq)
			if err != nil {
				log.Errorln(err)
				return
			}
			responseBuffer = ioCtlRes.Buffer
		} else {
			var n int
			responseBuffer = make([]byte, sb.maxFragReceiveSize+16) // 16 bytes overhead of read request
			n, err = sb.f.ReadFile(responseBuffer, 0)
			if err != nil {
				log.Errorln(err)
				return
			}
			responseBuffer = responseBuffer[:n]
		}

		if len(responseBuffer) < PDUHeaderCommonSize {
			err = fmt.Errorf("Read/IoCtl response on DCERPC fragment was smaller than the DCERPC header size")
			log.Errorln(err)
			return
		}

		// Unmarshal DCERPC Request response
		err = resHeader.UnmarshalBinary(responseBuffer[:PDUHeaderCommonSize])
		if err != nil {
			log.Errorln(err)
			return
		}

		if resHeader.CallId != callId {
			err = fmt.Errorf("Incorrect CallId on response. Sent %d and received %d\n", callId, resHeader.CallId)
			log.Errorln(err)
			return
		}

		if resHeader.Type == PacketTypeFault {
			if len(responseBuffer) >= (PDUHeaderCommonSize + 12) {
				status := binary.LittleEndian.Uint32(responseBuffer[:PDUHeaderCommonSize+8])
				err = fmt.Errorf("DCERPC Fault PDU received with status: %d", status)
			} else {
				err = fmt.Errorf("DCERPC Fault PDU received but incomplete: %+v, full buffer: %x", resHeader, responseBuffer)
			}
			log.Errorln(err)
			return
		} else if resHeader.Type != PacketTypeResponse {
			err = fmt.Errorf("DCERPC Unexpected PDU received with type: %d", resHeader.Type)
			log.Errorln(err)
			return
		}

		if len(responseBuffer) < int(resHeader.FragLength) {
			err = fmt.Errorf("DCERPC response fragment is less that specified fragment lengh. Received %d bytes from ReadRequest, but FragLength field specifies %d bytes!", len(responseBuffer), resHeader.FragLength)
			log.Errorln(err)
			return
		}

		// Time to unpack the Response PDU
		var reqRes RequestRes
		err = reqRes.UnmarshalBinary(responseBuffer)
		if err != nil {
			log.Errorln(err)
			return
		}
		result = append(result, reqRes.Buffer...)
		if (reqRes.Flags & PfcLastFrag) == PfcLastFrag {
			break
		}

		fragmentedResponse = true
		// Request the next fragment
	}

	return
}
