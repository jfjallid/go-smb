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

	"github.com/jfjallid/go-smb/smb"
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
