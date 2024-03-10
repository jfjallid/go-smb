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
// The marshal/unmarshal of requerst and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit cumbersome
// to implement new features, so at some point a major rewrite should be
// performed to ideally handle the NDR syntax dynamically.

package dcerpc

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc")

var (
	MSRPCSvcCtlPipe                          = "svcctl"
	MSRPCUuidSvcCtl                          = "367ABB81-9844-35F1-AD32-98F038001003"
	MSRPCSvcCtlMajorVersion uint16           = 2
	MSRPCSvcCtlMinorVersion uint16           = 0
	MSRPCUuidSrvSvc                          = "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	MSRPCSrvSvcMajorVersion uint16           = 3
	MSRPCSrvSvcMinorVersion uint16           = 0
	MSRPCUuidNdr                             = "8a885d04-1ceb-11c9-9fe8-08002b104860" // NDR Transfer Syntax version 2.0
	re                      regexp.Regexp    = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)
	ContextItemLen                           = 44
	ContextResItemLen                        = 24
	le                      binary.ByteOrder = binary.LittleEndian
)

// MSRPC Packet Types
const (
	PacketTypeRequest  uint8 = 0
	PacketTypeResponse uint8 = 2
	PacketTypeBind     uint8 = 11
	PacketTypeBindAck  uint8 = 12
)

// Unused
//type RPCClient interface {
//	Bind(interface_uuid, transfer_uuid string) (bool, error)
//	//Write()
//}

type ServiceBind struct {
	f *smb.File
}

type Header struct { // 16 bytes
	MajorVersion   byte
	MinorVersion   byte
	Type           byte
	Flags          byte
	Representation uint32
	FragLength     uint16
	AuthLength     uint16
	CallId         uint32
}

func newHeader() Header {
	return Header{
		MajorVersion:   5,
		MinorVersion:   0,
		Type:           0,
		Flags:          0x01 | 0x02,
		Representation: 0x00000010, // 0x10000000, // Little-endian, char = ASCII, float = IEEE
		FragLength:     72,         // Always 72
		AuthLength:     0,
		CallId:         0,
	}
}

type ContextItem struct { // 44 bytes size
	Id               uint16
	Count            byte
	Reserved         byte
	AbstractUUID     []byte `smb:"fixed:16"`
	BindMajorVersion uint16
	BindMinVersion   uint16
	TransferUUID     []byte `smb:"fixed:16"`
	TransferVersion  uint32
}

type ContextResItem struct { // 24 bytes size
	Result          uint32 // Perhaps only uint16 with 2 bytes padding after?
	TransferUUID    []byte `smb:"fixed:16"`
	TransferVersion uint32
}

type ContextItems []ContextItem
type ContextResItems []ContextResItem

type BindReq struct { // 28 bytes before Context list
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32
	CtxCount        byte   `smb:"count:Context"`
	Reserved        byte   // Alignment
	Reserved2       uint16 // Alignment
	Context         *ContextItems
}

type BindRes struct { // 28 bytes before Context list
	Header          // 16 Bytes
	MaxSendFragSize uint16
	MaxRecvFragSize uint16
	Association     uint32
	SecAddrLen      uint16 `smb:"len:SecAddr"`
	SecAddr         []byte
	Align           []byte `smb:"align:4"`
	CtxCount        byte   `smb:"count:Context"`
	Reserved        byte   // Alignment
	Reserved2       uint16 // Alignment
	Context         *ContextResItems
}

type RequestReq struct { // 24 + len of Buffer
	Header    // 16 bytes
	AllocHint uint32
	ContextId uint16
	Opnum     uint16
	Buffer    []byte // Always start at an 8-byte boundary
}

type RequestRes struct {
	Header             // 16 bytes
	AllocHint   uint32 `smb:"len:Buffer"` // Not sure this field is guaranteed to contain buffer length
	ContextId   uint16
	CancelCount byte
	Reserved    byte
	Buffer      []byte // Always start at an 8-byte boundary
}

type UnicodeStr struct {
	ReferentIdPtr uint32 `smb:"omitempty:0"`
	MaxCount      uint32
	Offset        uint32 // Defaults to 0
	ActualCount   uint32
	EncodedString []byte //utf16le encoded string
	Padd          []byte `smb:"align:4"`
}

func (s *ContextItems) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	//log.Debugln("In MarshalBinary for ContextItems")
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, item := range *s {
		buf, err := encoder.Marshal(item)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *ContextItems) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	//log.Debugln("In UnmarshalBinary for ContextItems")

	slice := []ContextItem{}
	c, ok := meta.Counts[meta.CurrField]
	if !ok {
		return fmt.Errorf("Cannot unmarshal field '%s'. Missing count\n", meta.CurrField)
	}
	for i := 0; i < int(c); i++ {
		var item ContextItem
		err := encoder.Unmarshal(buf[i*ContextItemLen:(i+1)*ContextItemLen], &item)
		if err != nil {
			return err
		}
		slice = append(slice, item)
	}

	*s = slice
	return nil
}

func (s *ContextResItems) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for ContextResItems")
	var ret []byte
	w := bytes.NewBuffer(ret)
	for _, item := range *s {
		buf, err := encoder.Marshal(item)
		if err != nil {
			return nil, err
		}
		if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
			return nil, err
		}
	}
	return w.Bytes(), nil
}

func (s *ContextResItems) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for ContextResItems")

	slice := []ContextResItem{}
	c, ok := meta.Counts[meta.CurrField]
	if !ok {
		return fmt.Errorf("Cannot unmarshal field '%s'. Missing count\n", meta.CurrField)
	}
	for i := 0; i < int(c); i++ {
		var item ContextResItem
		err := encoder.Unmarshal(buf[i*ContextResItemLen:(i+1)*ContextResItemLen], &item)
		if err != nil {
			return err
		}
		slice = append(slice, item)
	}

	res := ContextResItems(slice)
	*s = res
	return nil
}

func (self *ContextItem) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for ContextItem")
	buf := make([]byte, 0, 43)
	buf = binary.LittleEndian.AppendUint16(buf, self.Id)
	buf = append(buf, self.Count)
	buf = append(buf, self.AbstractUUID...)
	buf = binary.LittleEndian.AppendUint16(buf, self.BindMajorVersion)
	buf = binary.LittleEndian.AppendUint16(buf, self.BindMinVersion)
	buf = append(buf, self.TransferUUID...)
	buf = binary.LittleEndian.AppendUint32(buf, self.TransferVersion)
	return buf, nil
}

func (self *ContextItem) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Debugln("In UnmarshalBinary for ContextItem")
	self.Id = binary.LittleEndian.Uint16(buf)
	self.Count = buf[2]
	self.Reserved = buf[3]
	self.AbstractUUID = buf[4:20]
	self.BindMajorVersion = binary.LittleEndian.Uint16(buf[20:22])
	self.BindMinVersion = binary.LittleEndian.Uint16(buf[22:24])
	self.TransferUUID = buf[24:40]
	self.TransferVersion = binary.LittleEndian.Uint32(buf[40:44])
	return nil
}

func NewUnicodeStr(referentId uint32, s string) *UnicodeStr {
	us := UnicodeStr{}
	if referentId != 0 {
		us.ReferentIdPtr = referentId
	}
	data := s + "\x00"
	unc := encoder.ToUnicode(data)
	count := (len(unc) / 2)
	us.MaxCount = uint32(count)
	us.Offset = 0
	us.ActualCount = uint32(count)

	us.EncodedString = make([]byte, len(unc))
	copy(us.EncodedString, unc)
	padd := (len(unc) % 4) //Got to be 4 byte aligned
	if padd != 0 {
		padd = 4 - padd
	}
	us.Padd = make([]byte, padd)
	return &us
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

func NewBindReq(callId uint32, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string) (*BindReq, error) {
	log.Debugln("In NewBindReq")

	srsv_uuid, err := uuid_to_bin(interface_uuid)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	ndr_uuid, err := uuid_to_bin(transfer_uuid)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	header := newHeader()
	header.Type = PacketTypeBind
	header.CallId = callId

	return &BindReq{
		Header:          header,
		MaxSendFragSize: 4280,
		MaxRecvFragSize: 4280,
		Association:     0,
		CtxCount:        1,
		Context: &ContextItems{
			{
				Id:               0,
				Count:            1,
				AbstractUUID:     srsv_uuid,
				BindMajorVersion: majorVersion,
				BindMinVersion:   minorVersion,
				TransferUUID:     ndr_uuid,
				TransferVersion:  2,
			},
		},
	}, nil
}

func NewBindRes() BindRes {
	return BindRes{
		Header:  newHeader(),
		Context: new(ContextResItems),
	}
}

func NewRequestReq(callId uint32, op uint16) (*RequestReq, error) {
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
	callId := rand.Uint32()
	bindReq, err := NewBindReq(callId, interface_uuid, majorVersion, minorVersion, transfer_uuid)
	if err != nil {
		return
	}

	buf, err := encoder.Marshal(bindReq)
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

	bindRes := NewBindRes()
	err = encoder.Unmarshal(ioCtlRes.Buffer, &bindRes)
	if err != nil {
		return
	}

	// Check if Bind was successful
	var contextRes ContextResItems
	contextRes = *bindRes.Context
	if bindRes.CallId != bindReq.CallId {
		return nil, fmt.Errorf("Received invalid callId: %d\n", bindRes.CallId)
	}
	if bindRes.Type != PacketTypeBindAck {
		return nil, fmt.Errorf("Invalid response from server: %v\n", bindRes)
	}
	if contextRes[0].Result != 0 {
		return nil, fmt.Errorf("Server did not approve bind request: %v\n", contextRes)
	}

	return &ServiceBind{f: f}, nil
}

func roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func (sb *ServiceBind) MakeIoCtlRequest(opcode uint16, innerBuf []byte) (result []byte, err error) {
	callId := rand.Uint32()
	req, err := NewRequestReq(callId, opcode)
	if err != nil {
		log.Errorln(err)
		return
	}

	req.Buffer = make([]byte, len(innerBuf))
	copy(req.Buffer, innerBuf)

	req.AllocHint = uint32(len(innerBuf))
	req.FragLength = uint16(req.AllocHint + 24) // Includes header size

	// Encode DCERPC Request
	buf, err := encoder.Marshal(req)
	if err != nil {
		log.Errorln(err)
		return
	}

	ioCtlReq, err := sb.f.NewIoCTLReq(smb.FsctlPipeTransceive, buf)
	if err != nil {
		log.Errorln(err)
		return
	}

	//NOTE Might be a problem with exceeding a max payload size of 65536 for
	// servers that do not support multi-credit requests

	// Send DCERPC request inside SMB IoCTL Request
	ioCtlRes, err := sb.f.WriteIoCtlReq(ioCtlReq)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Unmarshal DCERPC Request response
	var reqRes RequestRes
	err = encoder.Unmarshal(ioCtlRes.Buffer, &reqRes)
	if err != nil {
		log.Errorln(err)
		return
	}

	if reqRes.CallId != callId {
		err = fmt.Errorf("Incorrect CallId on response. Sent %d and received %d\n", callId, reqRes.CallId)
		log.Errorln(err)
		return
	}

	// Return response data
	return reqRes.Buffer, err
}

func (s *UnicodeStr) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	var ret []byte
	w := bytes.NewBuffer(ret)
	if s == nil {
		// Workaround for the generic encoder function that calls MarshalBinary even when the ptr is nil
		w.Write([]byte{0, 0, 0, 0})
		return w.Bytes(), nil
	}
	if s.ReferentIdPtr != 0 {
		binary.Write(w, binary.LittleEndian, s.ReferentIdPtr)
	}

	binary.Write(w, binary.LittleEndian, s.MaxCount)
	binary.Write(w, binary.LittleEndian, s.Offset)
	binary.Write(w, binary.LittleEndian, s.ActualCount)
	w.Write(s.EncodedString)

	l := len(w.Bytes())

	requiredPadd := 4 - (l % 4)
	if requiredPadd != 4 {
		w.Write(make([]byte, requiredPadd))
	}

	return w.Bytes(), nil
}

func (self *UnicodeStr) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	//NOTE This function will only work when unmarshalling a standalone UnicodeStr struct.
	// If the UnicodeStr is part of an array for instance, the ReferentIdPtr will not be
	// part of this buffer but rather be placed earlier in the byte stream.

	// Not sure how to handle if the ReferentId Ptr is placed somewhere earlier in the byte stream, before the actual struct
	// e.g., if all the elements of the struct are not serialized in order right next to each other

	self.ReferentIdPtr = binary.LittleEndian.Uint32(buf)
	self.MaxCount = binary.LittleEndian.Uint32(buf[4:])
	self.Offset = binary.LittleEndian.Uint32(buf[8:])
	self.ActualCount = binary.LittleEndian.Uint32(buf[12:])

	if int(self.Offset) > len(buf) {
		return fmt.Errorf("Specified offset of encoded string is outside buffer\n")
	}
	if int(self.Offset+self.ActualCount*2) > len(buf) {
		return fmt.Errorf("Encoded strings is placed outside buffer based on specified offset and ActualCount\n")
	}

	self.EncodedString = make([]byte, self.ActualCount*2)
	copy(self.EncodedString, buf[self.Offset:self.Offset+2*self.ActualCount])

	l := 16 + self.ActualCount*2
	paddLen := 4 - (l % 4)
	if paddLen != 4 {
		self.Padd = make([]byte, paddLen)
	}

	return nil
}
