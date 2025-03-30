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
	"encoding/binary"
	"encoding/hex"
	"fmt"
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

const (
	ErrorSuccess         uint32 = 0x00000000
	ErrorAccessDenied    uint32 = 0x00000005
	ErrorContextMismatch uint32 = 0x1c00001a
)

var responseCodeMap = map[uint32]error{
	ErrorSuccess:         fmt.Errorf("The operation completed successfully"),
	ErrorAccessDenied:    fmt.Errorf("Access denied!"),
	ErrorContextMismatch: fmt.Errorf("Context Mismatch"),
}

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

func (sb *ServiceBind) GetSessionKey() (sessionKey []byte) {
	return sb.f.GetSessionKey()
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
				returnCode := binary.LittleEndian.Uint32(responseBuffer[PDUHeaderCommonSize+8:])
				status, found := responseCodeMap[returnCode]
				if !found {
					err = fmt.Errorf("DCERPC Fault PDU received with status: 0x%x", returnCode)
					log.Errorln(err)
					return
				}
				err = fmt.Errorf("DCERPC Fault PDU received with status: %s", status)
				log.Errorln(err)
				return
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
