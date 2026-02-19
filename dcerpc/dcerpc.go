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

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/golog"
)

var (
	MSRPCUuidNdr                  = "8a885d04-1ceb-11c9-9fe8-08002b104860" // NDR Transfer Syntax version 2.0
	re           regexp.Regexp    = *regexp.MustCompile(`([\dA-Fa-f]{8})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})-([\dA-Fa-f]{4})([\dA-Fa-f]{8})`)
	le           binary.ByteOrder = binary.LittleEndian
	log                           = golog.Get("github.com/jfjallid/go-smb/dcerpc")
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

// MSRPC Request header size (header + AllocHint + ContextId + Opnum)
const RequestHeaderSize int = 24

// MSRPC Packet Types
const (
	PacketTypeRequest          uint8 = 0
	PacketTypeResponse         uint8 = 2
	PacketTypeFault            uint8 = 3
	PacketTypeBind             uint8 = 11
	PacketTypeBindAck          uint8 = 12
	PacketTypeBindNak          uint8 = 13
	PacketTypeAlterContext     uint8 = 14
	PacketTypeAlterContextResp uint8 = 15
	PacketTypeAuth3            uint8 = 16
)

// Auth types (MS-RPCE 2.2.1.1.7)
const (
	RpcAuthnNone         uint8 = 0x00
	RpcAuthnGssNegotiate uint8 = 0x09 // SPNEGO
	RpcAuthnWinnt        uint8 = 0x0A // NTLMSSP
	RpcAuthnGssKerberos  uint8 = 0x10 // Kerberos (raw, without SPNEGO)
)

// Auth levels (MS-RPCE 2.2.1.1.8)
const (
	RpcAuthnLevelNone         uint8 = 1
	RpcAuthnLevelConnect      uint8 = 2
	RpcAuthnLevelCall         uint8 = 3
	RpcAuthnLevelPkt          uint8 = 4
	RpcAuthnLevelPktIntegrity uint8 = 5
	RpcAuthnLevelPktPrivacy   uint8 = 6
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

// Sealer provides per-PDU encryption/decryption for auth levels
// PktIntegrity and PktPrivacy. The mechanism (e.g., NTLMInitiator,
// KRB5Initiator) implements this interface to seal outgoing and unseal
// incoming stubs.
//
// For NTLM, the MAC covers the full PDU (header + plaintext stub +
// auth_pad + sec_trailer) while only the stub + auth_pad is encrypted.
// For Kerberos, integrity is built into the encryption (HMAC inside
// the encrypted blob), so the toSign / pduHeader+secTrailer parameters
// are ignored.
type Sealer interface {
	// Seal encrypts toEncrypt (stub + auth_pad) and returns ciphertext
	// and signature (auth_value bytes). toSign is the full PDU for NTLM
	// MAC; Kerberos ignores it. The returned ciphertext may be larger
	// than toEncrypt by EncryptionOverhead() bytes.
	Seal(toEncrypt, toSign []byte) (ciphertext, signature []byte)
	// Unseal decrypts ciphertext and verifies integrity.
	// signature is the auth_value bytes. pduHeader and secTrailer are
	// provided for NTLM (which MACs the full PDU); Kerberos ignores them.
	Unseal(ciphertext, signature, pduHeader, secTrailer []byte) (plaintext []byte, err error)
	// SignatureSize returns the maximum auth_value size
	// (NTLM=16, Kerberos=16+16+RRC+maxPad).
	SignatureSize() int
	// EncryptionOverhead returns extra ciphertext bytes beyond plaintext
	// size (0 for both NTLM and Kerberos).
	EncryptionOverhead() int
}

// DCEThirdLegProvider is implemented by mechanisms that generate a 3rd leg
// token for DCERPC SPNEGO authentication (e.g., Kerberos sends a modified
// AP_REP in the AlterContext).
type DCEThirdLegProvider interface {
	DCEThirdLeg() ([]byte, error)
}

// DCEAPRepProcessor is implemented by mechanisms that can process a bare
// AP_REP (not KRB5Token-wrapped) from a DCE-style SPNEGO response.
// When GSS_C_DCE_STYLE is set, the server sends the AP_REP directly
// in the NegTokenResp's ResponseToken field, without KRB5Token wrapping.
type DCEAPRepProcessor interface {
	DCEProcessAPRep(rawAPRep []byte) error
}

// DCERPCTransport abstracts the underlying transport for DCERPC PDUs.
type DCERPCTransport interface {
	// Transceive sends a complete DCERPC PDU and returns the first response PDU.
	// For SMB: maps to FsctlPipeTransceive (atomic send+receive).
	// For TCP: writes PDU then reads response.
	Transceive(pdu []byte) ([]byte, error)

	// Write sends a DCERPC PDU without waiting for a response.
	// Used for send-side fragmentation (non-last fragments) and Auth3.
	// For SMB: maps to WriteFile on the named pipe.
	// For TCP: writes PDU to socket.
	Write(pdu []byte) error

	// Read reads the next DCERPC PDU fragment from the transport.
	// Used for continuation fragments after the first Transceive response.
	// maxSize is a buffer sizing hint: SMBTransport uses it to size the read
	// buffer, while TCPTransport ignores it (TCP is self-framing via FragLength).
	// For SMB: maps to ReadFile on the named pipe.
	// For TCP: reads a complete PDU (header + body based on FragLength).
	Read(maxSize uint16) ([]byte, error)

	// GetSessionKey returns the session key for upper-layer encryption
	// (e.g., MS-LSAD DES secret encryption, MS-SAMR RC4 password encryption).
	GetSessionKey() []byte
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
		FragLength:     0, // Set after marshal to actual PDU size
		AuthLength:     0,
		CallId:         0,
	}
}

func UUIDToBin(uuid string) ([]byte, error) {
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

	srsv_uuid, err := UUIDToBin(interface_uuid)
	if err != nil {
		log.Errorln(err)
		return
	}
	ndr_uuid, err := UUIDToBin(transfer_uuid)
	if err != nil {
		log.Errorln(err)
		return
	}
	header := newHeader()
	header.Type = PacketTypeBind
	header.CallId = callId
	ctxItem := ContextItem{
		Id: 0,
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
// parseAndValidateCommonHeader validates a BindAck or AlterContext response PDU Common Header.
// It checks the CallId and the packet type
func parseAndValidateCommonHeader(response []byte, expectedCallId uint32) (error) {
	var h Header
	err := h.UnmarshalBinary(response[:16])
	if err != nil {
		return err
	}
	if h.CallId != expectedCallId {
		return fmt.Errorf("Received invalid callId: %d\n", h.CallId)
	}
	switch h.Type {
	case PacketTypeBindNak:
		return fmt.Errorf("Received Bind_Nak with reason: 0x%x", le.Uint16(response[16:18])) // Should it be Little Endian?
	case PacketTypeBindAck,PacketTypeAlterContextResp:
	default:
		return fmt.Errorf("Invalid response from server: %v\n", h)
	}
	return nil
}

// parseAndValidateBindAck validates a BindAck (or AlterContext response) PDU.
// It checks the CallId, packet type, unmarshals the BindRes, and verifies the
// first context result item was accepted.
func parseAndValidateBindAck(response []byte, expectedCallId uint32) (*BindRes, error) {
	err := parseAndValidateCommonHeader(response, expectedCallId)
	if err != nil {
		return nil, err
	}
	var bindRes BindRes
	err = bindRes.UnmarshalBinary(response)
	if err != nil {
		return nil, err
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

	return &bindRes, nil
}

func Bind(transport DCERPCTransport, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string) (bind *ServiceBind, err error) {
	log.Debugln("In Bind")
	if transport == nil {
		return nil, fmt.Errorf("Transport argument cannot be nil")
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
	// Update FragLength to actual PDU size
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))

	response, err := transport.Transceive(buf)
	if err != nil {
		return
	}

	bindRes, err := parseAndValidateBindAck(response, bindReq.CallId)
	if err != nil {
		return
	}

	return &ServiceBind{
		callId:              &callId,
		transport:           transport,
		maxFragReceiveSize:  bindRes.MaxSendFragSize,
		maxFragTransmitSize: bindRes.MaxRecvFragSize,
	}, nil
}

// SessionKeySettable is implemented by transports that support setting a
// session key after an authenticated bind (e.g., TCPTransport).
type SessionKeySettable interface {
	SetSessionKey(key []byte)
}

// authTypeForMechanism maps a GSS mechanism OID to the corresponding
// RPC authentication type constant.
func authTypeForMechanism(mechanism gss.Mechanism) (uint8, error) {
	oid := mechanism.Oid()
	if oid.Equal(gss.NtLmSSPMechTypeOid) {
		return RpcAuthnWinnt, nil
	}
	if oid.Equal(gss.KerberosSSPMechTypeOid) || oid.Equal(gss.MsKerberosOid) {
		// Use SPNEGO (0x09) for Kerberos, not raw Kerberos (0x10).
		// Windows DCERPC servers expect SPNEGO wrapping with a 3-leg
		// exchange (Bind, BindAck, AlterContext) to finalize the context.
		return RpcAuthnGssNegotiate, nil
	}
	return 0, fmt.Errorf("Unsupported authentication mechanism OID: %v", oid)
}

// isKerberosMech returns true if the mechanism is a Kerberos mechanism.
func isKerberosMech(mechanism gss.Mechanism) bool {
	oid := mechanism.Oid()
	return oid.Equal(gss.KerberosSSPMechTypeOid) || oid.Equal(gss.MsKerberosOid)
}

// marshalSPNEGOInit wraps a mechanism token in a SPNEGO NegTokenInit.
func marshalSPNEGOInit(mechTypes []asn1.ObjectIdentifier, mechToken []byte) ([]byte, error) {
	init := gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes:    mechTypes,
			ReqFlags:     asn1.BitString{},
			MechToken:    mechToken,
			MechTokenMIC: []byte{},
		},
	}
	buf, err := asn1.Marshal(init)
	if err != nil {
		return nil, err
	}
	// Override ASN1 SEQUENCE tag (0x30) with APPLICATION tag (0x60)
	buf[0] = 0x60
	return buf, nil
}

// unmarshalSPNEGOResp parses a SPNEGO NegTokenResp.
func unmarshalSPNEGOResp(data []byte) (gss.NegTokenResp, error) {
	var resp gss.NegTokenResp
	_, err := asn1.UnmarshalWithParams(data, &resp, "explicit,tag:1")
	return resp, err
}

// marshalSPNEGOResp encodes a SPNEGO NegTokenResp.
func marshalSPNEGOResp(resp gss.NegTokenResp) ([]byte, error) {
	wrapped := struct{ G interface{} }{resp}
	buf, err := asn1.Marshal(wrapped)
	if err != nil {
		return nil, err
	}
	// Override ASN1 SEQUENCE tag (0x30) with CONTEXT tag 1 (0xa1)
	buf[0] = 0xa1
	return buf, nil
}

// BindAuth performs an authenticated DCERPC bind using the provided GSS mechanism.
// For NTLM (3-leg), it uses Alter Context for the third leg so that the server's
// response confirms authentication success.
// For Kerberos, it wraps tokens in SPNEGO and uses Alter Context for the third
// leg to finalize the security context.
func BindAuth(transport DCERPCTransport, interface_uuid string, majorVersion, minorVersion uint16, transfer_uuid string, authLevel uint8, mechanism gss.Mechanism) (bind *ServiceBind, err error) {
	log.Debugln("In BindAuth")
	if transport == nil {
		return nil, fmt.Errorf("Transport argument cannot be nil")
	}
	if mechanism == nil {
		return nil, fmt.Errorf("Mechanism argument cannot be nil")
	}

	authType, err := authTypeForMechanism(mechanism)
	if err != nil {
		return nil, err
	}

	useSpnego := isKerberosMech(mechanism)

	callId := atomic.Uint32{}
	maxFragRxSize := uint16(4280)
	maxFragTxSize := uint16(4280)

	// Step 1: Get initial auth token from mechanism
	mechToken, err := mechanism.InitSecContext(nil)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize security context: %w", err)
	}

	// For Kerberos, wrap the raw AP_REQ in SPNEGO NegTokenInit
	var initToken []byte
	if useSpnego {
		// Use MS KRB5 OID (1.2.840.48018.1.2.2) as the SPNEGO MechType
		mechTypes := []asn1.ObjectIdentifier{gss.MsKerberosOid}
		initToken, err = marshalSPNEGOInit(mechTypes, mechToken)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal SPNEGO NegTokenInit: %w", err)
		}
	} else {
		initToken = mechToken
	}

	// Step 2: Build Bind request with AuthVerifier
	bindReq, err := newBindReq(callId.Add(1), interface_uuid, majorVersion, minorVersion, transfer_uuid, maxFragTxSize, maxFragRxSize)
	if err != nil {
		return
	}
	bindReq.AuthVerifier = &AuthVerifier{
		AuthType:      authType,
		AuthLevel:     authLevel,
		AuthValue:     initToken,
	}

	// Set AuthLength to the length of just the auth token
	bindReq.Header.AuthLength = uint16(len(initToken))

	buf, err := bindReq.MarshalBinary()
	if err != nil {
		return
	}
	// Update FragLength to actual PDU size
	binary.LittleEndian.PutUint16(buf[8:10], uint16(len(buf)))

	// Step 3: Send Bind, receive BindAck
	response, err := transport.Transceive(buf)
	if err != nil {
		return
	}

	// Step 4: Validate BindAck
	bindRes, err := parseAndValidateBindAck(response, bindReq.CallId)
	if err != nil {
		return
	}

	// Step 5: Process server auth token if present
	if bindRes.AuthVerifier != nil && len(bindRes.AuthVerifier.AuthValue) > 0 {
		var responseToken []byte

		if useSpnego {
			// Kerberos with SPNEGO: unwrap NegTokenResp to get inner AP_REP
			negResp, err2 := unmarshalSPNEGOResp(bindRes.AuthVerifier.AuthValue)
			if err2 != nil {
				return nil, fmt.Errorf("Failed to parse SPNEGO NegTokenResp from BindAck: %w", err2)
			}

			// DCE-style: the ResponseToken is a bare AP_REP (not KRB5Token-wrapped)
			// because GSS_C_DCE_STYLE is set in the AP_REQ authenticator checksum.
			if processor, ok := mechanism.(DCEAPRepProcessor); ok {
				err = processor.DCEProcessAPRep(negResp.ResponseToken)
			} else {
				_, err = mechanism.InitSecContext(negResp.ResponseToken)
			}
			if err != nil {
				return nil, fmt.Errorf("Failed to process server auth token: %w", err)
			}

			// Build 3rd leg: SPNEGO NegTokenResp with modified AP_REP
			var thirdLegMechToken []byte
			if provider, ok := mechanism.(DCEThirdLegProvider); ok {
				thirdLegMechToken, err = provider.DCEThirdLeg()
				if err != nil {
					return nil, fmt.Errorf("Failed to build 3rd leg token: %w", err)
				}
			}

			// Leaving negState at zero omits it via omitempty.
			thirdLeg := gss.NegTokenResp{
				ResponseToken: thirdLegMechToken,
			}
			responseToken, err = marshalSPNEGOResp(thirdLeg)
			if err != nil {
				return nil, fmt.Errorf("Failed to marshal SPNEGO 3rd leg: %w", err)
			}
		} else {
			// NTLM: pass server token directly to mechanism
			responseToken, err = mechanism.InitSecContext(bindRes.AuthVerifier.AuthValue)
			if err != nil {
				return nil, fmt.Errorf("Failed to process server auth token: %w", err)
			}
		}

		// Step 6: Send third leg via Alter Context to finalize the security context.
		if len(responseToken) > 0 {
			alterReq, err2 := newBindReq(callId.Add(1), interface_uuid, majorVersion, minorVersion, transfer_uuid, maxFragTxSize, maxFragRxSize)
			if err2 != nil {
				return nil, fmt.Errorf("Failed to build Alter Context: %w", err2)
			}
			alterReq.Header.Type = PacketTypeAlterContext
			alterReq.AuthVerifier = &AuthVerifier{
				AuthType:      authType,
				AuthLevel:     authLevel,
				AuthValue:     responseToken,
			}
			alterReq.Header.AuthLength = uint16(len(responseToken))

			var alterBuf []byte
			alterBuf, err = alterReq.MarshalBinary()
			if err != nil {
				return nil, fmt.Errorf("Failed to marshal Alter Context: %w", err)
			}
			binary.LittleEndian.PutUint16(alterBuf[8:10], uint16(len(alterBuf)))

			var alterResponse []byte
			alterResponse, err = transport.Transceive(alterBuf)
			if err != nil {
				return nil, fmt.Errorf("Failed to send Alter Context: %w", err)
			}

			err := parseAndValidateCommonHeader(alterResponse, alterReq.CallId)
			if err != nil {
				return nil, fmt.Errorf("Alter Context Response validation failed with error: %w", err)
			}
			var alterRes BindRes
			err = alterRes.UnmarshalBinary(alterResponse)
			if err != nil {
				return nil, fmt.Errorf("Failed to unmarshal Alter Context Response: %w", err)
			}

			if len(alterRes.ResultList.Items) == 0 {
				return nil, fmt.Errorf("Alter Context Response has no context items")
			}
			if alterRes.ResultList.Items[0].Result != acceptance {
				return nil, fmt.Errorf("Authentication failed: server rejected Alter Context")
			}

		}
	}

	// Step 7: Set session key on transport
	sessionKey := mechanism.SessionKey()
	if len(sessionKey) > 0 {
		if settable, ok := transport.(SessionKeySettable); ok {
			settable.SetSessionKey(sessionKey)
		}
	}

	var sealer Sealer
	if authLevel >= RpcAuthnLevelPktIntegrity {
		s, ok := mechanism.(Sealer)
		if !ok {
			return nil, fmt.Errorf("Mechanism does not support per-PDU auth for level %d", authLevel)
		}
		sealer = s
	}

	return &ServiceBind{
		callId:              &callId,
		transport:           transport,
		maxFragReceiveSize:  bindRes.MaxSendFragSize,
		maxFragTransmitSize: bindRes.MaxRecvFragSize,
		authType:            authType,
		authLevel:           authLevel,
		sealer:              sealer,
	}, nil
}

func (sb *ServiceBind) GetSessionKey() (sessionKey []byte) {
	return sb.transport.GetSessionKey()
}

func (sb *ServiceBind) MakeRequest(opcode uint16, innerBuf []byte) (result []byte, err error) {
	callId := sb.callId.Add(1)
	totalPayloadLen := len(innerBuf)
	authOverhead := 0
	if sb.sealer != nil {
		// 8 = auth verifier header + worst-case signature + worst-case auth padding (3 bytes)
		// + encryption overhead (0 for both NTLM and Kerberos)
		authOverhead = 8 + sb.sealer.SignatureSize() + 3 + sb.sealer.EncryptionOverhead()
	}
	maxStub := int(sb.maxFragTransmitSize) - RequestHeaderSize - authOverhead
	if maxStub <= 0 {
		maxStub = totalPayloadLen
	}

	// Determine if we need send-side fragmentation
	needsSendFragmentation := totalPayloadLen > maxStub

	if !needsSendFragmentation {
		// Single fragment: send via Transceive and get response
		var req *RequestReq
		req, err = newRequestReq(callId, opcode)
		if err != nil {
			log.Errorln(err)
			return
		}

		req.Buffer = make([]byte, len(innerBuf))
		copy(req.Buffer, innerBuf)
		req.AllocHint = uint32(totalPayloadLen)
		req.FragLength = uint16(len(innerBuf) + RequestHeaderSize)

		var buf []byte
		buf, err = req.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		if sb.sealer != nil {
			buf, err = sb.sealRequestPDU(buf)
			if err != nil {
				log.Errorln(err)
				return
			}
		}

		var responseBuffer []byte
		responseBuffer, err = sb.transport.Transceive(buf)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Process response (may be fragmented on the receive side)
		return sb.processResponse(callId, responseBuffer)
	}

	// Send-side fragmentation: split payload into multiple fragments
	offset := 0
	firstFrag := true
	for offset < totalPayloadLen {
		remaining := totalPayloadLen - offset
		chunkSize := maxStub
		if chunkSize > remaining {
			chunkSize = remaining
		}
		lastFrag := (offset + chunkSize) >= totalPayloadLen

		var req *RequestReq
		req, err = newRequestReq(callId, opcode)
		if err != nil {
			log.Errorln(err)
			return
		}

		req.Buffer = make([]byte, chunkSize)
		copy(req.Buffer, innerBuf[offset:offset+chunkSize])
		req.AllocHint = uint32(totalPayloadLen)
		req.FragLength = uint16(chunkSize + RequestHeaderSize)

		// Set fragmentation flags
		req.Flags = 0
		if firstFrag {
			req.Flags |= PfcFirstFrag
		}
		if lastFrag {
			req.Flags |= PfcLastFrag
		}

		var buf []byte
		buf, err = req.MarshalBinary()
		if err != nil {
			log.Errorln(err)
			return
		}

		if sb.sealer != nil {
			buf, err = sb.sealRequestPDU(buf)
			if err != nil {
				log.Errorln(err)
				return
			}
		}

		if lastFrag {
			// Last fragment: use Transceive to get response
			var responseBuffer []byte
			responseBuffer, err = sb.transport.Transceive(buf)
			if err != nil {
				log.Errorln(err)
				return
			}
			return sb.processResponse(callId, responseBuffer)
		}

		// Non-last fragment: use Write (no response expected)
		err = sb.transport.Write(buf)
		if err != nil {
			log.Errorln(err)
			return
		}

		offset += chunkSize
		firstFrag = false
	}

	return
}

// sealRequestPDU encrypts the stub data in a marshaled Request PDU and appends
// an AuthVerifier. The input pdu must be a complete marshaled RequestReq
// (header + AllocHint + CtxId + Opnum + plaintext stub).
//
// Per MS-RPCE, the MAC covers the full PDU (header + plaintext stub + auth_pad
// + sec_trailer) while only stub + auth_pad is encrypted.
func (sb *ServiceBind) sealRequestPDU(pdu []byte) ([]byte, error) {
	if len(pdu) < RequestHeaderSize {
		return nil, fmt.Errorf("PDU too short to seal: %d bytes", len(pdu))
	}

	stub := pdu[RequestHeaderSize:]

	// Compute auth padding to align (header + stub + padding) to 4-byte boundary
	authPad := (4 - (len(pdu) % 4)) % 4
	toEncrypt := make([]byte, len(stub)+authPad)
	copy(toEncrypt, stub)
	// padding bytes are zero (already zero from make)

	sigSize := sb.sealer.SignatureSize()

	// Build sec_trailer (8 bytes) for inclusion in signed data
	secTrailer := AuthVerifier{
		AuthType:      sb.authType,
		AuthLevel:     sb.authLevel,
		AuthPadLength: uint8(authPad),
		AuthReserved:  0,
	}
	secTrailerBytes, err := secTrailer.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal sec_trailer: %w", err)
	}
	// secTrailerBytes is 8 bytes (no AuthValue)

	// Pre-compute FragLength for the header used in NTLM signing.
	// For both NTLM and Kerberos, ciphertext length equals toEncrypt length,
	// but actual signature size may differ from sigSize — we fix the header below.
	preFragLen := uint16(RequestHeaderSize + len(toEncrypt) + len(secTrailerBytes) + sigSize)

	// Build the header with pre-computed FragLength and AuthLength
	header := make([]byte, RequestHeaderSize)
	copy(header, pdu[:RequestHeaderSize])
	binary.LittleEndian.PutUint16(header[8:10], preFragLen)
	binary.LittleEndian.PutUint16(header[10:12], uint16(sigSize))

	// Build toSign: header + plaintext stub+pad + sec_trailer
	// This is the full PDU minus the auth_value (signature).
	// Used by NTLM for MAC; Kerberos ignores it.
	toSign := make([]byte, 0, RequestHeaderSize+len(toEncrypt)+len(secTrailerBytes))
	toSign = append(toSign, header...)
	toSign = append(toSign, toEncrypt...)
	toSign = append(toSign, secTrailerBytes...)

	// Encrypt toEncrypt, compute MAC over toSign
	ciphertext, signature := sb.sealer.Seal(toEncrypt, toSign)

	// Compute actual FragLength from Seal output sizes.
	// len(ciphertext)==len(toEncrypt) for both NTLM and Kerberos.
	// len(signature) may differ from sigSize (Kerberos varies by padding).
	actualFragLen := uint16(RequestHeaderSize + len(ciphertext) + len(secTrailerBytes) + len(signature))
	binary.LittleEndian.PutUint16(header[8:10], actualFragLen)
	binary.LittleEndian.PutUint16(header[10:12], uint16(len(signature)))

	// Assemble sealed PDU: header + ciphertext + sec_trailer + signature
	sealed := make([]byte, int(actualFragLen))
	copy(sealed[:RequestHeaderSize], header)
	copy(sealed[RequestHeaderSize:], ciphertext)
	copy(sealed[RequestHeaderSize+len(ciphertext):], secTrailerBytes)
	copy(sealed[RequestHeaderSize+len(ciphertext)+len(secTrailerBytes):], signature)

	return sealed, nil
}

// ResponseHeaderSize is the fixed size of a Response PDU header
// (common header 16 + AllocHint 4 + ContextId 2 + CancelCount 1 + Reserved 1).
const ResponseHeaderSize int = 24

// unsealResponsePDU decrypts the stub data in a Response PDU and returns a
// clean buffer that RequestRes.UnmarshalBinary can parse (with auth stripped).
//
// Per MS-RPCE, the MAC covers the full PDU (header + plaintext stub + auth_pad
// + sec_trailer) while only stub + auth_pad is encrypted.
func (sb *ServiceBind) unsealResponsePDU(pdu []byte, header *Header) ([]byte, error) {
	fragLen := int(header.FragLength)
	authTotalLen := int(header.AuthLength) + 8
	if fragLen < ResponseHeaderSize+authTotalLen {
		return nil, fmt.Errorf("Response PDU too short to contain auth verifier")
	}

	authStart := fragLen - authTotalLen
	signatureStart := fragLen - int(header.AuthLength)

	// Extract sec_trailer (8 bytes) and signature
	secTrailerBytes := pdu[authStart:signatureStart]
	signature := pdu[signatureStart:fragLen]

	// Unmarshal sec_trailer to get AuthPadLength
	var av AuthVerifier
	err := av.UnmarshalBinary(pdu[authStart:fragLen])
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal response AuthVerifier: %w", err)
	}

	// Encrypted data is between response header and sec_trailer
	encryptedData := pdu[ResponseHeaderSize:authStart]

	// Decrypt and verify integrity in one step.
	// NTLM uses pduHeader and secTrailer for MAC verification.
	// Kerberos verifies integrity inside DecryptMessage.
	plaintext, err := sb.sealer.Unseal(encryptedData, signature, pdu[:ResponseHeaderSize], secTrailerBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to unseal response PDU: %w", err)
	}

	// Strip auth padding
	stubLen := len(plaintext) - int(av.AuthPadLength)
	if stubLen < 0 {
		return nil, fmt.Errorf("Auth padding length %d exceeds plaintext length %d", av.AuthPadLength, len(plaintext))
	}
	stub := plaintext[:stubLen]

	// Rebuild clean PDU: header + response fields + stub (no auth)
	newFragLen := uint16(ResponseHeaderSize + len(stub))
	cleanPDU := make([]byte, newFragLen)
	copy(cleanPDU[:ResponseHeaderSize], pdu[:ResponseHeaderSize])
	copy(cleanPDU[ResponseHeaderSize:], stub)

	// Fix header: FragLength = new size, AuthLength = 0
	binary.LittleEndian.PutUint16(cleanPDU[8:10], newFragLen)
	binary.LittleEndian.PutUint16(cleanPDU[10:12], 0)

	return cleanPDU, nil
}

// processResponse handles the receive-side reassembly of a DCERPC response,
// which may arrive as multiple fragments.
func (sb *ServiceBind) processResponse(callId uint32, responseBuffer []byte) (result []byte, err error) {
	for {
		if len(responseBuffer) < PDUHeaderCommonSize {
			err = fmt.Errorf("Read/IoCtl response on DCERPC fragment was smaller than the DCERPC header size")
			log.Errorln(err)
			return
		}

		var resHeader Header
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

		// Unseal response if per-PDU auth is active
		if resHeader.AuthLength > 0 && sb.sealer != nil {
			responseBuffer, err = sb.unsealResponsePDU(responseBuffer, &resHeader)
			if err != nil {
				log.Errorln(err)
				return
			}
			// Re-parse header since we rebuilt the buffer
			err = resHeader.UnmarshalBinary(responseBuffer[:PDUHeaderCommonSize])
			if err != nil {
				log.Errorln(err)
				return
			}
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

		// Read the next response fragment
		responseBuffer, err = sb.transport.Read(sb.maxFragReceiveSize)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	return
}
