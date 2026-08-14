// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

// Hand-written wire marshalling for the SMB2 structures, replacing the
// reflection-based smb/encoder engine.
//
// Conventions, matching MS-SMB2 and what the reflection engine produced:
//
//   - Offsets in a request/response body are measured from the first byte of
//     the 64-byte SMB2 header, so a payload that follows an N-byte fixed body
//     sits at 64+N. Each struct below names that constant.
//   - A "…Offset" field is emitted as 0 when its payload is empty, and a
//     "…Length" field is always derived from the payload actually written, so
//     the two can never disagree with the bytes on the wire.
//   - "Count" fields (dialects, ciphers, hash algorithms, …) are *not* derived:
//     they are written verbatim from the struct, because callers set them while
//     assembling the negotiate contexts and the reflection engine passed them
//     through the same way.
//   - Fixed-width byte fields (GUIDs, FileIds, signatures) are padded or
//     truncated to their spec length rather than emitted at whatever length the
//     caller happened to supply.
//
// Decoders bounds-check every peer-supplied offset and length. Several of these
// run before a connection is authenticated, and the SMB2 receive loop has no
// recover(), so an out-of-range slice would take down the process.
package smb

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/gss"
)

// Fixed body sizes, excluding the 64-byte SMB2 header. Each doubles as the
// offset (from the header) at which that PDU's variable-length payload starts.
const (
	transformHeaderSize    = 52
	smb1HeaderSize         = 32
	negotiateResBodySize   = 64
	sessionSetupReqBody    = 24
	sessionSetupResBody    = 8
	treeConnectReqBody     = 8
	createResBodySize      = 88
	queryDirReqBodySize    = 32
	queryDirResBodySize    = 8
	readResBodySize        = 16
	writeReqBodySize       = 48
	setInfoReqBodySize     = 32
	fileBothDirInfoFixed   = 94
	negContextHeaderSize   = 8
	oplockBreakBodySize    = 24
	closeReqBodySize       = 24
	flushReqBodySize       = 24
	structureSizeOnlyBody  = 4
	setInfoResBodySize     = 2
	treeConnectResBodySize = 16
	closeResBodySize       = 60
	writeResBodySize       = 16
)

// reader is a bounds-checked little-endian cursor. Every accessor is a no-op
// once an error has been recorded, so a decoder can read a whole structure and
// check err once at the end instead of after every field.
type reader struct {
	what string // structure name, for error messages
	buf  []byte
	off  int
	err  error
}

func newReader(what string, buf []byte) *reader {
	return &reader{what: what, buf: buf}
}

func (r *reader) need(n int) bool {
	if r.err != nil {
		return false
	}
	if n < 0 || r.off+n > len(r.buf) {
		r.err = fmt.Errorf("%s: need %d bytes at offset %d but the buffer is %d bytes", r.what, n, r.off, len(r.buf))
		return false
	}
	return true
}

func (r *reader) u8() byte {
	if !r.need(1) {
		return 0
	}
	v := r.buf[r.off]
	r.off++
	return v
}

func (r *reader) u16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v
}

func (r *reader) u32() uint32 {
	if !r.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(r.buf[r.off:])
	r.off += 4
	return v
}

func (r *reader) u64() uint64 {
	if !r.need(8) {
		return 0
	}
	v := binary.LittleEndian.Uint64(r.buf[r.off:])
	r.off += 8
	return v
}

// next returns the following n bytes, advancing the cursor.
func (r *reader) next(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.buf[r.off : r.off+n]
	r.off += n
	return v
}

func (r *reader) skip(n int) {
	if r.need(n) {
		r.off += n
	}
}

// u16s reads n little-endian uint16 values.
func (r *reader) u16s(n int) []uint16 {
	if n == 0 || !r.need(n*2) {
		return nil
	}
	out := make([]uint16, n)
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(r.buf[r.off+i*2:])
	}
	r.off += n * 2
	return out
}

// at returns the length bytes located at offset, which is measured from the
// start of the PDU rather than from the cursor. Both values come off the wire,
// so the arithmetic is done in uint64 to stop a hostile offset+length pair from
// wrapping past the guard.
func (r *reader) at(field string, offset, length uint64) []byte {
	if r.err != nil {
		return nil
	}
	if length == 0 {
		return nil
	}
	if offset > uint64(len(r.buf)) || length > uint64(len(r.buf))-offset {
		r.err = fmt.Errorf("%s: %s at offset %d (%d bytes) is outside the %d-byte PDU", r.what, field, offset, length, len(r.buf))
		return nil
	}
	return r.buf[offset : offset+length]
}

// appendFixed appends exactly n bytes of b, zero-padding a short value and
// dropping the excess from a long one, so a caller cannot desynchronise the
// wire format by supplying a wrongly-sized GUID or FileId.
func appendFixed(buf, b []byte, n int) []byte {
	if len(b) >= n {
		return append(buf, b[:n]...)
	}
	buf = append(buf, b...)
	return append(buf, make([]byte, n-len(b))...)
}

// payloadOffset returns off when length is non-zero and 0 otherwise, matching
// the "absent payload gets a zero offset" convention described above.
func payloadOffset(off, length int) uint32 {
	if length == 0 {
		return 0
	}
	return uint32(off)
}

// ---------------------------------------------------------------- SMB2 header

func (s *Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, headerSize)
	buf = appendFixed(buf, s.ProtocolID, 4)
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.CreditCharge)
	buf = binary.LittleEndian.AppendUint32(buf, s.Status)
	buf = binary.LittleEndian.AppendUint16(buf, s.Command)
	buf = binary.LittleEndian.AppendUint16(buf, s.Credits)
	buf = binary.LittleEndian.AppendUint32(buf, s.Flags)
	buf = binary.LittleEndian.AppendUint32(buf, s.NextCommand)
	buf = binary.LittleEndian.AppendUint64(buf, s.MessageID)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, s.TreeID)
	buf = binary.LittleEndian.AppendUint64(buf, s.SessionID)
	return appendFixed(buf, s.Signature, 16), nil
}

func (s *Header) UnmarshalBinary(buf []byte) error {
	r := newReader("SMB2 header", buf)
	s.ProtocolID = r.next(4)
	s.StructureSize = r.u16()
	s.CreditCharge = r.u16()
	s.Status = r.u32()
	s.Command = r.u16()
	s.Credits = r.u16()
	s.Flags = r.u32()
	s.NextCommand = r.u32()
	s.MessageID = r.u64()
	s.Reserved = r.u32()
	s.TreeID = r.u32()
	s.SessionID = r.u64()
	s.Signature = r.next(16)
	return r.err
}

// marshalHeader is shared by every PDU marshaller below.
func (s *Header) marshalInto(buf []byte) ([]byte, error) {
	h, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(buf, h...), nil
}

func (s *TransformHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, transformHeaderSize)
	buf = binary.LittleEndian.AppendUint32(buf, s.ProtcolID)
	buf = appendFixed(buf, s.Signature, 16)
	buf = appendFixed(buf, s.Nonce, 16)
	buf = binary.LittleEndian.AppendUint32(buf, s.OriginalMessageSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint16(buf, s.Flags)
	return binary.LittleEndian.AppendUint64(buf, s.SessionId), nil
}

func (s *TransformHeader) UnmarshalBinary(buf []byte) error {
	r := newReader("SMB2 transform header", buf)
	s.ProtcolID = r.u32()
	s.Signature = r.next(16)
	s.Nonce = r.next(16)
	s.OriginalMessageSize = r.u32()
	s.Reserved = r.u16()
	s.Flags = r.u16()
	s.SessionId = r.u64()
	return r.err
}

func (s *SMB1Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, smb1HeaderSize)
	buf = appendFixed(buf, s.Protocol, 4)
	buf = append(buf, s.Command)
	buf = binary.LittleEndian.AppendUint32(buf, s.Status)
	buf = append(buf, s.Flags)
	buf = binary.LittleEndian.AppendUint16(buf, s.Flags2)
	buf = binary.LittleEndian.AppendUint16(buf, s.PIDHigh)
	buf = appendFixed(buf, s.SecurityFeatures, 8)
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint16(buf, s.TID)
	buf = binary.LittleEndian.AppendUint16(buf, s.PIDLow)
	buf = binary.LittleEndian.AppendUint16(buf, s.UID)
	return binary.LittleEndian.AppendUint16(buf, s.MID), nil
}

func (s *SMB1Header) UnmarshalBinary(buf []byte) error {
	r := newReader("SMB1 header", buf)
	s.Protocol = r.next(4)
	s.Command = r.u8()
	s.Status = r.u32()
	s.Flags = r.u8()
	s.Flags2 = r.u16()
	s.PIDHigh = r.u16()
	s.SecurityFeatures = r.next(8)
	s.Reserved = r.u16()
	s.TID = r.u16()
	s.PIDLow = r.u16()
	s.UID = r.u16()
	s.MID = r.u16()
	return r.err
}

// ------------------------------------------------------- negotiate contexts

func (s *NegContext) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, negContextHeaderSize+len(s.Data))
	buf = binary.LittleEndian.AppendUint16(buf, s.ContextType)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Data)))
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved)
	return append(buf, s.Data...), nil
}

// marshalNegContextList serializes a negotiate context list, inserting the
// alignment padding that MS-SMB2 §3.3.5.4 requires: the first context starts at
// NegotiateContextOffset (which the caller has already 8-aligned) and every
// subsequent one starts at the next 8-byte boundary after its predecessor.
//
// The padding is emitted *between* contexts rather than as a tail on each one,
// so there is never a trailing pad after the final context and no caller has to
// remember to strip one.
func marshalNegContextList(contexts []NegContext) ([]byte, error) {
	var buf []byte
	for i := range contexts {
		if i > 0 {
			if rem := len(buf) % 8; rem != 0 {
				buf = append(buf, make([]byte, 8-rem)...)
			}
		}
		cb, err := contexts[i].MarshalBinary()
		if err != nil {
			return nil, err
		}
		buf = append(buf, cb...)
	}
	return buf, nil
}

func (s *NegContext) UnmarshalBinary(buf []byte) error {
	r := newReader("negotiate context", buf)
	s.ContextType = r.u16()
	s.DataLength = r.u16()
	s.Reserved = r.u32()
	s.Data = r.next(int(s.DataLength))
	return r.err
}

// NegContextSize returns the on-wire size of the context including the
// alignment padding that must precede the next one.
func (s *NegContext) NegContextSize() int {
	size := negContextHeaderSize + int(s.DataLength)
	if rem := size % 8; rem != 0 {
		size += 8 - rem
	}
	return size
}

func (s *PreauthIntegrityContext) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 4+len(s.HashAlgorithms)*2+len(s.Salt))
	buf = binary.LittleEndian.AppendUint16(buf, s.HashAlgorithmCount)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Salt)))
	for _, h := range s.HashAlgorithms {
		buf = binary.LittleEndian.AppendUint16(buf, h)
	}
	return append(buf, s.Salt...), nil
}

func (s *PreauthIntegrityContext) UnmarshalBinary(buf []byte) error {
	r := newReader("preauth integrity context", buf)
	s.HashAlgorithmCount = r.u16()
	s.SaltLength = r.u16()
	s.HashAlgorithms = r.u16s(int(s.HashAlgorithmCount))
	s.Salt = r.next(int(s.SaltLength))
	return r.err
}

func (s *EncryptionContext) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 2+len(s.Ciphers)*2)
	buf = binary.LittleEndian.AppendUint16(buf, s.CipherCount)
	for _, c := range s.Ciphers {
		buf = binary.LittleEndian.AppendUint16(buf, c)
	}
	return buf, nil
}

func (s *EncryptionContext) UnmarshalBinary(buf []byte) error {
	r := newReader("encryption context", buf)
	s.CipherCount = r.u16()
	s.Ciphers = r.u16s(int(s.CipherCount))
	return r.err
}

func (s *CompressionContext) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 8+len(s.CompressionAlgorithms)*2)
	buf = binary.LittleEndian.AppendUint16(buf, s.CompressionAlgorithmCount)
	buf = binary.LittleEndian.AppendUint16(buf, s.Padding)
	buf = binary.LittleEndian.AppendUint32(buf, s.Flags)
	for _, a := range s.CompressionAlgorithms {
		buf = binary.LittleEndian.AppendUint16(buf, a)
	}
	return buf, nil
}

func (s *CompressionContext) UnmarshalBinary(buf []byte) error {
	r := newReader("compression context", buf)
	s.CompressionAlgorithmCount = r.u16()
	s.Padding = r.u16()
	s.Flags = r.u32()
	s.CompressionAlgorithms = r.u16s(int(s.CompressionAlgorithmCount))
	return r.err
}

func (s *SigningContext) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, 2+len(s.SigningAlgorithms)*2)
	buf = binary.LittleEndian.AppendUint16(buf, s.SigningAlgorithmCount)
	for _, a := range s.SigningAlgorithms {
		buf = binary.LittleEndian.AppendUint16(buf, a)
	}
	return buf, nil
}

func (s *SigningContext) UnmarshalBinary(buf []byte) error {
	r := newReader("signing context", buf)
	s.SigningAlgorithmCount = r.u16()
	s.SigningAlgorithms = r.u16s(int(s.SigningAlgorithmCount))
	return r.err
}

// ------------------------------------------------------------------ negotiate

func (s *NegotiateRes) MarshalBinary() ([]byte, error) {
	var blob []byte
	var err error
	if s.SecurityBlob != nil {
		if blob, err = s.SecurityBlob.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	contexts, err := marshalNegContextList(s.ContextList)
	if err != nil {
		return nil, err
	}

	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+negotiateResBodySize+len(blob)+len(contexts)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.SecurityMode)
	buf = binary.LittleEndian.AppendUint16(buf, s.DialectRevision)
	buf = binary.LittleEndian.AppendUint16(buf, s.NegotiateContextCount)
	buf = appendFixed(buf, s.ServerGuid, 16)
	buf = binary.LittleEndian.AppendUint32(buf, s.Capabilities)
	buf = binary.LittleEndian.AppendUint32(buf, s.MaxTransactSize)
	buf = binary.LittleEndian.AppendUint32(buf, s.MaxReadSize)
	buf = binary.LittleEndian.AppendUint32(buf, s.MaxWriteSize)
	buf = binary.LittleEndian.AppendUint64(buf, s.SystemTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.ServerStartTime)

	blobOffset := headerSize + negotiateResBodySize
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(blobOffset, len(blob))))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(blob)))
	// The context list follows the blob plus the caller-supplied Padding, which
	// is what aligns NegotiateContextOffset to 8 bytes (MS-SMB2 §2.2.4).
	ctxOffset := blobOffset + len(blob) + len(s.Padding)
	buf = binary.LittleEndian.AppendUint32(buf, payloadOffset(ctxOffset, len(contexts)))
	buf = append(buf, blob...)
	buf = append(buf, s.Padding...)
	return append(buf, contexts...), nil
}

func (s *NegotiateRes) UnmarshalBinary(buf []byte) error {
	r := newReader("NegotiateRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.SecurityMode = r.u16()
	s.DialectRevision = r.u16()
	s.NegotiateContextCount = r.u16()
	s.ServerGuid = r.next(16)
	s.Capabilities = r.u32()
	s.MaxTransactSize = r.u32()
	s.MaxReadSize = r.u32()
	s.MaxWriteSize = r.u32()
	s.SystemTime = r.u64()
	s.ServerStartTime = r.u64()
	s.SecurityBufferOffset = r.u16()
	s.SecurityBufferLength = r.u16()
	s.NegotiateContextOffset = r.u32()
	if r.err != nil {
		return r.err
	}

	blob := r.at("SecurityBlob", uint64(s.SecurityBufferOffset), uint64(s.SecurityBufferLength))
	if r.err != nil {
		return r.err
	}
	s.SecurityBlob = &gss.NegTokenInit{}
	if len(blob) > 0 {
		if err := s.SecurityBlob.UnmarshalBinary(blob); err != nil {
			return fmt.Errorf("NegotiateRes: decoding SecurityBlob: %w", err)
		}
	}

	s.ContextList = nil
	offset := int(s.NegotiateContextOffset)
	for i := 0; i < int(s.NegotiateContextCount); i++ {
		if offset < 0 || offset > len(buf) {
			return fmt.Errorf("NegotiateRes: negotiate context %d starts at %d, outside the %d-byte PDU", i, offset, len(buf))
		}
		var ctx NegContext
		if err := ctx.UnmarshalBinary(buf[offset:]); err != nil {
			return err
		}
		s.ContextList = append(s.ContextList, ctx)
		offset += ctx.NegContextSize()
	}
	return nil
}

// -------------------------------------------------------------- session setup

// marshalSessionSetupReq emits the shared SESSION_SETUP request body. blob is
// the already-serialized security blob.
func marshalSessionSetupReq(h *Header, structureSize uint16, flags, securityMode byte,
	capabilities, channel uint32, previousSessionID uint64, blob []byte) ([]byte, error) {

	buf, err := h.marshalInto(make([]byte, 0, headerSize+sessionSetupReqBody+len(blob)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, structureSize)
	buf = append(buf, flags, securityMode)
	buf = binary.LittleEndian.AppendUint32(buf, capabilities)
	buf = binary.LittleEndian.AppendUint32(buf, channel)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+sessionSetupReqBody, len(blob))))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(blob)))
	buf = binary.LittleEndian.AppendUint64(buf, previousSessionID)
	return append(buf, blob...), nil
}

// sessionSetupReqFields decodes the shared request body, returning the raw
// security blob bytes.
func (s *SessionSetupReq) unmarshalCommon(buf []byte) ([]byte, error) {
	r := newReader("SessionSetupReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Flags = r.u8()
	s.SecurityMode = r.u8()
	s.Capabilities = r.u32()
	s.Channel = r.u32()
	s.SecurityBufferOffset = r.u16()
	s.SecurityBufferLength = r.u16()
	s.PreviousSessionID = r.u64()
	blob := r.at("SecurityBlob", uint64(s.SecurityBufferOffset), uint64(s.SecurityBufferLength))
	return blob, r.err
}

func (s *SessionSetupReq) MarshalBinary() ([]byte, error) {
	return marshalSessionSetupReq(&s.Header, s.StructureSize, s.Flags, s.SecurityMode,
		s.Capabilities, s.Channel, s.PreviousSessionID, s.SecurityBlob)
}

func (s *SessionSetupReq) UnmarshalBinary(buf []byte) error {
	blob, err := s.unmarshalCommon(buf)
	if err != nil {
		return err
	}
	s.SecurityBlob = blob
	return nil
}

func (s *SessionSetup1Req) MarshalBinary() ([]byte, error) {
	var blob []byte
	if s.SecurityBlob != nil {
		var err error
		if blob, err = s.SecurityBlob.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return marshalSessionSetupReq(&s.Header, s.StructureSize, s.Flags, s.SecurityMode,
		s.Capabilities, s.Channel, s.PreviousSessionID, blob)
}

func (s *SessionSetup1Req) UnmarshalBinary(buf []byte) error {
	var raw SessionSetupReq
	blob, err := raw.unmarshalCommon(buf)
	if err != nil {
		return err
	}
	s.Header = raw.Header
	s.StructureSize, s.Flags, s.SecurityMode = raw.StructureSize, raw.Flags, raw.SecurityMode
	s.Capabilities, s.Channel = raw.Capabilities, raw.Channel
	s.SecurityBufferOffset, s.SecurityBufferLength = raw.SecurityBufferOffset, raw.SecurityBufferLength
	s.PreviousSessionID = raw.PreviousSessionID
	s.SecurityBlob = &gss.NegTokenInit{}
	if len(blob) > 0 {
		if err := s.SecurityBlob.UnmarshalBinary(blob); err != nil {
			return fmt.Errorf("SessionSetup1Req: decoding SecurityBlob: %w", err)
		}
	}
	return nil
}

func (s *SessionSetup2Req) MarshalBinary() ([]byte, error) {
	var blob []byte
	if s.SecurityBlob != nil {
		var err error
		if blob, err = s.SecurityBlob.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return marshalSessionSetupReq(&s.Header, s.StructureSize, s.Flags, s.SecurityMode,
		s.Capabilities, s.Channel, s.PreviousSessionID, blob)
}

func (s *SessionSetup2Req) UnmarshalBinary(buf []byte) error {
	var raw SessionSetupReq
	blob, err := raw.unmarshalCommon(buf)
	if err != nil {
		return err
	}
	s.Header = raw.Header
	s.StructureSize, s.Flags, s.SecurityMode = raw.StructureSize, raw.Flags, raw.SecurityMode
	s.Capabilities, s.Channel = raw.Capabilities, raw.Channel
	s.SecurityBufferOffset, s.SecurityBufferLength = raw.SecurityBufferOffset, raw.SecurityBufferLength
	s.PreviousSessionID = raw.PreviousSessionID
	s.SecurityBlob = &gss.NegTokenResp{}
	if len(blob) > 0 {
		if err := s.SecurityBlob.UnmarshalBinary(blob); err != nil {
			return fmt.Errorf("SessionSetup2Req: decoding SecurityBlob: %w", err)
		}
	}
	return nil
}

// marshalSessionSetupRes emits the shared SESSION_SETUP response body.
func marshalSessionSetupRes(h *Header, structureSize, flags uint16, blob []byte) ([]byte, error) {
	buf, err := h.marshalInto(make([]byte, 0, headerSize+sessionSetupResBody+len(blob)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, structureSize)
	buf = binary.LittleEndian.AppendUint16(buf, flags)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+sessionSetupResBody, len(blob))))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(blob)))
	return append(buf, blob...), nil
}

// unmarshalSessionSetupRes decodes the shared response body and returns the raw
// security blob.
func unmarshalSessionSetupRes(what string, buf []byte, h *Header, structureSize, flags, bufOffset, bufLength *uint16) ([]byte, error) {
	r := newReader(what, buf)
	if err := h.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	r.skip(headerSize)
	*structureSize = r.u16()
	*flags = r.u16()
	*bufOffset = r.u16()
	*bufLength = r.u16()
	blob := r.at("SecurityBlob", uint64(*bufOffset), uint64(*bufLength))
	return blob, r.err
}

func (s *SessionSetupRes) MarshalBinary() ([]byte, error) {
	return marshalSessionSetupRes(&s.Header, s.StructureSize, s.Flags, s.SecurityBlob)
}

func (s *SessionSetupRes) UnmarshalBinary(buf []byte) error {
	blob, err := unmarshalSessionSetupRes("SessionSetupRes", buf, &s.Header,
		&s.StructureSize, &s.Flags, &s.SecurityBufferOffset, &s.SecurityBufferLength)
	if err != nil {
		return err
	}
	s.SecurityBlob = blob
	return nil
}

func (s *SessionSetup1Res) MarshalBinary() ([]byte, error) {
	var blob []byte
	if s.SecurityBlob != nil {
		var err error
		if blob, err = s.SecurityBlob.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return marshalSessionSetupRes(&s.Header, s.StructureSize, s.Flags, blob)
}

func (s *SessionSetup1Res) UnmarshalBinary(buf []byte) error {
	blob, err := unmarshalSessionSetupRes("SessionSetup1Res", buf, &s.Header,
		&s.StructureSize, &s.Flags, &s.SecurityBufferOffset, &s.SecurityBufferLength)
	if err != nil {
		return err
	}
	s.SecurityBlob = &gss.NegTokenResp{}
	if len(blob) > 0 {
		if err := s.SecurityBlob.UnmarshalBinary(blob); err != nil {
			return fmt.Errorf("SessionSetup1Res: decoding SecurityBlob: %w", err)
		}
	}
	return nil
}

func (s *SessionSetup2Res) MarshalBinary() ([]byte, error) {
	var blob []byte
	if s.SecurityBlob != nil {
		var err error
		if blob, err = s.SecurityBlob.MarshalBinary(); err != nil {
			return nil, err
		}
	}
	return marshalSessionSetupRes(&s.Header, s.StructureSize, s.Flags, blob)
}

func (s *SessionSetup2Res) UnmarshalBinary(buf []byte) error {
	blob, err := unmarshalSessionSetupRes("SessionSetup2Res", buf, &s.Header,
		&s.StructureSize, &s.Flags, &s.SecurityBufferOffset, &s.SecurityBufferLength)
	if err != nil {
		return err
	}
	s.SecurityBlob = &gss.NegTokenResp{}
	if len(blob) > 0 {
		if err := s.SecurityBlob.UnmarshalBinary(blob); err != nil {
			return fmt.Errorf("SessionSetup2Res: decoding SecurityBlob: %w", err)
		}
	}
	return nil
}

// ------------------------------------------------- fixed-body request/response

// marshalStructureSizeOnly emits a PDU whose whole body is StructureSize plus a
// 2-byte reserved field: LOGOFF, TREE_DISCONNECT, ECHO, CANCEL and FLUSH's
// response all share that shape.
func marshalStructureSizeOnly(h *Header, structureSize, reserved uint16) ([]byte, error) {
	buf, err := h.marshalInto(make([]byte, 0, headerSize+structureSizeOnlyBody))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, structureSize)
	return binary.LittleEndian.AppendUint16(buf, reserved), nil
}

func unmarshalStructureSizeOnly(what string, buf []byte, h *Header, structureSize, reserved *uint16) error {
	r := newReader(what, buf)
	if err := h.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	*structureSize = r.u16()
	*reserved = r.u16()
	return r.err
}

func (s *LogoffReq) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *LogoffReq) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("LogoffReq", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *LogoffRes) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *LogoffRes) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("LogoffRes", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *TreeDisconnectReq) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *TreeDisconnectReq) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("TreeDisconnectReq", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *TreeDisconnectRes) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *TreeDisconnectRes) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("TreeDisconnectRes", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *EchoReq) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *EchoReq) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("EchoReq", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *EchoRes) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *EchoRes) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("EchoRes", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *CancelReq) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *CancelReq) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("CancelReq", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *FlushRes) MarshalBinary() ([]byte, error) {
	return marshalStructureSizeOnly(&s.Header, s.StructureSize, s.Reserved)
}

func (s *FlushRes) UnmarshalBinary(buf []byte) error {
	return unmarshalStructureSizeOnly("FlushRes", buf, &s.Header, &s.StructureSize, &s.Reserved)
}

func (s *SetInfoRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+setInfoResBodySize))
	if err != nil {
		return nil, err
	}
	return binary.LittleEndian.AppendUint16(buf, s.StructureSize), nil
}

func (s *SetInfoRes) UnmarshalBinary(buf []byte) error {
	r := newReader("SetInfoRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	return r.err
}

// ---------------------------------------------------------------- tree connect

func (s *TreeConnectReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+treeConnectReqBody+len(s.Path)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+treeConnectReqBody, len(s.Path))))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Path)))
	return append(buf, s.Path...), nil
}

func (s *TreeConnectReq) UnmarshalBinary(buf []byte) error {
	r := newReader("TreeConnectReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Reserved = r.u16()
	s.PathOffset = r.u16()
	s.PathLength = r.u16()
	s.Path = r.at("Path", uint64(s.PathOffset), uint64(s.PathLength))
	return r.err
}

func (s *TreeConnectRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+treeConnectResBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = append(buf, s.ShareType, s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, s.ShareFlags)
	buf = binary.LittleEndian.AppendUint32(buf, s.Capabilities)
	return binary.LittleEndian.AppendUint32(buf, s.MaximalAccess), nil
}

func (s *TreeConnectRes) UnmarshalBinary(buf []byte) error {
	r := newReader("TreeConnectRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.ShareType = r.u8()
	s.Reserved = r.u8()
	s.ShareFlags = r.u32()
	s.Capabilities = r.u32()
	s.MaximalAccess = r.u32()
	return r.err
}

// --------------------------------------------------------------- create/close

func (s *CreateRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+createResBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = append(buf, s.OplockLevel, s.Flags)
	buf = binary.LittleEndian.AppendUint32(buf, s.CreateAction)
	buf = binary.LittleEndian.AppendUint64(buf, s.CreationTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastAccessTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastWriteTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.ChangeTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.AllocationSize)
	buf = binary.LittleEndian.AppendUint64(buf, s.EndOfFile)
	buf = binary.LittleEndian.AppendUint32(buf, s.FileAttributes)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved2)
	buf = appendFixed(buf, s.FileId, 16)
	buf = binary.LittleEndian.AppendUint32(buf, payloadOffset(headerSize+createResBodySize, len(s.Buffer)))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	return append(buf, s.Buffer...), nil
}

func (s *CreateRes) UnmarshalBinary(buf []byte) error {
	r := newReader("CreateRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.OplockLevel = r.u8()
	s.Flags = r.u8()
	s.CreateAction = r.u32()
	s.CreationTime = r.u64()
	s.LastAccessTime = r.u64()
	s.LastWriteTime = r.u64()
	s.ChangeTime = r.u64()
	s.AllocationSize = r.u64()
	s.EndOfFile = r.u64()
	s.FileAttributes = r.u32()
	s.Reserved2 = r.u32()
	s.FileId = r.next(16)
	s.CreateContextsOffset = r.u32()
	s.CreateContextsLength = r.u32()
	s.Buffer = r.at("CreateContexts", uint64(s.CreateContextsOffset), uint64(s.CreateContextsLength))
	return r.err
}

func (s *CloseReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+closeReqBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Flags)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved)
	return appendFixed(buf, s.FileId, 16), nil
}

func (s *CloseReq) UnmarshalBinary(buf []byte) error {
	r := newReader("CloseReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Flags = r.u16()
	s.Reserved = r.u32()
	s.FileId = r.next(16)
	return r.err
}

func (s *CloseRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+closeResBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Flags)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint64(buf, s.CreationTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastAccessTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastWriteTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.ChangeTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.AllocationSize)
	buf = binary.LittleEndian.AppendUint64(buf, s.EndOfFile)
	return binary.LittleEndian.AppendUint32(buf, s.FileAttributes), nil
}

func (s *CloseRes) UnmarshalBinary(buf []byte) error {
	r := newReader("CloseRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Flags = r.u16()
	s.Reserved = r.u32()
	s.CreationTime = r.u64()
	s.LastAccessTime = r.u64()
	s.LastWriteTime = r.u64()
	s.ChangeTime = r.u64()
	s.AllocationSize = r.u64()
	s.EndOfFile = r.u64()
	s.FileAttributes = r.u32()
	return r.err
}

func (s *OplockBreak) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+oplockBreakBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = append(buf, s.OplockLevel, s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved2)
	return appendFixed(buf, s.FileId, 16), nil
}

func (s *OplockBreak) UnmarshalBinary(buf []byte) error {
	r := newReader("OplockBreak", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.OplockLevel = r.u8()
	s.Reserved = r.u8()
	s.Reserved2 = r.u32()
	s.FileId = r.next(16)
	return r.err
}

func (s *FlushReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+flushReqBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved1)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved2)
	return appendFixed(buf, s.FileId, 16), nil
}

func (s *FlushReq) UnmarshalBinary(buf []byte) error {
	r := newReader("FlushReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Reserved1 = r.u16()
	s.Reserved2 = r.u32()
	s.FileId = r.next(16)
	return r.err
}

// ------------------------------------------------------------ query directory

func (s *QueryDirectoryReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+queryDirReqBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = append(buf, s.FileInformationClass, s.Flags)
	buf = binary.LittleEndian.AppendUint32(buf, s.FileIndex)
	buf = appendFixed(buf, s.FileID, 16)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+queryDirReqBodySize, len(s.Buffer))))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Buffer)))
	buf = binary.LittleEndian.AppendUint32(buf, s.OutputBufferLength)
	return append(buf, s.Buffer...), nil
}

func (s *QueryDirectoryReq) UnmarshalBinary(buf []byte) error {
	r := newReader("QueryDirectoryReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.FileInformationClass = r.u8()
	s.Flags = r.u8()
	s.FileIndex = r.u32()
	s.FileID = r.next(16)
	s.FileNameOffset = r.u16()
	s.FileNameLength = r.u16()
	s.OutputBufferLength = r.u32()
	s.Buffer = r.at("FileName", uint64(s.FileNameOffset), uint64(s.FileNameLength))
	return r.err
}

func (s *QueryDirectoryRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+queryDirResBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+queryDirResBodySize, len(s.Buffer))))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	return append(buf, s.Buffer...), nil
}

func (s *QueryDirectoryRes) UnmarshalBinary(buf []byte) error {
	r := newReader("QueryDirectoryRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.OutputBufferOffset = r.u16()
	s.OutputBufferLength = r.u32()
	s.Buffer = r.at("OutputBuffer", uint64(s.OutputBufferOffset), uint64(s.OutputBufferLength))
	return r.err
}

func (s *FileBothDirectoryInformationStruct) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 0, fileBothDirInfoFixed+len(s.FileName))
	buf = binary.LittleEndian.AppendUint32(buf, s.NextEntryOffset)
	buf = binary.LittleEndian.AppendUint32(buf, s.FileIndex)
	buf = binary.LittleEndian.AppendUint64(buf, s.CreationTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastAccessTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.LastWriteTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.ChangeTime)
	buf = binary.LittleEndian.AppendUint64(buf, s.EndOfFile)
	buf = binary.LittleEndian.AppendUint64(buf, s.AllocationSize)
	buf = binary.LittleEndian.AppendUint32(buf, s.FileAttributes)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.FileName)))
	buf = binary.LittleEndian.AppendUint32(buf, s.EaSize)
	buf = append(buf, s.ShortNameLength, s.Reserved)
	buf = appendFixed(buf, s.ShortName, 24)
	return append(buf, s.FileName...), nil
}

func (s *FileBothDirectoryInformationStruct) UnmarshalBinary(buf []byte) error {
	r := newReader("FileBothDirectoryInformation", buf)
	s.NextEntryOffset = r.u32()
	s.FileIndex = r.u32()
	s.CreationTime = r.u64()
	s.LastAccessTime = r.u64()
	s.LastWriteTime = r.u64()
	s.ChangeTime = r.u64()
	s.EndOfFile = r.u64()
	s.AllocationSize = r.u64()
	s.FileAttributes = r.u32()
	s.FileNameLength = r.u32()
	s.EaSize = r.u32()
	s.ShortNameLength = r.u8()
	s.Reserved = r.u8()
	s.ShortName = r.next(24)
	s.FileName = r.next(int(s.FileNameLength))
	return r.err
}

// --------------------------------------------------------------- read / write

func (s *ReadRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+readResBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	// DataOffset is a single byte, so it can only ever describe an offset up to
	// 255; 64+16 always fits.
	buf = append(buf, byte(payloadOffset(headerSize+readResBodySize, len(s.Buffer))), s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	buf = binary.LittleEndian.AppendUint32(buf, s.DataRemaining)
	buf = binary.LittleEndian.AppendUint32(buf, s.Reserved2)
	return append(buf, s.Buffer...), nil
}

func (s *ReadRes) UnmarshalBinary(buf []byte) error {
	r := newReader("ReadRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.DataOffset = r.u8()
	s.Reserved = r.u8()
	s.DataLength = r.u32()
	s.DataRemaining = r.u32()
	s.Reserved2 = r.u32()
	s.Buffer = r.at("Data", uint64(s.DataOffset), uint64(s.DataLength))
	return r.err
}

func (s *WriteReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+writeReqBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+writeReqBodySize, len(s.Buffer))))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	buf = binary.LittleEndian.AppendUint64(buf, s.Offset)
	buf = appendFixed(buf, s.FileId, 16)
	buf = binary.LittleEndian.AppendUint32(buf, s.Channel)
	buf = binary.LittleEndian.AppendUint32(buf, s.RemainingBytes)
	buf = binary.LittleEndian.AppendUint16(buf, s.WriteChannelInfoOffset)
	buf = binary.LittleEndian.AppendUint16(buf, s.WriteChannelInfoLength)
	buf = binary.LittleEndian.AppendUint32(buf, s.Flags)
	return append(buf, s.Buffer...), nil
}

func (s *WriteReq) UnmarshalBinary(buf []byte) error {
	r := newReader("WriteReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.DataOffset = r.u16()
	s.Length = r.u32()
	s.Offset = r.u64()
	s.FileId = r.next(16)
	s.Channel = r.u32()
	s.RemainingBytes = r.u32()
	s.WriteChannelInfoOffset = r.u16()
	s.WriteChannelInfoLength = r.u16()
	s.Flags = r.u32()
	s.Buffer = r.at("Data", uint64(s.DataOffset), uint64(s.Length))
	return r.err
}

func (s *WriteRes) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+writeResBodySize))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, s.Count)
	buf = binary.LittleEndian.AppendUint32(buf, s.Remaining)
	buf = binary.LittleEndian.AppendUint16(buf, s.WriteChannelInfoOffset)
	return binary.LittleEndian.AppendUint16(buf, s.WriteChannelInfoLength), nil
}

func (s *WriteRes) UnmarshalBinary(buf []byte) error {
	r := newReader("WriteRes", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.Reserved = r.u16()
	s.Count = r.u32()
	s.Remaining = r.u32()
	s.WriteChannelInfoOffset = r.u16()
	s.WriteChannelInfoLength = r.u16()
	return r.err
}

func (s *SetInfoReq) MarshalBinary() ([]byte, error) {
	buf, err := s.Header.marshalInto(make([]byte, 0, headerSize+setInfoReqBodySize+len(s.Buffer)))
	if err != nil {
		return nil, err
	}
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	buf = append(buf, s.InfoType, s.FileInfoClass)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	buf = binary.LittleEndian.AppendUint16(buf, uint16(payloadOffset(headerSize+setInfoReqBodySize, len(s.Buffer))))
	buf = binary.LittleEndian.AppendUint16(buf, s.Reserved)
	buf = binary.LittleEndian.AppendUint32(buf, s.AdditionalInformation)
	buf = appendFixed(buf, s.FileId, 16)
	return append(buf, s.Buffer...), nil
}

func (s *SetInfoReq) UnmarshalBinary(buf []byte) error {
	r := newReader("SetInfoReq", buf)
	if err := s.Header.UnmarshalBinary(buf); err != nil {
		return err
	}
	r.skip(headerSize)
	s.StructureSize = r.u16()
	s.InfoType = r.u8()
	s.FileInfoClass = r.u8()
	s.BufferLength = r.u32()
	s.BufferOffset = r.u16()
	s.Reserved = r.u16()
	s.AdditionalInformation = r.u32()
	s.FileId = r.next(16)
	s.Buffer = r.at("Buffer", uint64(s.BufferOffset), uint64(s.BufferLength))
	return r.err
}

// Marshaller is implemented by every SMB2 structure in this package. It is what
// Connection.send and the server's reply helpers accept, so the compiler —
// rather than a runtime type assertion — enforces that a PDU knows how to
// serialize itself. Note the pointer receivers: pass &req, not req.
type Marshaller interface {
	MarshalBinary() ([]byte, error)
}
