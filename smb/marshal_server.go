// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
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

package smb

// Marshal/Unmarshal pairs for the server-side direction. The reflection
// encoder in smb/encoder handles most PDU types in both directions, but a few
// have layouts that don't fit its tag model (variable-offset Name +
// CreateContexts that share the trailing buffer, structure sizes the encoder
// can't precompute, etc.). Those are hand-rolled here.

import (
	"encoding/binary"
	"fmt"
)

// ---------------------------------------------------------------------------
// QueryInfoReq.UnmarshalBinary
// ---------------------------------------------------------------------------

// UnmarshalBinary parses an inbound QueryInfo request. The reflection encoder
// can't drive this because the Buffer slice's length is encoded as
// InputBufferLength (uint32) rather than via a tag.
func (s *QueryInfoReq) UnmarshalBinary(buf []byte) error {
	if len(buf) < 64+40 {
		return fmt.Errorf("QueryInfoReq: buffer too short (%d bytes)", len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf[:64]); err != nil {
		return err
	}
	off := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.InfoType = buf[off]
	off++
	s.FileInfoClass = buf[off]
	off++
	s.OutputBufferLength = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.InputBufferOffset = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.Reserved = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.InputBufferLength = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.AdditionalInformation = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.Flags = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.FileId = make([]byte, 16)
	copy(s.FileId, buf[off:off+16])
	off += 16

	if s.InputBufferLength > 0 {
		start := int(s.InputBufferOffset)
		end := start + int(s.InputBufferLength)
		if start < off || end > len(buf) {
			return fmt.Errorf("QueryInfoReq: bad InputBuffer range [%d:%d] in %d-byte msg", start, end, len(buf))
		}
		s.Buffer = make([]byte, s.InputBufferLength)
		copy(s.Buffer, buf[start:end])
	}
	return nil
}

// ---------------------------------------------------------------------------
// QueryInfoRes.MarshalBinary
// ---------------------------------------------------------------------------

// MarshalBinary serializes an outbound QueryInfo response. The reflection
// encoder can't drive this because OutputBufferOffset/Length aren't tagged.
func (s *QueryInfoRes) MarshalBinary() ([]byte, error) {
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hBuf)+8+len(s.Buffer))
	out = append(out, hBuf...)

	out = binary.LittleEndian.AppendUint16(out, 9) // StructureSize must be 9.
	bufOff := uint16(0)
	if len(s.Buffer) > 0 {
		bufOff = 64 + 8 // 64-byte SMB2 header + 8-byte fixed body.
	}
	out = binary.LittleEndian.AppendUint16(out, bufOff)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(s.Buffer)))
	out = append(out, s.Buffer...)
	return out, nil
}

// ---------------------------------------------------------------------------
// ReadReq.MarshalBinary / UnmarshalBinary
// ---------------------------------------------------------------------------

// MarshalBinary serializes a Read request. Used by the in-tree client to send
// a READ; the server's counterpart is UnmarshalBinary below.
func (s *ReadReq) MarshalBinary() ([]byte, error) {
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	fid := s.FileId
	if len(fid) != 16 {
		fid = make([]byte, 16)
		copy(fid, s.FileId)
	}
	out := make([]byte, 0, len(hBuf)+48+len(s.Buffer)+1)
	out = append(out, hBuf...)
	out = binary.LittleEndian.AppendUint16(out, s.StructureSize)
	out = append(out, s.Padding)
	out = append(out, s.Flags)
	out = binary.LittleEndian.AppendUint32(out, s.Length)
	out = binary.LittleEndian.AppendUint64(out, s.Offset)
	out = append(out, fid...)
	out = binary.LittleEndian.AppendUint32(out, s.MinimumCount)
	out = binary.LittleEndian.AppendUint32(out, s.Channel)
	out = binary.LittleEndian.AppendUint32(out, s.RemainingBytes)
	out = binary.LittleEndian.AppendUint16(out, s.ReadChannelInfoOffset)
	out = binary.LittleEndian.AppendUint16(out, s.ReadChannelInfoLength)
	if len(s.Buffer) > 0 {
		out = append(out, s.Buffer...)
	} else {
		// Spec requires Buffer to be at least 1 byte even if empty.
		out = append(out, 0)
	}
	return out, nil
}

// UnmarshalBinary parses an inbound Read request. The reflection encoder
// can't drive this because Buffer has no `len:` tag (it's documented as
// 0-length for SMB 2.1).
func (s *ReadReq) UnmarshalBinary(buf []byte) error {
	if len(buf) < 64+48 {
		return fmt.Errorf("ReadReq: buffer too short (%d bytes)", len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf[:64]); err != nil {
		return err
	}
	off := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.Padding = buf[off]
	off++
	s.Flags = buf[off]
	off++
	s.Length = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.Offset = binary.LittleEndian.Uint64(buf[off : off+8])
	off += 8
	s.FileId = make([]byte, 16)
	copy(s.FileId, buf[off:off+16])
	off += 16
	s.MinimumCount = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.Channel = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.RemainingBytes = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.ReadChannelInfoOffset = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.ReadChannelInfoLength = binary.LittleEndian.Uint16(buf[off : off+2])
	// Buffer left empty for SMB 2.1; ignore trailing padding byte.
	return nil
}

// ---------------------------------------------------------------------------
// CreateReq.MarshalBinary / UnmarshalBinary
// ---------------------------------------------------------------------------

// MarshalBinary serializes a Create request. Used by the in-tree client to send
// a CREATE; the server's counterpart is UnmarshalBinary below.
func (s *CreateReq) MarshalBinary() ([]byte, error) {
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(hBuf)+56+len(s.Buffer))
	out = append(out, hBuf...)
	out = binary.LittleEndian.AppendUint16(out, s.StructureSize)
	out = append(out, s.SecurityFlags)
	out = append(out, s.RequestedOplockLevel)
	out = binary.LittleEndian.AppendUint32(out, s.ImpersonationLevel)
	out = binary.LittleEndian.AppendUint64(out, s.SmbCreateFlags)
	out = binary.LittleEndian.AppendUint64(out, s.Reserved)
	out = binary.LittleEndian.AppendUint32(out, s.DesiredAccess)
	out = binary.LittleEndian.AppendUint32(out, s.FileAttributes)
	out = binary.LittleEndian.AppendUint32(out, s.ShareAccess)
	out = binary.LittleEndian.AppendUint32(out, s.CreateDisposition)
	out = binary.LittleEndian.AppendUint32(out, s.CreateOptions)
	out = binary.LittleEndian.AppendUint16(out, s.NameOffset)
	out = binary.LittleEndian.AppendUint16(out, s.NameLength)
	out = binary.LittleEndian.AppendUint32(out, s.CreateContextsOffset)
	out = binary.LittleEndian.AppendUint32(out, s.CreateContextsLength)
	if len(s.Buffer) > 0 {
		out = append(out, s.Buffer...)
	} else {
		// Spec requires Buffer to be at least 1 byte even if empty.
		out = append(out, 0)
	}
	return out, nil
}

// UnmarshalBinary parses an inbound Create request. The reflection encoder
// can't drive this because Name and CreateContexts share the trailing Buffer
// slice and use untagged offset/length pairs.
func (s *CreateReq) UnmarshalBinary(buf []byte) error {
	if len(buf) < 64+57 {
		return fmt.Errorf("CreateReq: buffer too short (%d bytes)", len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf[:64]); err != nil {
		return err
	}
	off := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.SecurityFlags = buf[off]
	off++
	s.RequestedOplockLevel = buf[off]
	off++
	s.ImpersonationLevel = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.SmbCreateFlags = binary.LittleEndian.Uint64(buf[off : off+8])
	off += 8
	s.Reserved = binary.LittleEndian.Uint64(buf[off : off+8])
	off += 8
	s.DesiredAccess = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.FileAttributes = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.ShareAccess = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.CreateDisposition = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.CreateOptions = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.NameOffset = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.NameLength = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.CreateContextsOffset = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.CreateContextsLength = binary.LittleEndian.Uint32(buf[off : off+4])

	// The trailing Buffer is the union of Name + alignment + CreateContexts.
	// Stash it from NameOffset (when present) or CreateContextsOffset to the
	// end of the message; handlers slice Name/CreateContexts back out.
	bufStart := uint32(0)
	switch {
	case s.NameOffset > 0:
		bufStart = uint32(s.NameOffset)
	case s.CreateContextsOffset > 0:
		bufStart = s.CreateContextsOffset
	default:
		// At least 1 byte of Buffer is required by the spec; anchor to the
		// fixed layout end.
		bufStart = 64 + 56
	}
	if int(bufStart) > len(buf) {
		return fmt.Errorf("CreateReq: Buffer offset %d > msg %d", bufStart, len(buf))
	}
	s.Buffer = make([]byte, len(buf)-int(bufStart))
	copy(s.Buffer, buf[bufStart:])
	return nil
}

// CreateReqName extracts the unicode name from a parsed CreateReq's Buffer.
// Returns an empty string if NameLength is zero.
func (s *CreateReq) CreateReqName() ([]byte, error) {
	if s.NameLength == 0 {
		return nil, nil
	}
	bufStart := uint32(s.NameOffset)
	if bufStart == 0 {
		bufStart = 64 + 56
	}
	// Buffer in our parsed form starts at bufStart; shift accordingly.
	relStart := uint32(s.NameOffset) - bufStart
	relEnd := relStart + uint32(s.NameLength)
	if int(relEnd) > len(s.Buffer) {
		return nil, fmt.Errorf("CreateReq: Name [%d:%d] exceeds Buffer (%d)", relStart, relEnd, len(s.Buffer))
	}
	return s.Buffer[relStart:relEnd], nil
}

// CreateReqContexts returns the raw CreateContexts blob from a parsed
// CreateReq's Buffer. Empty when CreateContextsLength == 0.
func (s *CreateReq) CreateReqContexts() ([]byte, error) {
	if s.CreateContextsLength == 0 {
		return nil, nil
	}
	bufStart := uint32(s.NameOffset)
	if bufStart == 0 {
		bufStart = s.CreateContextsOffset
	}
	relStart := s.CreateContextsOffset - bufStart
	relEnd := relStart + s.CreateContextsLength
	if int(relEnd) > len(s.Buffer) {
		return nil, fmt.Errorf("CreateReq: CreateContexts [%d:%d] exceeds Buffer (%d)", relStart, relEnd, len(s.Buffer))
	}
	return s.Buffer[relStart:relEnd], nil
}

// ---------------------------------------------------------------------------
// IoCtlReq.MarshalBinary / UnmarshalBinary
// ---------------------------------------------------------------------------

// MarshalBinary serializes an IOCTL request. Used by the in-tree client to send
// an IOCTL; the server's counterpart is UnmarshalBinary below.
func (s *IoCtlReq) MarshalBinary() ([]byte, error) {
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	fid := s.FileId
	if len(fid) != 16 {
		fid = make([]byte, 16)
		copy(fid, s.FileId)
	}
	out := make([]byte, 0, len(hBuf)+56+len(s.Buffer))
	out = append(out, hBuf...)
	out = binary.LittleEndian.AppendUint16(out, s.StructureSize)
	out = binary.LittleEndian.AppendUint16(out, s.Reserved)
	out = binary.LittleEndian.AppendUint32(out, s.CtlCode)
	out = append(out, fid...)
	inputOff := uint32(0)
	if len(s.Buffer) > 0 {
		inputOff = 64 + 56 // SMB2 header + IoCtlReq fixed body
	}
	out = binary.LittleEndian.AppendUint32(out, inputOff)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(s.Buffer)))
	out = binary.LittleEndian.AppendUint32(out, s.MaxInputResponse)
	out = binary.LittleEndian.AppendUint32(out, 0) // OutputOffset
	out = binary.LittleEndian.AppendUint32(out, 0) // OutputCount
	out = binary.LittleEndian.AppendUint32(out, s.MaxOutputResponse)
	out = binary.LittleEndian.AppendUint32(out, s.Flags)
	out = binary.LittleEndian.AppendUint32(out, s.Reserved2)
	out = append(out, s.Buffer...)
	return out, nil
}

// UnmarshalBinary parses an inbound IOCTL request. The reflection encoder's
// multi-offset-tag handling is unreliable for this layout (InputOffset and
// OutputOffset both reference the same Buffer field), so it's hand-rolled.
func (s *IoCtlReq) UnmarshalBinary(buf []byte) error {
	if len(buf) < 64+56 {
		return fmt.Errorf("IoCtlReq: buffer too short (%d bytes)", len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf[:64]); err != nil {
		return err
	}
	off := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.Reserved = binary.LittleEndian.Uint16(buf[off : off+2])
	off += 2
	s.CtlCode = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.FileId = make([]byte, 16)
	copy(s.FileId, buf[off:off+16])
	off += 16
	s.InputOffset = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.InputCount = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.MaxInputResponse = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.OutputOffset = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.OutputCount = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.MaxOutputResponse = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.Flags = binary.LittleEndian.Uint32(buf[off : off+4])
	off += 4
	s.Reserved2 = binary.LittleEndian.Uint32(buf[off : off+4])

	if s.InputCount > 0 {
		start := int(s.InputOffset)
		end := start + int(s.InputCount)
		if start < 64+56 || end > len(buf) {
			return fmt.Errorf("IoCtlReq: bad Input range [%d:%d] in %d-byte msg", start, end, len(buf))
		}
		s.Buffer = make([]byte, s.InputCount)
		copy(s.Buffer, buf[start:end])
	}
	return nil
}

// UnmarshalBinary parses an IOCTL Response (MS-SMB2 §2.2.32). Used by the
// in-tree client (smb.Connection.WriteIoCtlReq) to parse the server's reply;
// the server itself never receives an IOCTL response.
func (s *IoCtlRes) UnmarshalBinary(buf []byte) error {
	if len(buf) < 64+48 {
		return fmt.Errorf("IoCtlRes too short: %d bytes", len(buf))
	}
	if err := s.Header.UnmarshalBinary(buf[:64]); err != nil {
		return fmt.Errorf("IoCtlRes header: %w", err)
	}
	body := buf[64:]
	s.StructureSize = binary.LittleEndian.Uint16(body[0:2])
	s.Reserved = binary.LittleEndian.Uint16(body[2:4])
	s.CtlCode = binary.LittleEndian.Uint32(body[4:8])
	s.FileId = append([]byte(nil), body[8:24]...)
	s.InputOffset = binary.LittleEndian.Uint32(body[24:28])
	s.InputCount = binary.LittleEndian.Uint32(body[28:32])
	s.OutputOffset = binary.LittleEndian.Uint32(body[32:36])
	s.OutputCount = binary.LittleEndian.Uint32(body[36:40])
	s.Flags = binary.LittleEndian.Uint32(body[40:44])
	s.Reserved2 = binary.LittleEndian.Uint32(body[44:48])
	if s.OutputCount == 0 {
		s.Buffer = nil
		return nil
	}
	off := int(s.OutputOffset)
	end := off + int(s.OutputCount)
	if off < 64 || end > len(buf) {
		return fmt.Errorf("IoCtlRes Buffer [%d:%d] out of bounds (len=%d)", off, end, len(buf))
	}
	s.Buffer = append([]byte(nil), buf[off:end]...)
	return nil
}

// MarshalBinary writes an IOCTL Response (MS-SMB2 §2.2.32). The reflection
// encoder produces a malformed wire layout because IoCtlRes.Buffer is tagged
// as both the InputBuffer and OutputBuffer source — for a server-to-client
// IOCTL response only the OutputBuffer is meaningful (InputCount must be 0).
// Hand-rolled here so InputCount=0 / InputOffset=0 and OutputBuffer carries
// the payload at offset 64+48 = 112.
func (s *IoCtlRes) MarshalBinary() ([]byte, error) {
	hBuf, err := s.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	fid := s.FileId
	if len(fid) != 16 {
		fid = make([]byte, 16)
		copy(fid, s.FileId)
	}
	out := make([]byte, 0, len(hBuf)+48+len(s.Buffer))
	out = append(out, hBuf...)
	out = binary.LittleEndian.AppendUint16(out, 49) // StructureSize
	out = binary.LittleEndian.AppendUint16(out, 0)  // Reserved
	out = binary.LittleEndian.AppendUint32(out, s.CtlCode)
	out = append(out, fid...)
	// Server responses to a CtlCode never echo InputBuffer.
	out = binary.LittleEndian.AppendUint32(out, 0) // InputOffset
	out = binary.LittleEndian.AppendUint32(out, 0) // InputCount
	outputOff := uint32(0)
	if len(s.Buffer) > 0 {
		outputOff = 64 + 48 // SMB2 header + IoCtlRes fixed body
	}
	out = binary.LittleEndian.AppendUint32(out, outputOff)
	out = binary.LittleEndian.AppendUint32(out, uint32(len(s.Buffer)))
	out = binary.LittleEndian.AppendUint32(out, s.Flags)
	out = binary.LittleEndian.AppendUint32(out, 0) // Reserved2
	out = append(out, s.Buffer...)
	return out, nil
}
