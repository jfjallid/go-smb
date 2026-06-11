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

package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// handleQueryInfo processes SMB2 QUERY_INFO. Three InfoTypes are supported:
//
//   - OInfoFile (0x01) — per-handle file info classes (Basic, Standard,
//     NetworkOpen, EndOfFile, AllInformation, etc.)
//   - OInfoFilesystem (0x02) — volume / attribute info classes
//   - OInfoSecurity (0x03) — security descriptor for the handle's object
//
// VFS hooks see the same InfoType / FileInfoClass byte and decide whether
// to fulfil the request themselves; if they return STATUS_NOT_SUPPORTED the
// server falls back to a default response built from the handle's Stat().
func (c *Conn) handleQueryInfo(ctx pduCtx, raw []byte, h *smb.Header) error {
	logger := c.logger()

	sess := c.session(h.SessionID)
	if sess == nil || !sess.Authenticated {
		logger.Debugf("QueryInfo: session %d not authenticated -> StatusUserSessionDeleted", h.SessionID)
		return c.writeRawError(ctx, h, smb.StatusUserSessionDeleted)
	}
	tree := sess.tree(h.TreeID)
	if tree == nil {
		logger.Debugf("QueryInfo: unknown TreeID %d -> StatusNetworkNameDeleted", h.TreeID)
		return c.writeRawError(ctx, h, smb.StatusNetworkNameDeleted)
	}
	var req smb.QueryInfoReq
	if err := encoder.Unmarshal(raw, &req); err != nil {
		logger.Errorf("QueryInfo: decode QueryInfoReq: %v", err)
		return formatErr("decode QueryInfoReq", err)
	}
	hndl := tree.lookupHandle(volatileFromFileID(req.FileId))
	// FILESYSTEM info works without a per-file handle in some clients, but
	// real Windows always passes a valid FID — reject if missing.
	if hndl == nil {
		logger.Debugf("QueryInfo from %s: tree=%d unknown volatileFID=%d -> StatusFileClosed",
			c.RemoteAddr, tree.ID, volatileFromFileID(req.FileId))
		return c.writeRawError(ctx, h, smb.StatusFileClosed)
	}

	switch req.InfoType {
	case smb.OInfoFile:
		return c.queryFileInfo(ctx, h, tree, hndl, &req)
	case smb.OInfoFilesystem:
		return c.queryFsInfo(ctx, h, tree, &req)
	case smb.OInfoSecurity:
		return c.querySecurityInfo(ctx, h, tree, hndl, &req)
	default:
		logger.Debugf("QueryInfo from %s: unsupported InfoType 0x%02x -> StatusNotSupported",
			c.RemoteAddr, req.InfoType)
		return c.writeRawError(ctx, h, smb.StatusNotSupported)
	}
}

func (c *Conn) queryFileInfo(ctx pduCtx, h *smb.Header, tree *Tree, hndl Handle, req *smb.QueryInfoReq) error {
	logger := c.logger()
	// Defer to VFS first; it may return a serialized buffer or struct.
	out, status, err := tree.Share.VFS.QueryFileInfo(context.Background(), hndl, req.FileInfoClass)
	if err != nil {
		logger.Errorf("VFS.QueryFileInfo class=0x%02x: %v", req.FileInfoClass, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	var buf []byte
	if status == smb.StatusNotSupported {
		// Fall back to server-built default from Stat().
		info, statErr := hndl.Stat()
		if statErr != nil {
			logger.Errorf("QueryFileInfo: handle Stat: %v", statErr)
			return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
		buf, status = serializeFileInfo(req.FileInfoClass, info, hndl)
		if status != smb.StatusOk {
			logger.Debugf("QueryFileInfo: serializeFileInfo class=0x%02x returned status=0x%08x",
				req.FileInfoClass, status)
		}
	} else if status == smb.StatusOk {
		buf, err = serializeOpaqueOrInfo(out)
		if err != nil {
			logger.Errorf("QueryFileInfo: serializeOpaqueOrInfo: %v", err)
			return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
	}
	if status != smb.StatusOk {
		return c.writeRawError(ctx, h, status)
	}
	return c.writeQueryInfoReply(ctx, h, buf)
}

func (c *Conn) queryFsInfo(ctx pduCtx, h *smb.Header, tree *Tree, req *smb.QueryInfoReq) error {
	logger := c.logger()
	out, status, err := tree.Share.VFS.QueryFSInfo(context.Background(), req.FileInfoClass)
	if err != nil {
		logger.Errorf("VFS.QueryFSInfo class=0x%02x: %v", req.FileInfoClass, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	var buf []byte
	if status == smb.StatusNotSupported {
		buf, status = defaultFsInfo(req.FileInfoClass, tree.Share.Name)
		if status != smb.StatusOk {
			logger.Debugf("QueryFSInfo: defaultFsInfo class=0x%02x returned status=0x%08x",
				req.FileInfoClass, status)
		}
	} else if status == smb.StatusOk {
		buf, err = serializeOpaqueOrInfo(out)
		if err != nil {
			logger.Errorf("QueryFSInfo: serializeOpaqueOrInfo: %v", err)
			return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
		}
	}
	if status != smb.StatusOk {
		return c.writeRawError(ctx, h, status)
	}
	return c.writeQueryInfoReply(ctx, h, buf)
}

func (c *Conn) querySecurityInfo(ctx pduCtx, h *smb.Header, tree *Tree, hndl Handle, req *smb.QueryInfoReq) error {
	logger := c.logger()
	buf, status, err := tree.Share.VFS.QuerySecurity(context.Background(), hndl, req.AdditionalInformation)
	if err != nil {
		logger.Errorf("VFS.QuerySecurity addInfo=0x%08x: %v", req.AdditionalInformation, err)
		return c.writeRawError(ctx, h, smb.StatusInvalidParameter)
	}
	if status == smb.StatusNotSupported {
		// Default world-readable SD: Owner=Group=Everyone, no DACL/SACL.
		buf = worldReadableSecurityDescriptor()
		status = smb.StatusOk
	}
	if status != smb.StatusOk {
		logger.Debugf("QuerySecurityInfo: VFS returned status=0x%08x", status)
		return c.writeRawError(ctx, h, status)
	}
	return c.writeQueryInfoReply(ctx, h, buf)
}

// writeQueryInfoReply marshals a QueryInfoRes carrying buf and sends it.
func (c *Conn) writeQueryInfoReply(ctx pduCtx, reqHdr *smb.Header, buf []byte) error {
	res := smb.QueryInfoRes{
		Header:        buildResponseHeader(reqHdr, smb.StatusOk, reqHdr.SessionID, smb.CommandQueryInfo),
		StructureSize: 9,
		Buffer:        buf,
	}
	res.Header.TreeID = reqHdr.TreeID
	return c.writeReply(ctx, &res)
}

// serializeOpaqueOrInfo accepts either a []byte (already-serialized) or one
// of the typed Information structs and returns its wire bytes.
func serializeOpaqueOrInfo(v interface{}) ([]byte, error) {
	if b, ok := v.([]byte); ok {
		return b, nil
	}
	return nil, fmt.Errorf("VFS returned unrecognized info type %T", v)
}

// serializeFileInfo serializes a FileInfo into the requested FILE_*INFORMATION
// wire format. Returns the buffer plus an NT status (StatusOk on success,
// StatusInfoLengthMismatch / StatusNotSupported otherwise).
func serializeFileInfo(class byte, fi FileInfo, hndl Handle) ([]byte, uint32) {
	switch class {
	case smb.FileBasicInformation: // 0x04, 40 bytes
		buf := make([]byte, 40)
		binary.LittleEndian.PutUint64(buf[0:], timeToFileTime(fi.CreationTime))
		binary.LittleEndian.PutUint64(buf[8:], timeToFileTime(fi.LastAccessTime))
		binary.LittleEndian.PutUint64(buf[16:], timeToFileTime(fi.LastWriteTime))
		binary.LittleEndian.PutUint64(buf[24:], timeToFileTime(fi.ChangeTime))
		binary.LittleEndian.PutUint32(buf[32:], fi.Attributes)
		// reserved 4 bytes already zero
		return buf, smb.StatusOk

	case smb.FileStandardInformation: // 0x05, 24 bytes
		buf := make([]byte, 24)
		binary.LittleEndian.PutUint64(buf[0:], uint64(fi.AllocationSize))
		binary.LittleEndian.PutUint64(buf[8:], uint64(fi.Size))
		binary.LittleEndian.PutUint32(buf[16:], 1) // NumberOfLinks
		// DeletePending(1) + Directory(1) + Reserved(2)
		if hndl != nil && hndl.IsDir() {
			buf[21] = 1
		}
		return buf, smb.StatusOk

	case smb.FileEaInformation: // 0x07, 4 bytes (EaSize)
		return make([]byte, 4), smb.StatusOk

	case smb.FileNameInformation: // 0x09 — name relative to share root
		var nameBytes []byte
		if hndl != nil {
			nameBytes = encoder.ToUnicode("\\" + hndl.Path())
		}
		buf := make([]byte, 4+len(nameBytes))
		binary.LittleEndian.PutUint32(buf[0:], uint32(len(nameBytes)))
		copy(buf[4:], nameBytes)
		return buf, smb.StatusOk

	case smb.FileNetworkOpenInformation: // 0x22, 56 bytes
		buf := make([]byte, 56)
		binary.LittleEndian.PutUint64(buf[0:], timeToFileTime(fi.CreationTime))
		binary.LittleEndian.PutUint64(buf[8:], timeToFileTime(fi.LastAccessTime))
		binary.LittleEndian.PutUint64(buf[16:], timeToFileTime(fi.LastWriteTime))
		binary.LittleEndian.PutUint64(buf[24:], timeToFileTime(fi.ChangeTime))
		binary.LittleEndian.PutUint64(buf[32:], uint64(fi.AllocationSize))
		binary.LittleEndian.PutUint64(buf[40:], uint64(fi.Size))
		binary.LittleEndian.PutUint32(buf[48:], fi.Attributes)
		return buf, smb.StatusOk

	case smb.FileAllInformation: // 0x12 — Basic+Standard+Internal+Ea+Access+Position+Mode+Alignment+Name
		var b bytes.Buffer
		basic, status := serializeFileInfo(smb.FileBasicInformation, fi, hndl)
		if status != smb.StatusOk {
			log.Debugf("serializeFileInfo(FileAllInformation): basic sub-class failed -> 0x%08x", status)
			return nil, status
		}
		std, status := serializeFileInfo(smb.FileStandardInformation, fi, hndl)
		if status != smb.StatusOk {
			log.Debugf("serializeFileInfo(FileAllInformation): standard sub-class failed -> 0x%08x", status)
			return nil, status
		}
		b.Write(basic)
		b.Write(std)
		// FILE_INTERNAL_INFORMATION: IndexNumber (8 bytes)
		var idx [8]byte
		binary.LittleEndian.PutUint64(idx[:], fi.FileID)
		b.Write(idx[:])
		// FILE_EA_INFORMATION: EaSize (4)
		b.Write(make([]byte, 4))
		// FILE_ACCESS_INFORMATION: AccessFlags (4)
		var acc [4]byte
		binary.LittleEndian.PutUint32(acc[:], 0x001f01ff) // FILE_ALL_ACCESS
		b.Write(acc[:])
		// FILE_POSITION_INFORMATION: CurrentByteOffset (8)
		b.Write(make([]byte, 8))
		// FILE_MODE_INFORMATION: Mode (4)
		b.Write(make([]byte, 4))
		// FILE_ALIGNMENT_INFORMATION: AlignmentRequirement (4)
		b.Write(make([]byte, 4))
		// FILE_NAME_INFORMATION
		nameInfo, status := serializeFileInfo(smb.FileNameInformation, fi, hndl)
		if status != smb.StatusOk {
			log.Debugf("serializeFileInfo(FileAllInformation): name sub-class failed -> 0x%08x", status)
			return nil, status
		}
		b.Write(nameInfo)
		return b.Bytes(), smb.StatusOk

	case smb.FilePositionInformation: // 0x0e — 8 bytes CurrentByteOffset
		return make([]byte, 8), smb.StatusOk

	case smb.FileAlignmentInformation: // 0x11 — 4 bytes AlignmentRequirement
		return make([]byte, 4), smb.StatusOk

	default:
		return nil, smb.StatusNotSupported
	}
}

// defaultFsInfo serializes a synthetic filesystem info struct for the
// requested FS info class. The values are chosen to be uncontroversial: a
// 16TB volume, NTFS-style attributes.
func defaultFsInfo(class byte, label string) ([]byte, uint32) {
	switch class {
	case 0x01: // FileFsVolumeInformation
		// VolumeCreationTime(8) + VolumeSerialNumber(4) + VolumeLabelLength(4)
		// + SupportsObjects(1) + Reserved(1) + VolumeLabel(*)
		labelBytes := encoder.ToUnicode(label)
		buf := make([]byte, 18+len(labelBytes))
		// CreationTime stays zero
		binary.LittleEndian.PutUint32(buf[8:], 0xdeadbeef)
		binary.LittleEndian.PutUint32(buf[12:], uint32(len(labelBytes)))
		// SupportsObjects=0, Reserved=0
		copy(buf[18:], labelBytes)
		return buf, smb.StatusOk

	case 0x03: // FileFsSizeInformation
		// TotalAllocationUnits(8) + AvailableAllocationUnits(8)
		// + SectorsPerAllocationUnit(4) + BytesPerSector(4)
		buf := make([]byte, 24)
		binary.LittleEndian.PutUint64(buf[0:], 1<<24)  // 16M units
		binary.LittleEndian.PutUint64(buf[8:], 1<<23)  // half free
		binary.LittleEndian.PutUint32(buf[16:], 8)     // 8 sectors/unit
		binary.LittleEndian.PutUint32(buf[20:], 512)   // 512B/sector
		return buf, smb.StatusOk

	case 0x05: // FileFsAttributeInformation
		fsName := encoder.ToUnicode("NTFS")
		// FileSystemAttributes(4) + MaxComponentNameLength(4) + FileSystemNameLength(4) + FileSystemName(*)
		buf := make([]byte, 12+len(fsName))
		binary.LittleEndian.PutUint32(buf[0:], 0x00000003) // CASE_PRESERVED + UNICODE_ON_DISK
		binary.LittleEndian.PutUint32(buf[4:], 255)
		binary.LittleEndian.PutUint32(buf[8:], uint32(len(fsName)))
		copy(buf[12:], fsName)
		return buf, smb.StatusOk

	default:
		return nil, smb.StatusNotSupported
	}
}

// worldReadableSecurityDescriptor returns a self-relative SD: Owner=Group=Everyone,
// no DACL/SACL. Sufficient for clients that just want to read the SD; tighter
// VFS implementations should override QuerySecurity.
func worldReadableSecurityDescriptor() []byte {
	// Minimal self-relative SD: Revision(1) + Sbz1(1) + Control(2) + Owner(4)
	// + Group(4) + Sacl(4) + Dacl(4) = 20 bytes header. Owner/Group offsets
	// point at SIDs of "S-1-1-0" (Everyone). Each "Everyone" SID is 12 bytes.
	header := make([]byte, 20)
	header[0] = 0x01 // Revision
	binary.LittleEndian.PutUint16(header[2:], 0x8000) // SE_SELF_RELATIVE
	binary.LittleEndian.PutUint32(header[4:], 20)     // Owner offset
	binary.LittleEndian.PutUint32(header[8:], 32)     // Group offset
	// SACL/DACL offsets remain 0 (not present)
	owner := []byte{
		0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // Revision=1, SubAuth count=1, Authority=World
		0x00, 0x00, 0x00, 0x00, // Subauth: 0
	}
	group := owner
	out := make([]byte, 0, 20+len(owner)+len(group))
	out = append(out, header...)
	out = append(out, owner...)
	out = append(out, group...)
	return out
}
