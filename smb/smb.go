// MIT License
//
// Copyright (c) 2017 stacktitan
// Copyright (c) 2023 Jimmy Fjällid for extensions beyond login for SMB 2.1
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

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/compress"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb").SetDisplayName("smb")

const ProtocolSmb = "\xFFSMB"
const ProtocolSmb2 = "\xFESMB"
const ProtocolTransformHdr = "\xFDSMB"
const ProtocolCompressionHdr = "\xFCSMB"

const SHA512 = 0x001

const (
	StatusOk                         uint32 = 0x00000000
	StatusPending                    uint32 = 0x00000103
	StatusBufferOverflow             uint32 = 0x80000005
	StatusNoMoreFiles                uint32 = 0x80000006
	StatusInfoLengthMismatch         uint32 = 0xc0000004
	StatusInvalidParameter           uint32 = 0xc000000d
	StatusNoSuchFile                 uint32 = 0xc000000f
	FsctlStatusInvalidDeviceRequest  uint32 = 0xc0000010 //The type of the handle is not a pipe.
	StatusEndOfFile                  uint32 = 0xc0000011
	StatusMoreProcessingRequired     uint32 = 0xc0000016
	StatusAccessDenied               uint32 = 0xc0000022
	StatusBufferTooSmall             uint32 = 0xc0000023
	StatusObjectNameInvalid          uint32 = 0xc0000033
	StatusObjectNameNotFound         uint32 = 0xc0000034
	StatusObjectNameCollision        uint32 = 0xc0000035
	StatusObjectPathNotFound         uint32 = 0xc000003a
	StatusLogonFailure               uint32 = 0xc000006d
	StatusAccountRestriction         uint32 = 0xc000006e
	StatusPasswordExpired            uint32 = 0xc0000071
	StatusAccountDisabled            uint32 = 0xc0000072
	FsctlStatusInsufficientResources uint32 = 0xc000009a //There were insufficient resources to complete the operation.
	StatusPipeNotAvailable           uint32 = 0xc00000ac
	FsctlStatusInvalidPipeState      uint32 = 0xc00000ad //The named pipe is not in the connected state or not in the full-duplex message mode.
	StatusPipeBusy                   uint32 = 0xc00000ae
	FsctlStatusPipeDisconnected      uint32 = 0xc00000b0 //The specified named pipe is in the disconnected state.
	StatusFileIsADirectory           uint32 = 0xc00000ba
	StatusNotSupported               uint32 = 0xc00000bb
	StatusNetworkNameDeleted         uint32 = 0xc00000c9
	StatusBadNetworkName             uint32 = 0xc00000cc
	FsctlStatusInvalidUserBuffer     uint32 = 0xc00000e8 //An exception was raised while accessing a user buffer.
	StatusDirectoryNotEmpty          uint32 = 0xc0000101
	StatusNotADirectory              uint32 = 0xc0000103
	StatusCannotDelete               uint32 = 0xc0000121
	StatusFileClosed                 uint32 = 0xc0000128
	FsctlStatusPipeBroken            uint32 = 0xc000014b // The pipe operation has failed because the other end of the pipe has been closed
	StatusUserSessionDeleted         uint32 = 0xc0000203
	StatusPasswordMustChange         uint32 = 0xc0000224
	StatusAccountLockedOut           uint32 = 0xc0000234
	StatusVirusInfected              uint32 = 0xc0000906
)

var StatusMap = map[uint32]error{
	StatusOk:                         fmt.Errorf("OK"),
	StatusPending:                    fmt.Errorf("Status Pending"),
	StatusBufferOverflow:             fmt.Errorf("Response buffer overflow"),
	StatusNoMoreFiles:                fmt.Errorf("No more files"),
	StatusInfoLengthMismatch:         fmt.Errorf("Insuffient size of response buffer"),
	StatusInvalidParameter:           fmt.Errorf("Invalid Parameter"),
	StatusNoSuchFile:                 fmt.Errorf("No such file"),
	StatusEndOfFile:                  fmt.Errorf("The end-of-file marker has been reached"),
	StatusMoreProcessingRequired:     fmt.Errorf("More Processing Required"),
	StatusAccessDenied:               fmt.Errorf("Access denied!"),
	StatusBufferTooSmall:             fmt.Errorf("Buffer is too small to contain the entry"),
	StatusObjectNameInvalid:          fmt.Errorf("The object name is invalid for the target filesystem"),
	StatusObjectNameNotFound:         fmt.Errorf("Requested file does not exist"),
	StatusObjectNameCollision:        fmt.Errorf("File or directory already exists"),
	StatusObjectPathNotFound:         fmt.Errorf("The path to the specified directory was not found"),
	StatusLogonFailure:               fmt.Errorf("Logon failed"),
	StatusAccountRestriction:         fmt.Errorf("Account restriction"),
	StatusPasswordExpired:            fmt.Errorf("Password expired!"),
	StatusAccountDisabled:            fmt.Errorf("Account disabled!"),
	StatusPipeNotAvailable:           fmt.Errorf("Pipe not available!"),
	StatusPipeBusy:                   fmt.Errorf("Pipe busy!"),
	StatusNotSupported:               fmt.Errorf("Not Supported!"),
	StatusNetworkNameDeleted:         fmt.Errorf("Network name deleted"),
	StatusBadNetworkName:             fmt.Errorf("Bad network name"),
	StatusDirectoryNotEmpty:          fmt.Errorf("Directory is not empty"),
	StatusNotADirectory:              fmt.Errorf("Not a directory!"),
	StatusFileClosed:                 fmt.Errorf("The handle is no longer valid"),
	StatusUserSessionDeleted:         fmt.Errorf("User session deleted"),
	StatusPasswordMustChange:         fmt.Errorf("User is required to change password at next logon"),
	StatusAccountLockedOut:           fmt.Errorf("User account has been locked!"),
	StatusVirusInfected:              fmt.Errorf("The file contains a virus"),
	StatusFileIsADirectory:           fmt.Errorf("File is a directory!"),
	FsctlStatusPipeDisconnected:      fmt.Errorf("FSCTL_STATUS_PIPE_DISCONNECTED"),
	FsctlStatusInvalidPipeState:      fmt.Errorf("FSCTL_STATUS_INVALID_PIPE_STATE"),
	FsctlStatusInvalidUserBuffer:     fmt.Errorf("FSCTL_STATUS_INVALID_USER_BUFFER"),
	FsctlStatusInsufficientResources: fmt.Errorf("FSCTL_STATUS_INSUFFICIENT_RESOURCES"),
	FsctlStatusInvalidDeviceRequest:  fmt.Errorf("FSCTL_STATUS_INVALID_DEVICE_REQUEST"),
	FsctlStatusPipeBroken:            fmt.Errorf("FSCTL_STATUS_PIPE_BROKEN"),
}

const DialectSmb_2_0_2 uint16 = 0x0202
const DialectSmb_2_1 uint16 = 0x0210
const DialectSmb_3_0 uint16 = 0x0300
const DialectSmb_3_0_2 uint16 = 0x0302
const DialectSmb_3_1_1 uint16 = 0x0311
const DialectSmb2_ALL uint16 = 0x02FF

// DialectString maps a dialect revision to its friendly SMB version string
// (e.g. 0x0311 -> "3.1.1"). Unknown values fall back to a hex representation so
// log output stays readable regardless of what a client offers.
func DialectString(d uint16) string {
	switch d {
	case DialectSmb_2_0_2:
		return "2.0.2"
	case DialectSmb_2_1:
		return "2.1"
	case DialectSmb_3_0:
		return "3.0"
	case DialectSmb_3_0_2:
		return "3.0.2"
	case DialectSmb_3_1_1:
		return "3.1.1"
	case DialectSmb2_ALL:
		return "2.??? (wildcard)"
	default:
		return fmt.Sprintf("0x%04X", d)
	}
}

// DialectsString maps a slice of dialect revisions to their friendly version
// strings for logging.
func DialectsString(dialects []uint16) []string {
	out := make([]string, len(dialects))
	for i, d := range dialects {
		out[i] = DialectString(d)
	}
	return out
}

// DialectsSMB2Only pins the negotiate offer to the legacy SMB 2.1 dialect. Use
// it as Options.Dialects when a server has SMB 3.x disabled or must be forced
// onto the 2.1 path (which cannot negotiate signing contexts or encryption).
var DialectsSMB2Only = []uint16{DialectSmb_2_1}

const (
	CommandNegotiate uint16 = iota
	CommandSessionSetup
	CommandLogoff
	CommandTreeConnect
	CommandTreeDisconnect
	CommandCreate
	CommandClose
	CommandFlush
	CommandRead
	CommandWrite
	CommandLock
	CommandIOCtl
	CommandCancel
	CommandEcho
	CommandQueryDirectory
	CommandChangeNotify
	CommandQueryInfo
	CommandSetInfo
	CommandOplockBreak
)

// MS-SMB2 2.2.1.1 Flags
const (
	SMB2_FLAGS_SERVER_TO_REDIR    uint32 = 0x00000001
	SMB2_FLAGS_ASYNC_COMMAND      uint32 = 0x00000002
	SMB2_FLAGS_RELATED_OPERATIONS uint32 = 0x00000004
	SMB2_FLAGS_SIGNED             uint32 = 0x00000008
	SMB2_FLAGS_PRIORITY_MASK      uint32 = 0x00000070
	SMB2_FLAGS_DFS_OPERATIONS     uint32 = 0x10000000
	SMB2_FLAGS_REPLAY_OPERATIONS  uint32 = 0x20000000
)

const (
	SecurityModeSigningDisabled uint16 = iota
	SecurityModeSigningEnabled
	SecurityModeSigningRequired
)

const (
	_ byte = iota
	ShareTypeDisk
	ShareTypePipe
	ShareTypePrint
)

const (
	ShareFlagManualCaching            uint32 = 0x00000000
	ShareFlagAutoCaching              uint32 = 0x00000010
	ShareFlagVDOCaching               uint32 = 0x00000020
	ShareFlagNoCaching                uint32 = 0x00000030
	ShareFlagDFS                      uint32 = 0x00000001
	ShareFlagDFSRoot                  uint32 = 0x00000002
	ShareFlagRestriceExclusiveOpens   uint32 = 0x00000100
	ShareFlagForceSharedDelete        uint32 = 0x00000200
	ShareFlagAllowNamespaceCaching    uint32 = 0x00000400
	ShareFlagAccessBasedDirectoryEnum uint32 = 0x00000800
	ShareFlagForceLevelIIOplock       uint32 = 0x00001000
	ShareFlagEnableHashV1             uint32 = 0x00002000
	ShareFlagEnableHashV2             uint32 = 0x00004000
	ShareFlagEncryptData              uint32 = 0x00008000
)

const (
	ShareCapDFS                    uint32 = 0x00000008
	ShareCapContinuousAvailability uint32 = 0x00000010
	ShareCapScaleout               uint32 = 0x00000020
	ShareCapCluster                uint32 = 0x00000040
	ShareCapAsymmetric             uint32 = 0x00000080
)

const (
	GlobalCapDFS               uint32 = 0x00000001
	GlobalCapLeasing           uint32 = 0x00000002
	GlobalCapLargeMTU          uint32 = 0x00000004
	GlobalCapMultiChannel      uint32 = 0x00000008
	GlobalCapPersistentHandles uint32 = 0x00000010
	GlobalCapDirectoryLeasing  uint32 = 0x00000020
	GlobalCapEncryption        uint32 = 0x00000040
)

const (
	OpLockLevelNone      byte = 0x00
	OpLockLevelII        byte = 0x01
	OpLockLevelExclusive byte = 0x08
	OpLockLevelBatch     byte = 0x09
	OpLockLevelLease     byte = 0xff
)

const (
	ImpersonationLevelAnonymous      uint32 = 0x00000000
	ImpersonationLevelIdentification uint32 = 0x00000001
	ImpersonationLevelImpersonation  uint32 = 0x00000002
	ImpersonationLevelDelegate       uint32 = 0x00000003
)

// MS-SMB2 Section 2.2.3.1 Context Type
const (
	PreauthIntegrityCapabilities uint16 = 0x0001
	EncryptionCapabilities       uint16 = 0x0002
	CompressionCapabilities      uint16 = 0x0003
	NetNameNegotiateContextId    uint16 = 0x0005
	TransportCapabilities        uint16 = 0x0006
	RDMATranformCapabilities     uint16 = 0x0007
	SigningCapabilities          uint16 = 0x0008
)

// MS-SMB2 Section 2.2.3.1.3 CompressionAlgorithms
const (
	CompressionNone        uint16 = 0x0000
	CompressionLZNT1       uint16 = 0x0001
	CompressionLZ77        uint16 = 0x0002
	CompressionLZ77Huffman uint16 = 0x0003
	CompressionPatternV1   uint16 = 0x0004
	CompressionLZ4         uint16 = 0x0005
)

// MS-SMB2 Section 2.2.3.1.3 SMB2_COMPRESSION_CAPABILITIES Flags
const (
	CompressionCapabilitiesFlagNone    uint32 = 0x00000000
	CompressionCapabilitiesFlagChained uint32 = 0x00000001
)

// MS-SMB2 Section 2.2.3.1.2 Ciphers
const (
	// CipherNone is the value a server returns in SMB2_ENCRYPTION_CAPABILITIES
	// when it shares no cipher with the client's offer (MS-SMB2 §3.3.5.4). It
	// means "encryption unavailable on this connection", not an error.
	CipherNone uint16 = 0x0000
	AES128CCM  uint16 = 0x0001
	AES128GCM  uint16 = 0x0002
	AES256CCM  uint16 = 0x0003
	AES256GCM  uint16 = 0x0004
)

// MS-SMB2 Section 2.2.3.1.7 SigningAlgorithms
const (
	HMAC_SHA256 uint16 = 0x0000
	AES_CMAC    uint16 = 0x0001
	AES_GMAC    uint16 = 0x0002
)

// MS-SMB2 Section 2.2.6 Session setup flags
const (
	SessionFlagIsGuest     uint16 = 0x0001
	SessionFlagIsNull      uint16 = 0x0002
	SessionFlagEncryptData uint16 = 0x0004
)

// MS-SMB2 Section 2.2.5 SessionSetup request flags
const (
	SMB2_SESSION_FLAG_BINDING byte = 0x01
)

// MS-SMB2 NTSTATUS values not already listed in the table above.
const (
	StatusRequestNotAccepted uint32 = 0xc00000d0
	StatusCancelled          uint32 = 0xc0000120
)

// File, Pipe, Printer access masks
const (
	FAccMaskFileReadData         uint32 = 0x00000001
	FAccMaskFileWriteData        uint32 = 0x00000002
	FAccMaskFileAppendData       uint32 = 0x00000004
	FAccMaskFileReadEA           uint32 = 0x00000008
	FAccMaskFileWriteEA          uint32 = 0x00000010
	FAccMaskFileDeleteChild      uint32 = 0x00000040
	FAccMaskFileExecute          uint32 = 0x00000020
	FAccMaskFileReadAttributes   uint32 = 0x00000080
	FAccMaskFileWriteAttributes  uint32 = 0x00000100
	FAccMaskDelete               uint32 = 0x00010000
	FAccMaskReadControl          uint32 = 0x00020000
	FAccMaskWriteDac             uint32 = 0x00040000
	FAccMaskWriteOwner           uint32 = 0x00080000
	FAccMaskSynchronize          uint32 = 0x00100000
	FAccMaskAccessSystemSecurity uint32 = 0x01000000
	FAccMaskMaximumAllowed       uint32 = 0x02000000
	FAccMaskGenericAll           uint32 = 0x10000000
	FAccMaskGenericExecute       uint32 = 0x20000000
	FAccMaskGenericWrite         uint32 = 0x40000000
	FAccMaskGenericRead          uint32 = 0x80000000
)

// Directory access masks
const (
	DAccMaskFileListDirectory    uint32 = 0x00000001
	DAccMaskFileAddFile          uint32 = 0x00000002
	DAccMaskFileAddSubDirectory  uint32 = 0x00000004
	DAccMaskFileReadEA           uint32 = 0x00000008
	DAccMaskFileWriteEA          uint32 = 0x00000010
	DAccMaskFileTraverse         uint32 = 0x00000020
	DAccMaskFileDeleteChild      uint32 = 0x00000040
	DAccMaskFileReadAttributes   uint32 = 0x00000080
	DAccMaskFileWriteAttributes  uint32 = 0x00000100
	DAccMaskDelete               uint32 = 0x00010000
	DAccMaskReadControl          uint32 = 0x00020000
	DAccMaskWriteDac             uint32 = 0x00040000
	DAccMaskWriteOwner           uint32 = 0x00080000
	DAccMaskSynchronize          uint32 = 0x00100000
	DAccMaskAccessSystemSecurity uint32 = 0x01000000
	DAccMaskMaximumAllowed       uint32 = 0x02000000
	DAccMaskGenericAll           uint32 = 0x10000000
	DAccMaskGenericExecute       uint32 = 0x20000000
	DAccMaskGenericWrite         uint32 = 0x40000000
	DAccMaskGenericRead          uint32 = 0x80000000
)

// File attributes
const (
	FileAttrReadonly           uint32 = 0x00000001
	FileAttrHidden             uint32 = 0x00000002
	FileAttrSystem             uint32 = 0x00000004
	FileAttrDirectory          uint32 = 0x00000010
	FileAttrAchive             uint32 = 0x00000020
	FileAttrNormal             uint32 = 0x00000080
	FileAttrTemporary          uint32 = 0x00000100
	FileAttrSparseFile         uint32 = 0x00000200
	FileAttrReparsePoint       uint32 = 0x00000400 // Junction
	FileAttrCompressed         uint32 = 0x00000800
	FileAttrOffline            uint32 = 0x00001000
	FileAttrNotContentIndexed  uint32 = 0x00002000
	FileAttrEncrypted          uint32 = 0x00004000
	FileAttrIntegrityStream    uint32 = 0x00008000
	FileAttrNoScrubData        uint32 = 0x00020000
	FileAttrRecallOnOpen       uint32 = 0x00040000
	FileAttrPinned             uint32 = 0x00080000
	FileAttrUnPinned           uint32 = 0x00100000
	FileAttrRecallOnDataAccess uint32 = 0x00400000
)

// Share access
const (
	FileShareRead   uint32 = 0x00000001
	FileShareWrite  uint32 = 0x00000002
	FileShareDelete uint32 = 0x00000004
)

// File Create Disposition
const (
	FileSupersede   uint32 = iota // If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.
	FileOpen                      // If the file already exists, return success; otherwise, fail the operation MUST NOT be used for a printer object.
	FileCreate                    // If the file already exists, fail the operation; otherwise, create the file.
	FileOpenIf                    // Open the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.
	FileOverwrite                 // Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be used for a printer object.
	FileOverwriteIf               // Overwrite the file if it already exists; otherwise, create the file. This value SHOULD NOT be used for a printer object.
)

// File Create Options
const (
	FileDirectoryFile           uint32 = 0x00000001
	FileWriteThrough            uint32 = 0x00000002
	FileSequentialOnly          uint32 = 0x00000004
	FileNoIntermediateBuffering uint32 = 0x00000008
	FileSynchronousIOAlert      uint32 = 0x00000010
	FileSynchronousIONonAlert   uint32 = 0x00000020
	FileNonDirectoryFile        uint32 = 0x00000040
	FileCompleteIfOpLocked      uint32 = 0x00000100
	FileNoEAKnowledge           uint32 = 0x00000200
	FileRandomAccess            uint32 = 0x00000800
	FileDeleteOnClose           uint32 = 0x00001000
	FileOpenByFileId            uint32 = 0x00002000
	FileOpenForBackupIntent     uint32 = 0x00004000
	FileNoCompression           uint32 = 0x00008000
	FileOpenRemoteInstance      uint32 = 0x00000400
	FileOpenRequiringOpLock     uint32 = 0x00010000
	FileDisallowExclusive       uint32 = 0x00020000
	FileReserveOpFilter         uint32 = 0x00100000
	FileOpenReparsePoint        uint32 = 0x00200000
	FileOpenNoRecall            uint32 = 0x00400000
	FileOpenForFreeSpaceQuery   uint32 = 0x00800000
)

// File CreateActions
const (
	FileSuperseded uint32 = iota
	FileOpened
	FileCreated
	FileOverwritten
)

//// File information class
//const (
//	FileDirectoryInformation       byte = 0x01
//	FileFullDirectoryInformation   byte = 0x02
//	FileIdFullDirectoryInformation byte = 0x26
//	FileBothDirectoryInformation   byte = 0x03
//	FileIdBothDirectoryInformation byte = 0x25
//	FileNamesInformation           byte = 0x0c
//	FileIdExtDirectoryInformation  byte = 0x3c
//)

// Query Directory Flags
const (
	RestartScans      byte = 0x01
	ReturnSingleEntry byte = 0x02
	IndexSpecified    byte = 0x04
	Reopen            byte = 0x10
)

// IOCTL Functions / CtlCode
const (
	FsctlDfsGetRefferrals uint32 = 0x00060194
	FsctlPipePeek         uint32 = 0x0011400c
	FsctlPipeWait         uint32 = 0x00110018
	// ...
	FsctlPipeTransceive uint32 = 0x0011C017
	// ...
)

// IOCTL Flags
const (
	IoctlIsFsctl uint32 = 0x00000001
)

// MS-SMB2 Section 2.2.39 Info Type
const (
	OInfoFile       byte = 0x01
	OInfoFilesystem byte = 0x02
	OInfoSecurity   byte = 0x03
	OInfoQuota      byte = 0x04
)

// MS-SMB2 Section 2.2.39 AdditionalInformation
const (
	OwnerSecurityInformation     uint32 = 0x00000001 // The client is setting the owner in the security descriptor of the file or named pipe.
	GroupSecurityInformation     uint32 = 0x00000002 // The client is setting the group in the security descriptor of the file or named pipe.
	DACLSecurityInformation      uint32 = 0x00000004 // The client is setting the discretionary access control list in the security descriptor of the file or named pipe.
	SACLSecurityInformation      uint32 = 0x00000008 // The client is setting the system access control list in the security descriptor of the file or named pipe.
	LabelSecurityInformation     uint32 = 0x00000010 // The client is setting the integrity label in the security descriptor of the file or named pipe.
	AttributeSecurityInformation uint32 = 0x00000020 // The client is setting the resource attribute in the security descriptor of the file or named pipe.
	ScopeSecurityInformation     uint32 = 0x00000040 // The client is setting the central access policy of the resource in the security descriptor of the file or named pipe.
	BackupSecurityInformation    uint32 = 0x00010000 // The client is setting the backup operation information in the security descriptor of the file or named pipe
)

// MS-FSCC Section 2.4 File Information Class
const (
	FileDirectoryInformation           byte = 0x01 // Query
	FileFullDirectoryInformation       byte = 0x02 // Query
	FileBothDirectoryInformation       byte = 0x03 // Query
	FileBasicInformation               byte = 0x04 // Query, Set
	FileStandardInformation            byte = 0x05 // Query
	FileInternalInformation            byte = 0x06 // Query
	FileEaInformation                  byte = 0x07 // Query
	FileAccessInformation              byte = 0x08 // Query
	FileNameInformation                byte = 0x09 // LOCAL
	FileRenameInformation              byte = 0x0a // Set
	FileLinkInformation                byte = 0x0b // Set
	FileNamesInformation               byte = 0x0c // Query
	FileDispositionInformation         byte = 0x0d // Set
	FilePositionInformation            byte = 0x0e // Query, Set
	FileFullEaInformation              byte = 0x0f // Query, Set
	FileModeInformation                byte = 0x10 // Query, Set
	FileAlignmentInformation           byte = 0x11 // Query
	FileAllInformation                 byte = 0x12 // Query
	FileAllocationInformation          byte = 0x13 // Set
	FileEndOfFileInformation           byte = 0x14 // Set
	FileAlternateNameInformation       byte = 0x15 // Query
	FileStreamInformation              byte = 0x16 // Query
	FilePipeInformation                byte = 0x17 // Query, Set
	FilePipeLocalInformation           byte = 0x18 // Query
	FilePipeRemoteInformation          byte = 0x19 // Query
	FileMailslotQueryInformation       byte = 0x1a // LOCAL
	FileMailslotSetInformation         byte = 0x1b // LOCAL
	FileCompressionInformation         byte = 0x1c // Query
	FileObjectIdInformation            byte = 0x1d // LOCAL
	FileMoveClusterInformation         byte = 0x1f //
	FileQuotaInformation               byte = 0x20 // Query, Set
	FileReparsePointInformation        byte = 0x21 // LOCAL
	FileNetworkOpenInformation         byte = 0x22 // Query
	FileAttributeTagInformation        byte = 0x23 // Query
	FileTrackingInformation            byte = 0x24 // LOCAL
	FileIdBothDirectoryInformation     byte = 0x25 // Query
	FileIdFullDirectoryInformation     byte = 0x26 // Query
	FileValidDataLengthInformation     byte = 0x27 // Set
	FileShortNameInformation           byte = 0x28 // Set
	FileSfioReserveInformation         byte = 0x2c // LOCAL
	FileSfioVolumeInformation          byte = 0x2d
	FileHardLinkInformation            byte = 0x2e // LOCAL
	FileNormalizedNameInformation      byte = 0x30 // Query
	FileIdGlobalTxDirectoryInformation byte = 0x32 // LOCAL
	FileStandardLinkInformation        byte = 0x36 // LOCAL
	FileIdInformation                  byte = 0x3b // Query
	FileIdExtdDirectoryInformation     byte = 0x3c // Query

)

// MS-DTYP Section 2.4.6 Security_Descriptor Control Flag
const (
	SecurityDescriptorFlagOD uint16 = 0x0001 // Owner Default
	SecurityDescriptorFlagGD uint16 = 0x0002 // Group Default
	SecurityDescriptorFlagDP uint16 = 0x0004 // DACL Present
	SecurityDescriptorFlagDD uint16 = 0x0008 // DACL Defaulted
	SecurityDescriptorFlagSP uint16 = 0x0010 // SACL Present
	SecurityDescriptorFlagSD uint16 = 0x0020 // SACL Defaulted
	SecurityDescriptorFlagDT uint16 = 0x0040 // DACL Trusted
	SecurityDescriptorFlagSS uint16 = 0x0080 // Server Security
	SecurityDescriptorFlagDC uint16 = 0x0100 // DACL Computed Inheritance Required
	SecurityDescriptorFlagSC uint16 = 0x0200 // SACL Computed Inheritance Required
	SecurityDescriptorFlagDI uint16 = 0x0400 // DACL Auto-Inherited
	SecurityDescriptorFlagSI uint16 = 0x0800 // SACL Auto-Inherited
	SecurityDescriptorFlagPD uint16 = 0x1000 // DACL Protected
	SecurityDescriptorFlagPS uint16 = 0x2000 // SACL Protected
	SecurityDescriptorFlagPM uint16 = 0x4000 // RM Control Valid
	SecurityDescriptorFlagSR uint16 = 0x8000 // Self-Relative
)

// MS-DTYP Section 2.4.4.1 ACE_HEADER
// AceType
const (
	AccessAllowedAceType               byte = 0x00
	AccessDeniedAceType                byte = 0x01
	SystemAuditAceType                 byte = 0x02
	SystemAlarmAceType                 byte = 0x03
	AccessAllowedCompoundAceType       byte = 0x04
	AccessAllowedObjectAceType         byte = 0x05
	AccessDeniedObjectAceType          byte = 0x06
	SystemAuditObjectAceType           byte = 0x07
	SystemAlarmObjectAceType           byte = 0x08
	AccessAllowedCallbackAceType       byte = 0x09
	AccessDeniedCallbackAceType        byte = 0x0a
	AccessAllowedCallbackObjectAceType byte = 0x0b
	AccessDeniedCallbackObjectAceType  byte = 0x0c
	SystemAuditCallbackAceType         byte = 0x0d
	SystemAlarmCallbackAceType         byte = 0x0e
	SystemAuditCallbackObjectAceType   byte = 0x0f
	SystemAlarmCallbackObjectAceType   byte = 0x10
	SystemMandatoryLabelAceType        byte = 0x11
	SystemResourceAttribyteAceType     byte = 0x12
	SystemScopedPolicyIdAceType        byte = 0x13
)

// AceFlags
const (
	ObjectInheritAce        byte = 0x01
	ContainerInheritAce     byte = 0x02
	NoPropagateInheritAce   byte = 0x04
	InheritOnlyAce          byte = 0x08
	InheritedAce            byte = 0x10
	SuccessfulAccessAceFlag byte = 0x40
	FailedAccessAceFlag     byte = 0x80
	DefaultAceFlag          byte = 0x02 // ContainerInheritAce
)

const (
	AccessMaskGenericRead          = "GENERIC_READ"
	AccessMaskGenericWrite         = "GENERIC_WRITE"
	AccessMaskGenericExecute       = "GENERIC_EXECUTE"
	AccessMaskGenericAll           = "GENERIC_ALL"
	AccessMaskMaximumAllowed       = "MAXIMUM_ALLOWED"
	AccessMaskAccessSystemSecurity = "ACCESS_SYSTEM_SECURITY"
	AccessMaskSynchronize          = "SYNCHRONIZE"
	AccessMaskWriteOwner           = "WRITE_OWNER"
	AccessMaskWriteDACL            = "WRITE_DACL"
	AccessMaskReadControl          = "READ_CONTROL"
	AccessMaskDelete               = "DELETE"
)

var (
	// Keys are the generic/standard access-mask bits of MS-DTYP §2.4.3. They
	// are written via the FAccMask* constants rather than as literals: the
	// GENERIC_WRITE entry was previously 0x4000000 (one zero short of
	// 0x40000000), so ParseAccessMask never reported GENERIC_WRITE and instead
	// attributed it to the reserved bit 0x04000000.
	accessMaskMap = map[uint32]string{
		FAccMaskGenericRead:          AccessMaskGenericRead,
		FAccMaskGenericWrite:         AccessMaskGenericWrite,
		FAccMaskGenericExecute:       AccessMaskGenericExecute,
		FAccMaskGenericAll:           AccessMaskGenericAll,
		FAccMaskMaximumAllowed:       AccessMaskMaximumAllowed,
		FAccMaskAccessSystemSecurity: AccessMaskAccessSystemSecurity,
		FAccMaskSynchronize:          AccessMaskSynchronize,
		FAccMaskWriteOwner:           AccessMaskWriteOwner,
		FAccMaskWriteDac:             AccessMaskWriteDACL,
		FAccMaskReadControl:          AccessMaskReadControl,
		FAccMaskDelete:               AccessMaskDelete,
	}
)

// Custom error not part of SMB
var ErrorNotDir = fmt.Errorf("not a directory")

type Header struct { // 64 bytes
	ProtocolID    []byte `smb:"fixed:4"`
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32
	Command       uint16
	Credits       uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32 // In async requests Reserved and TreeId are replaced by AsyncID
	TreeID        uint32
	SessionID     uint64
	Signature     []byte `smb:"fixed:16"`
}

// headerSize is the fixed on-wire size of an SMB2 header (MS-SMB2 §2.2.1.2).
const headerSize = 64

// parseHeader decodes the 64-byte SMB2 header at the front of buf. It exists so
// that every response path shares one length check: slicing buf[:64] directly
// panics on a short reply, and a server (or an on-path attacker) controls that
// length. op names the operation for the error message.
func parseHeader(op string, buf []byte) (Header, error) {
	var h Header
	if len(buf) < headerSize {
		return h, fmt.Errorf("%s: response too short to contain an SMB2 header (%d bytes)", op, len(buf))
	}
	if err := encoder.Unmarshal(buf[:headerSize], &h); err != nil {
		return h, fmt.Errorf("%s: decoding SMB2 header: %w", op, err)
	}
	return h, nil
}

// headerStatus decodes the response header and converts its NTSTATUS to an
// error, the pattern used by every operation that cares only about success or
// failure. okStatuses lists additional codes the caller treats as success.
func headerStatus(op string, buf []byte, okStatuses ...uint32) (Header, error) {
	h, err := parseHeader(op, buf)
	if err != nil {
		return h, err
	}
	return h, statusError(op, h.Status, okStatuses...)
}

type TransformHeader struct { // 52 bytes
	ProtcolID           uint32
	Signature           []byte `smb:"fixed:16"`
	Nonce               []byte `smb:"fixed:16"` // 11 bytes nonce + 5 bytes reversed if CCM, 12 bytes nonce + 4 bytes reversed if GCM
	OriginalMessageSize uint32
	Reserved            uint16
	Flags               uint16 //SMB 3.1.1
	SessionId           uint64
}

// MS-SMB2 Section 2.2.3
type NegotiateReq struct {
	Header
	StructureSize          uint16
	DialectCount           uint16 `smb:"count:Dialects"`
	SecurityMode           uint16
	Reserved               uint16
	Capabilities           uint32
	ClientGuid             []byte `smb:"fixed:16"`
	NegotiateContextOffset uint32 `smb:"offset:ContextList"`
	NegotiateContextCount  uint16 `smb:"count:ContextList"`
	Reserved2              uint16
	Dialects               []uint16
	Padding                []byte `smb:"align:8"`
	ContextList            []NegContext
}

// MS-SMB2 Section 2.2.4
type NegotiateRes struct {
	Header
	StructureSize         uint16
	SecurityMode          uint16
	DialectRevision       uint16
	NegotiateContextCount uint16 `smb:"count:ContextList"`
	ServerGuid            []byte `smb:"fixed:16"`
	Capabilities          uint32
	// MaxTransactSize is the maximum size, in bytes, of the buffer sent by the
	// client in SetInfo, or sent by the server in the response to QueryInfo,
	// QueryDirectory, and ChangeNotify requests
	MaxTransactSize        uint32 // Max buffer size
	MaxReadSize            uint32 // Max value for Length of Read request the server will accept
	MaxWriteSize           uint32 // Max value for Length of Write request the server will accept
	SystemTime             uint64
	ServerStartTime        uint64
	SecurityBufferOffset   uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength   uint16 `smb:"len:SecurityBlob"`
	NegotiateContextOffset uint32 `smb:"offset:ContextList"`
	SecurityBlob           *gss.NegTokenInit
	Padding                []byte `smb:"align:8"`
	ContextList            []NegContext
}

// For SMB 3.1.1
// MS-SMB2 Section 2.2.3.1
type NegContext struct {
	ContextType uint16
	DataLength  uint16 `smb:"len:Data"`
	Reserved    uint32
	Data        []byte
	Padd        []byte `smb:"align:8"`
}

type PreauthIntegrityContext struct {
	HashAlgorithmCount uint16 `smb:"count:HashAlgorithms"`
	SaltLength         uint16 `smb:"len:Salt"`
	HashAlgorithms     []uint16
	Salt               []byte
	Padd               []byte `smb:"align:8"`
}

type EncryptionContext struct {
	CipherCount uint16 `smb:"count:Ciphers"`
	Ciphers     []uint16
}

// MS-SMB2 2.2.3.1.3 SMB2_COMPRESSION_CAPABILITIES. Note the extra Padding and
// Flags fields relative to EncryptionContext; Flags carries
// CompressionCapabilitiesFlagChained.
type CompressionContext struct {
	CompressionAlgorithmCount uint16 `smb:"count:CompressionAlgorithms"`
	Padding                   uint16
	Flags                     uint32
	CompressionAlgorithms     []uint16
}

// MS-SMB2 2.2.3.1.7 SMB2_SIGNING_CAPABILITIES
type SigningContext struct {
	SigningAlgorithmCount uint16 `smb:"count:SigningAlgorithms"`
	SigningAlgorithms     []uint16
}

type SessionSetup1Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Req struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenResp
}

type SessionSetup2Res struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

type LogoffReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type LogoffRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeConnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
	PathOffset    uint16 `smb:"offset:Path"`
	PathLength    uint16 `smb:"len:Path"`
	Path          []byte
}

type TreeConnectRes struct {
	Header
	StructureSize uint16
	ShareType     byte
	Reserved      byte
	ShareFlags    uint32
	Capabilities  uint32
	MaximalAccess uint32
}

type TreeDisconnectReq struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeDisconnectRes struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type CreateReq struct {
	Header
	StructureSize        uint16 // Must always be 57 regardless of Buffer size
	SecurityFlags        byte   // Must always be 0
	RequestedOplockLevel byte
	ImpersonationLevel   uint32
	SmbCreateFlags       uint64 // Must always be 0
	Reserved             uint64 // Must always be 0
	DesiredAccess        uint32
	FileAttributes       uint32
	ShareAccess          uint32
	CreateDisposition    uint32
	CreateOptions        uint32
	NameOffset           uint16
	NameLength           uint16
	CreateContextsOffset uint32
	CreateContextsLength uint32
	Buffer               []byte // Min length is 1
}

type CreateRes struct {
	Header
	StructureSize        uint16 // Must be 89
	OplockLevel          byte
	Flags                byte
	CreateAction         uint32
	CreationTime         uint64 //Filetime
	LastAccessTime       uint64 //Filetime
	LastWriteTime        uint64 //Filetime
	ChangeTime           uint64 //Filetime
	AllocationSize       uint64
	EndOfFile            uint64
	FileAttributes       uint32
	Reserved2            uint32 // Must be 0
	FileId               []byte `smb:"fixed:16"` // 16 bytes length
	CreateContextsOffset uint32 `smb:"offset:Buffer"`
	CreateContextsLength uint32 `smb:"len:Buffer"`
	Buffer               []byte
}

type CloseReq struct {
	Header
	StructureSize uint16 // Must be set to 24
	Flags         uint16 // Can only be 0x0000 or 0x0001
	Reserved      uint32
	FileId        []byte `smb:"fixed:16"` // 16 bytes length
}

type CloseRes struct {
	Header
	StructureSize  uint16 // Must be 60
	Flags          uint16 // Can only be 0x0000 or 0x0001
	Reserved       uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64
	FileAttributes uint32
}

// OplockBreak models the SMB2 OPLOCK_BREAK PDU (MS-SMB2 §2.2.23.1 /
// §2.2.24.1 / §2.2.25.1). The same 24-byte layout is used for the server's
// unsolicited break notification, the client's acknowledgment, and the
// server's response, differing only in the meaning of OplockLevel. A lease
// break uses a different, larger structure (StructureSize 44) that the client
// does not model yet.
type OplockBreak struct {
	Header
	StructureSize uint16 // Must be 24
	OplockLevel   byte
	Reserved      byte
	Reserved2     uint32
	FileId        []byte `smb:"fixed:16"`
}

// CancelReq models the SMB2 CANCEL request (MS-SMB2 §2.2.30). It carries no
// body beyond the fixed StructureSize; the request is correlated to the target
// operation by reusing the target's MessageId (and AsyncId, if the target went
// asynchronous).
type CancelReq struct {
	Header
	StructureSize uint16 // Must be 4
	Reserved      uint16
}

type QueryDirectoryReq struct {
	Header
	StructureSize        uint16 // Must always be 33 regardless of Buffer size
	FileInformationClass byte
	Flags                byte
	FileIndex            uint32
	FileID               []byte `smb:"fixed:16"`
	FileNameOffset       uint16 `smb:"offset:Buffer"`
	FileNameLength       uint16 `smb:"len:Buffer"`
	OutputBufferLength   uint32
	Buffer               []byte
}

type QueryDirectoryRes struct {
	Header
	StructureSize      uint16 // Must always be 9
	OutputBufferOffset uint16 `smb:"offset:Buffer"`
	OutputBufferLength uint32 `smb:"len:Buffer"`
	Buffer             []byte
}

type QueryInfoReq struct {
	Header
	StructureSize         uint16 // Must always be 41 regardless of Buffer size
	InfoType              byte
	FileInfoClass         byte
	OutputBufferLength    uint32
	InputBufferOffset     uint16
	Reserved              uint16
	InputBufferLength     uint32
	AdditionalInformation uint32
	Flags                 uint32
	FileId                []byte
	Buffer                []byte
}

type QueryInfoRes struct {
	Header
	StructureSize      uint16 // Must always be 9
	OutputBufferOffset uint16
	OutputBufferLength uint32
	Buffer             []byte
}

func (s *QueryInfoReq) MarshalBinary(meta *encoder.Metadata) (ret []byte, err error) {
	log.Traceln("In MarshalBinary for QueryInfoReq")
	buf := make([]byte, 0, 40+len(s.Buffer))

	hBuf, err := encoder.Marshal(s.Header)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}
	buf = append(buf, hBuf...)
	// StructureSize
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	// Info Type
	buf = append(buf, s.InfoType)
	// FileInfoClass
	buf = append(buf, s.FileInfoClass)
	// OutputBufferLength
	buf = binary.LittleEndian.AppendUint32(buf, s.OutputBufferLength)
	// InputBufferOffset
	inputBufferOffset := uint16(0)
	if len(s.Buffer) > 0 {
		inputBufferOffset = 104 // 40 bytes for QueryInfo, 64 for SMB2 Header
	}
	buf = binary.LittleEndian.AppendUint16(buf, inputBufferOffset)
	// Reserved
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	// InputBufferLength
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(s.Buffer)))
	// AdditionalInformation
	buf = binary.LittleEndian.AppendUint32(buf, s.AdditionalInformation)
	// Flags
	buf = binary.LittleEndian.AppendUint32(buf, s.Flags)
	// FileID
	buf = append(buf, s.FileId...)
	// Buffer
	buf = append(buf, s.Buffer...)

	return buf, nil
}

// QueryInfoReq.UnmarshalBinary and QueryInfoRes.MarshalBinary live in
// marshal_server.go (server-side direction).

func (s *QueryInfoRes) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Traceln("In UnmarshalBinary for QueryInfoRes")
	if len(buf) < headerSize+8 {
		return fmt.Errorf("QueryInfoRes: response too short (%d bytes)", len(buf))
	}
	err := encoder.Unmarshal(buf[:headerSize], &s.Header)
	if err != nil {
		return err
	}
	offset := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	s.OutputBufferOffset = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	s.OutputBufferLength = binary.LittleEndian.Uint32(buf[offset : offset+4])

	offset = int(s.OutputBufferOffset)
	s.Buffer = buf[offset : offset+int(s.OutputBufferLength)]

	return nil
}

func ParseAccessMask(mask uint32) []string {
	permissions := []string{}
	for v, s := range accessMaskMap {
		if mask&v > 0 {
			permissions = append(permissions, s)
		}
	}
	slices.Sort(permissions)
	return permissions
}

type FileSecurityInformationACL struct {
	Permissions []string
	SID         string
}

type FileSecurityInformation struct {
	OwnerSID string
	GroupSID string
	Access   []FileSecurityInformationACL
}

type FileBothDirectoryInformationStruct struct {
	NextEntryOffset uint32
	FileIndex       uint32
	CreationTime    uint64
	LastAccessTime  uint64
	LastWriteTime   uint64
	ChangeTime      uint64
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  uint32
	FileNameLength  uint32 `smb:"len:FileName"`
	EaSize          uint32
	ShortNameLength byte
	Reserved        byte
	ShortName       []byte `smb:"fixed:24"`
	FileName        []byte
}

type SharedFile struct {
	Name           string
	FullPath       string
	IsDir          bool
	Size           uint64
	IsHidden       bool
	IsReadOnly     bool
	IsJunction     bool
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	//FileId          uint64
}

// MS-SMB2 §2.2.28 Echo (Keepalive) Request — sent by clients to keep an
// otherwise-idle connection alive and verify the server is reachable.
type EchoReq struct {
	Header
	StructureSize uint16 // Must be 4
	Reserved      uint16
}

// MS-SMB2 §2.2.29 Echo Response — same shape as the request.
type EchoRes struct {
	Header
	StructureSize uint16 // Must be 4
	Reserved      uint16
}

type FlushReq struct {
	Header
	StructureSize uint16 // Must be 24
	Reserved1     uint16
	Reserved2     uint32
	FileId        []byte `smb:"fixed:16"`
}

type FlushRes struct {
	Header
	StructureSize uint16 // Must be 4
	Reserved      uint16
}

type ReadReq struct {
	Header
	StructureSize         uint16 // Must always be 49 regardless of Buffer size
	Padding               byte   // Set to 0
	Flags                 byte   // Must be 0 for smb 2.1
	Length                uint32
	Offset                uint64
	FileId                []byte `smb:"fixed:16"`
	MinimumCount          uint32 // How many bytes to at least read for successful operation
	Channel               uint32 // Must be 0 for smb 2.1
	RemainingBytes        uint32 // 0 for smb 2.1
	ReadChannelInfoOffset uint16 // 0 for smb 2.1
	ReadChannelInfoLength uint16 // 0 for smb 2.1
	Buffer                []byte // 0 length for smb 2.1
}

type ReadRes struct {
	Header
	StructureSize uint16 // Must be 17
	DataOffset    byte   `smb:"offset:Buffer"`
	Reserved      byte
	DataLength    uint32 `smb:"len:Buffer"`
	DataRemaining uint32
	Reserved2     uint32 // Must be 0 for smb 2.1
	Buffer        []byte
}

type WriteReq struct {
	Header
	StructureSize          uint16 // Must always be 49 regardless of Buffer size
	DataOffset             uint16 `smb:"offset:Buffer"` // 0x70. The offset, in bytes, from the beginning of the SMB2 header to the data being written.
	Length                 uint32 `smb:"len:Buffer"`    // The length of the data being written, in bytes. Can be zero bytes.
	Offset                 uint64 // The offset, in bytes, of where to write the data in the destination file. For pipes it must be 0.
	FileId                 []byte `smb:"fixed:16"`
	Channel                uint32 // Must be 0 for smb 2.1
	RemainingBytes         uint32 // Not used in smb 2.1
	WriteChannelInfoOffset uint16 // Not used in smb 2.1
	WriteChannelInfoLength uint16 // Not used in smb 2.1
	Flags                  uint32 // How to process the write operation. Can be 0.
	Buffer                 []byte // 0 length for smb 2.1
}

type WriteRes struct {
	Header
	StructureSize          uint16 // Must be 17
	Reserved               uint16 // Must not be used
	Count                  uint32 // The number of bytes written
	Remaining              uint32 // Must not be used
	WriteChannelInfoOffset uint16 // Must not be used
	WriteChannelInfoLength uint16 // Must not be used
}

type SetInfoReq struct {
	Header
	StructureSize         uint16 // Must always be 33 regardless of Buffer size
	InfoType              byte
	FileInfoClass         byte
	BufferLength          uint32 `smb:"len:Buffer"`    // The length of the data being written, in bytes. Can be zero bytes.
	BufferOffset          uint16 `smb:"offset:Buffer"` // 0x70. The offset, in bytes, from the beginning of the SMB2 header to the data being written.
	Reserved              uint16
	AdditionalInformation uint32
	FileId                []byte `smb:"fixed:16"`
	Buffer                []byte // 0 length for smb 2.1
}

type SetInfoRes struct {
	Header
	StructureSize uint16 // Must be 2
}

// NOTE Might be problematic and not work with multiple offset tags for same buffer?
type IoCtlReq struct { // 120 + len of Buffer
	Header                   // 64 bytes
	StructureSize     uint16 // Must be 57
	Reserved          uint16 // Must be 0
	CtlCode           uint32
	FileId            []byte `smb:"fixed:16"`
	InputOffset       uint32 `smb:"offset:Buffer"`
	InputCount        uint32 `smb:"len:Buffer"`
	MaxInputResponse  uint32
	OutputOffset      uint32 //`smb:"offset:Buffer"` // Must be 0
	OutputCount       uint32 //`smb:"len:Buffer"` // Must be 0
	MaxOutputResponse uint32 // Max response size. Test 4280
	Flags             uint32
	Reserved2         uint32 // Must be 0
	Buffer            []byte
}

type IoCtlRes struct {
	Header
	StructureSize uint16 // Must be 49
	Reserved      uint16 // Must be 0
	CtlCode       uint32
	FileId        []byte `smb:"fixed:16"`
	InputOffset   uint32 `smb:"offset:Buffer"`
	InputCount    uint32 `smb:"len:Buffer"`
	OutputOffset  uint32 `smb:"offset:Buffer"` // Must be 0
	OutputCount   uint32 `smb:"len:Buffer"`    // Must be 0
	Flags         uint32
	Reserved2     uint32 // Must be 0
	Buffer        []byte
}

// calcCreditCharge returns the number of credits a request consumes for a
// payload of payloadSize bytes: CreditCharge = (payloadSize - 1) / 65536 + 1
// (MS-SMB2 §3.1.5.2), i.e. one credit per 64 KiB or fraction thereof. Integer
// division is required — a float ceil over-charges by one at exact multiples of
// 65536 (e.g. a 64 KiB read would take 2 credits instead of 1), needlessly
// draining the window.
func calcCreditCharge(payloadSize uint32) uint16 {
	if payloadSize <= 1 {
		return 1
	}
	return uint16((payloadSize-1)/65536 + 1)
}

func (s *NegotiateReq) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Traceln("In MarshalBinary for NegotiateReq")
	buf := make([]byte, 0, 100)
	padding := 0
	hBuf, err := encoder.Marshal(s.Header)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}
	buf = append(buf, hBuf...)
	// StructureSize
	buf = binary.LittleEndian.AppendUint16(buf, s.StructureSize)
	// DialectCount
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(s.Dialects)))
	// SecurityMode
	buf = binary.LittleEndian.AppendUint16(buf, s.SecurityMode)
	//Reserved
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	// Capabilities
	buf = binary.LittleEndian.AppendUint32(buf, s.Capabilities)
	buf = append(buf, s.ClientGuid...)
	if len(s.ContextList) == 0 {
		buf = binary.LittleEndian.AppendUint32(buf, 0)
		buf = binary.LittleEndian.AppendUint16(buf, 0)
	} else {
		// Pad the dialect array up to the next 8-byte boundary so the first
		// negotiate context is 8-aligned. The outer % 8 keeps padding at 0 when
		// the array already ends on a boundary (e.g. a 2-dialect custom offer),
		// instead of inserting a spurious 8 bytes.
		padding = (8 - ((36 + len(s.Dialects)*2) % 8)) % 8
		offset := 64 + 36 + len(s.Dialects)*2 + padding
		buf = binary.LittleEndian.AppendUint32(buf, uint32(offset))
		buf = binary.LittleEndian.AppendUint16(buf, s.NegotiateContextCount)
	}
	// Reserved2
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	if len(s.Dialects) != 0 {
		for _, d := range s.Dialects {
			buf = binary.LittleEndian.AppendUint16(buf, d)
		}
	}
	if len(s.ContextList) != 0 {
		// Padding
		buf = append(buf, make([]byte, padding)...)
		for _, c := range s.ContextList {
			contextBuf, err := encoder.Marshal(c)
			if err != nil {
				log.Debugln(err)
				return nil, err
			}
			buf = append(buf, contextBuf...)
		}
	}
	return buf, nil
}

func (s *NegotiateReq) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	log.Traceln("In UnmarshalBinary for NegotiateReq")
	// 64-byte header + 36-byte fixed body before the dialect array.
	if len(buf) < headerSize+36 {
		return fmt.Errorf("NegotiateReq: request too short (%d bytes)", len(buf))
	}
	err := encoder.Unmarshal(buf[:headerSize], &s.Header)
	if err != nil {
		return err
	}
	offset := 64
	s.StructureSize = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	s.DialectCount = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	s.SecurityMode = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	// 2 bytes reserved
	offset += 2
	s.Capabilities = binary.LittleEndian.Uint32(buf[offset : offset+4])
	offset += 4
	s.ClientGuid = buf[offset : offset+16]
	offset += 16
	s.NegotiateContextOffset = binary.LittleEndian.Uint32(buf[offset : offset+4])
	offset += 4
	s.NegotiateContextCount = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2
	// 2 bytes reserved2
	offset += 2
	for i := 0; i < int(s.DialectCount); i++ {
		s.Dialects = append(s.Dialects, binary.LittleEndian.Uint16(buf[offset:offset+2]))
		offset += 2
	}

	offset = int(s.NegotiateContextOffset)
	for i := 0; i < int(s.NegotiateContextCount); i++ {
		var negContext NegContext
		err = encoder.Unmarshal(buf[offset:], &negContext)
		if err != nil {
			return err
		}
		s.ContextList = append(s.ContextList, negContext)
		negContextSize := int(8 + negContext.DataLength)
		if negContextSize%8 != 0 {
			negContextSize += 8 - (negContextSize % 8)
		}
		offset += negContextSize
	}

	return nil
}

// newHeader returns an SMB2 header with CreditCharge=0. Callers that target
// SMB 2.1+ MUST set CreditCharge to a non-zero credits-consumed value before
// sending (typically 1, or the result of calcCreditCharge for large
// transfers). In SMB 2.0.2 the field MUST remain 0 (MS-SMB2 §2.2.1.2).
func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  0,
		Status:        0,
		Command:       0,
		Credits:       1,
		Flags:         0,
		NextCommand:   0,
		MessageID:     0,
		Reserved:      0,
		TreeID:        0,
		SessionID:     0,
		Signature:     make([]byte, 16),
	}
}

// applyCreditCharge sets header.CreditCharge per the negotiated dialect.
// SMB 2.0.2 reserves the field (must be 0); all other dialects use it as the
// number of credits the request consumes (default 1 unless the caller has
// already set a larger value via calcCreditCharge).
func (s *Session) applyCreditCharge(header *Header) {
	if s.dialect == DialectSmb_2_0_2 {
		header.CreditCharge = 0
		return
	}
	if header.CreditCharge == 0 {
		header.CreditCharge = 1
	}
}

func NewTransformHeader() TransformHeader {
	return TransformHeader{
		ProtcolID: 0x424D53FD,
		Signature: make([]byte, 16),
		Nonce:     make([]byte, 16),
		Flags:     0x0001, // For SMB 3.1.1 and means Encrypted
	}
}

func (s *Session) NewNegotiateReq() (req NegotiateReq, err error) {
	header := newHeader()
	header.Command = CommandNegotiate
	// CreditCharge stays at 0: dialect not yet known, and 2.0.2 requires 0.
	// Servers running 2.1+ ignore the value on the NegotiateReq itself.

	var dialects []uint16

	switch {
	case len(s.options.Dialects) > 0:
		// Caller-supplied offer (validated in validateOptions). Copy so the
		// request does not alias the caller's slice. To pin the legacy SMB 2.1
		// path, callers set Options.Dialects = DialectsSMB2Only.
		dialects = append([]uint16(nil), s.options.Dialects...)
	default:
		dialects = []uint16{
			DialectSmb_3_1_1,
			DialectSmb_3_0_2,
			DialectSmb_3_0,
			DialectSmb_2_1,
			DialectSmb_2_0_2,
		}
	}

	// MS-SMB2 §2.2.3: the Capabilities field MUST be 0 unless the client
	// implements SMB 3.x, and the negotiate contexts (preauth integrity,
	// encryption, signing) are 3.1.1-only. Detect both from the offered list
	// so a custom Dialects set is handled correctly.
	offers3x := false
	offers311 := false
	for _, d := range dialects {
		if d >= DialectSmb_3_0 {
			offers3x = true
		}
		if d == DialectSmb_3_1_1 {
			offers311 = true
		}
	}

	var capabilities uint32
	if offers3x {
		capabilities = GlobalCapLargeMTU
		if !s.options.DisableEncryption {
			capabilities |= GlobalCapEncryption
		}
	}

	req = NegotiateReq{
		Header:        header,
		StructureSize: 36,
		DialectCount:  uint16(len(dialects)),
		SecurityMode:  SecurityModeSigningEnabled,
		Reserved:      0,
		Capabilities:  capabilities,
		ClientGuid:    s.clientGuid,
		Dialects:      dialects,
	}
	if s.isSigningRequired.Load() {
		req.SecurityMode = SecurityModeSigningEnabled | SecurityModeSigningRequired
	}

	if offers311 {
		pic := PreauthIntegrityContext{
			HashAlgorithmCount: 1,
			HashAlgorithms:     []uint16{SHA512},
			SaltLength:         32,
			Salt:               make([]byte, 32),
		}
		if _, err := rand.Read(pic.Salt); err != nil {
			return req, err
		}
		ciphers := s.options.Ciphers
		if ciphers == nil {
			ciphers = []uint16{AES128CCM, AES128GCM, AES256CCM, AES256GCM}
		}
		cc := EncryptionContext{
			CipherCount: uint16(len(ciphers)),
			Ciphers:     ciphers,
		}
		sc := SigningContext{
			// Order matters: highest-preference first. AES_GMAC is the
			// fastest on modern hardware (Windows 11 / Server 2022+);
			// AES_CMAC is the universal SMB 3.x default; HMAC_SHA256 is
			// included for legacy interop.
			SigningAlgorithms: []uint16{AES_GMAC, AES_CMAC, HMAC_SHA256},
		}
		sc.SigningAlgorithmCount = uint16(len(sc.SigningAlgorithms))

		picBuf, err := encoder.Marshal(pic)
		if err != nil {
			return NegotiateReq{}, err
		}

		ccBuf, err := encoder.Marshal(cc)
		if err != nil {
			return NegotiateReq{}, err
		}

		scBuf, err := encoder.Marshal(sc)
		if err != nil {
			return NegotiateReq{}, err
		}

		req.ContextList = []NegContext{
			{
				ContextType: PreauthIntegrityCapabilities,
				Data:        picBuf,
				DataLength:  uint16(len(picBuf)),
				Padd:        make([]byte, (8-(len(picBuf)%8))%8),
			},
		}
		n := NegContext{
			ContextType: EncryptionCapabilities,
			Data:        ccBuf,
			DataLength:  uint16(len(ccBuf)),
			Padd:        make([]byte, (8-(len(ccBuf)%8))%8),
		}
		req.ContextList = append(req.ContextList, n)

		// Compression is offered only when opted in. When present it becomes the
		// last context, so SigningCapabilities now needs trailing 8-byte
		// alignment padding (it was previously last and unpadded).
		offerCompression := s.options.Compression
		signingPad := []byte(nil)
		if offerCompression {
			signingPad = make([]byte, (8-(len(scBuf)%8))%8)
		}
		n = NegContext{
			ContextType: SigningCapabilities,
			Data:        scBuf,
			DataLength:  uint16(len(scBuf)),
			Padd:        signingPad,
		}
		/*
			TODO When rewriting the marshalling, move padding to before instead ot after each context based on alignment.
			The first negotiate context in the list MUST appear at the byte offset
			indicated by the SMB2 NEGOTIATE request's NegotiateContextOffset field.
			Subsequent negotiate contexts MUST appear at the first 8-byte-aligned
			offset following the previous negotiate context.
		*/
		req.ContextList = append(req.ContextList, n)

		if offerCompression {
			algs := s.options.CompressionAlgorithms
			if algs == nil {
				algs = compress.DefaultAlgorithms
			}
			comp := CompressionContext{
				CompressionAlgorithmCount: uint16(len(algs)),
				Flags:                     CompressionCapabilitiesFlagChained,
				CompressionAlgorithms:     algs,
			}
			compBuf, err := encoder.Marshal(comp)
			if err != nil {
				return NegotiateReq{}, err
			}
			req.ContextList = append(req.ContextList, NegContext{
				ContextType: CompressionCapabilities,
				Data:        compBuf,
				DataLength:  uint16(len(compBuf)),
				// Last context: no trailing padding required.
			})
		}

		req.NegotiateContextCount = uint16(len(req.ContextList))
	}

	return
}

func NewNegotiateRes() NegotiateRes {
	res := NegotiateRes{
		Header:                 newHeader(),
		StructureSize:          0x41,
		SecurityMode:           0,
		DialectRevision:        0,
		NegotiateContextCount:  0,
		ServerGuid:             make([]byte, 16),
		Capabilities:           0,
		MaxTransactSize:        0,
		MaxReadSize:            0,
		MaxWriteSize:           0,
		SystemTime:             0,
		ServerStartTime:        0,
		SecurityBufferOffset:   0,
		SecurityBufferLength:   0,
		NegotiateContextOffset: 0,
		SecurityBlob:           &gss.NegTokenInit{},
		ContextList:            []NegContext{},
	}
	res.Header.Flags = 0x1 // Response
	return res
}

func (s *Connection) NewSessionSetup1Req(spnegoClient *spnego.Client) (req SessionSetup1Req, err error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	negTokenInitbytes, err := spnegoClient.InitSecContext(nil)
	if err != nil {
		return
	}

	var init gss.NegTokenInit
	err = encoder.Unmarshal(negTokenInitbytes, &init)
	if err != nil {
		return
	}

	req = SessionSetup1Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		Capabilities:         s.capabilities,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}

	// MS-SMB2 §2.2.5: SMB2_NEGOTIATE_SIGNING_REQUIRED implies (and must be
	// combined with) SMB2_NEGOTIATE_SIGNING_ENABLED. Sending 0x02 alone
	// (REQUIRED but not ENABLED) is contradictory; strict servers (Windows)
	// can TCP-RST the connection instead of replying with an SMB error.
	if s.isSigningRequired.Load() {
		req.SecurityMode = byte(SecurityModeSigningEnabled | SecurityModeSigningRequired)
	} else {
		req.SecurityMode = byte(SecurityModeSigningEnabled)
	}

	return req, nil
}

func NewSessionSetup1Req() SessionSetup1Req {
	ret := SessionSetup1Req{
		Header:       newHeader(),
		SecurityBlob: &gss.NegTokenInit{},
	}
	return ret
}

// NewSessionSetupRawReq builds a SessionSetup request carrying a bare NTLMSSP
// token (no SPNEGO wrapper). It is used for both legs of the RawNTLMSSP client
// flow: the caller supplies the NTLMSSP NEGOTIATE (leg 1) or AUTHENTICATE
// (leg 2) bytes as blob, and sets the header SessionID for leg 2. The generic
// SessionSetupReq (SecurityBlob []byte) is reused so the token bytes are placed
// on the wire verbatim.
func (s *Connection) NewSessionSetupRawReq(blob []byte) SessionSetupReq {
	header := newHeader()
	header.Command = CommandSessionSetup
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	req := SessionSetupReq{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		Capabilities:         s.capabilities,
		Channel:              0,
		SecurityBufferOffset: 88,
		PreviousSessionID:    0,
		SecurityBlob:         blob,
	}

	// See NewSessionSetup1Req for the rationale on combining ENABLED+REQUIRED.
	if s.isSigningRequired.Load() {
		req.SecurityMode = byte(SecurityModeSigningEnabled | SecurityModeSigningRequired)
	} else {
		req.SecurityMode = byte(SecurityModeSigningEnabled)
	}
	return req
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:        newHeader(),
		StructureSize: 0x9,
		SecurityBlob:  &resp,
	}
	ret.Header.Flags = 0x1 // Response
	return ret, nil
}

func (s *Connection) NewSessionSetup2Req(sc []byte, msg *SessionSetup1Res) (SessionSetup2Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	var resp gss.NegTokenResp
	err := encoder.Unmarshal(sc, &resp)
	if err != nil {
		return SessionSetup2Req{}, err
	}

	// Session setup request #2
	req := SessionSetup2Req{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		Capabilities:         s.capabilities,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &resp,
	}

	// See NewSessionSetup1Req for the rationale on combining ENABLED+REQUIRED.
	if s.isSigningRequired.Load() {
		req.SecurityMode = byte(SecurityModeSigningEnabled | SecurityModeSigningRequired)
	} else {
		req.SecurityMode = byte(SecurityModeSigningEnabled)
	}

	return req, nil
}

func NewSessionSetup2Res() (SessionSetup2Res, error) {
	resp, _ := gss.NewNegTokenResp()
	ret := SessionSetup2Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

func (s *Session) NewLogoffReq() LogoffReq {
	header := newHeader()
	header.Command = CommandLogoff
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	ret := LogoffReq{
		Header:        header,
		StructureSize: 4,
	}
	return ret
}

func NewLogoffRes() LogoffRes {
	ret := LogoffRes{
		Header:        newHeader(),
		StructureSize: 4,
	}
	return ret
}

// NewTreeConnectReq creates a new TreeConnect message and accepts the share name
// as input.
func (s *Session) NewTreeConnectReq(name string) (TreeConnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeConnect
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	path := fmt.Sprintf("\\\\%s\\%s", s.options.Host, name)
	return TreeConnectReq{
		Header:        header,
		StructureSize: 9,
		Reserved:      0,
		PathOffset:    0,
		PathLength:    0,
		Path:          encoder.ToUnicode(path),
	}, nil
}

func NewTreeConnectRes() (TreeConnectRes, error) {
	return TreeConnectRes{}, nil
}

func (s *Session) NewTreeDisconnectReq(treeId uint32) (TreeDisconnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeDisconnect
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = treeId

	return TreeDisconnectReq{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}

func NewTreeDisconnectRes() (TreeDisconnectRes, error) {
	return TreeDisconnectRes{}, nil
}

func (s *Session) NewCreateReq(share, name string,
	opLockLevel byte,
	impersonationLevel uint32,
	desiredAccess uint32,
	fileAttr uint32,
	shareAccess uint32,
	createDisp uint32,
	createOpts uint32) (CreateReq, error) {

	header := newHeader()
	header.Command = CommandCreate
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)
	var buf []byte
	var nameLen uint16
	if len(name) > 0 {
		uname := encoder.ToUnicode(name)
		nameLen = uint16(len(uname))
		buf = make([]byte, nameLen)
		copy(buf, uname)
	} else {
		buf = make([]byte, 1)
	}

	return CreateReq{
		Header:               header,
		StructureSize:        57, // Must be 57
		SecurityFlags:        0,  // Must be 0
		RequestedOplockLevel: opLockLevel,
		ImpersonationLevel:   impersonationLevel, //Should likely be ImpersonationLevelImpersonation (2)
		SmbCreateFlags:       0,                  // Must be 0
		Reserved:             0,
		DesiredAccess:        desiredAccess,
		FileAttributes:       fileAttr,
		ShareAccess:          shareAccess,
		CreateDisposition:    createDisp,
		CreateOptions:        createOpts,
		NameOffset:           120, // 120 byte offset from start of CreateReq header to beginning of buffer as name is first entry in buffer.
		NameLength:           nameLen,
		CreateContextsOffset: 0,
		CreateContextsLength: 0,
		Buffer:               buf,
	}, nil
}

func (s *Session) NewCloseReq(share string, fileId []byte) (CloseReq, error) {
	header := newHeader()
	header.Command = CommandClose
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	return CloseReq{
		Header:        header,
		StructureSize: 24,
		Flags:         0x0000,
		Reserved:      0,
		FileId:        fileId,
	}, nil
}

// NewOplockBreakAck builds an SMB2 OPLOCK_BREAK acknowledgment for a break the
// server signalled on fileId (MS-SMB2 §2.2.24.1 / §3.2.5.19). oplockLevel is the
// level the client is willing to hold after the break — typically
// OpLockLevelII or OpLockLevelNone.
func (s *Session) NewOplockBreakAck(fileId []byte, oplockLevel byte) OplockBreak {
	header := newHeader()
	header.Command = CommandOplockBreak
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	return OplockBreak{
		Header:        header,
		StructureSize: 24,
		OplockLevel:   oplockLevel,
		FileId:        fileId,
	}
}

// NewCancelReq builds an SMB2 CANCEL for the request identified by msgId /
// asyncId (MS-SMB2 §2.2.30 / §3.2.4.24). When asyncId is non-zero the target
// had returned an interim STATUS_PENDING response, so the cancel is flagged
// asynchronous and carries the AsyncId; otherwise it is correlated purely by
// MessageId. The header's MessageId is set to the target's — the caller must
// send this without allocating a fresh id.
func (s *Session) NewCancelReq(msgId, asyncId uint64) CancelReq {
	header := newHeader()
	header.Command = CommandCancel
	s.applyCreditCharge(&header)
	header.MessageID = msgId
	header.SessionID = s.sessionID
	if asyncId != 0 {
		header.Flags |= SMB2_FLAGS_ASYNC_COMMAND
		// In an async header the 8-byte AsyncId overlays Reserved+TreeID.
		header.Reserved = uint32(asyncId & 0xffffffff)
		header.TreeID = uint32(asyncId >> 32)
	}

	return CancelReq{
		Header:        header,
		StructureSize: 4,
	}
}

// NewEchoReq builds an SMB2 ECHO request (MS-SMB2 §2.2.28), a connection-level
// keepalive that carries no body and targets no tree.
func (s *Session) NewEchoReq() EchoReq {
	header := newHeader()
	header.Command = CommandEcho
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID

	return EchoReq{
		Header:        header,
		StructureSize: 4,
	}
}

// NewFlushReq builds an SMB2 FLUSH request (MS-SMB2 §2.2.17) asking the server
// to commit buffered data for the open handle fileId to stable storage.
func (s *Session) NewFlushReq(share string, fileId []byte) FlushReq {
	header := newHeader()
	header.Command = CommandFlush
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	return FlushReq{
		Header:        header,
		StructureSize: 24,
		FileId:        fileId,
	}
}

func (s *Session) NewQueryDirectoryReq(share, pattern string, fileId []byte,
	fileInformationClass byte,
	flags byte,
	fileIndex uint32,
	outputBufferLength uint32,
) (QueryDirectoryReq, error) {
	/*
		The CreditCharge of an SMB2 operation is computed from the payload size (the size of the data within
		the variable-length field of the request) or the maximum size of the response.
		CreditCharge = (max(SendPayloadSize, Expected ResponsePayloadSize) – 1) / 65536 + 1
	*/
	header := newHeader()
	header.Command = CommandQueryDirectory
	header.CreditCharge = calcCreditCharge(outputBufferLength)
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	if pattern == "" {
		/* QueryDirectory has a fixed Structure Size of 33 which seems to mean
		   that a QueryDirectory request can not be less that 33 bytes in length.
		   An empty pattern is supposed to be represented by a pattern offset and
		   pattern length of 0, but that would lead to a 32 byte request which is
		   invalid. As such at least 1 byte has to be stored in the pattern buffer
		   but the offset and length must still be specified to 0.
		   Due to a problem with how the generic encoder is implemented it is not
		   possible to manually specify the length and offset of a buffer.
		   So either implement some workaround or just replace an empty pattern
		   with a pattern of "*" which serves as a wildcard.
		*/
		pattern = "*"
	}
	var buf []byte
	upattern := encoder.ToUnicode(pattern)
	patternLen := uint16(len(upattern))
	buf = make([]byte, patternLen)
	copy(buf, upattern)

	return QueryDirectoryReq{
		Header:               header, //Size 64 bytes
		StructureSize:        33,
		FileInformationClass: fileInformationClass,
		Flags:                flags,
		FileIndex:            fileIndex,
		FileID:               fileId,
		OutputBufferLength:   outputBufferLength,
		Buffer:               buf,
	}, nil
}

func (s *Session) NewReadReq(share string, fileid []byte,
	length uint32,
	offset uint64,
	minRead uint32,
) (ReadReq, error) {

	header := newHeader()
	header.Command = CommandRead
	header.CreditCharge = calcCreditCharge(length)
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	return ReadReq{
		Header:                header, //Size 64 bytes
		StructureSize:         49,
		Padding:               0,
		Flags:                 0,
		Length:                length,
		Offset:                offset,
		FileId:                fileid,
		MinimumCount:          minRead,
		Channel:               0,
		RemainingBytes:        0,
		ReadChannelInfoOffset: 0,
		ReadChannelInfoLength: 0,
		Buffer:                make([]byte, 1),
	}, nil
}

func (s *Session) NewWriteReq(share string, fileid []byte,
	offset uint64,
	data []byte,
) (WriteReq, error) {

	header := newHeader()
	header.Command = CommandWrite
	header.CreditCharge = calcCreditCharge(uint32(len(data)))
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	fileSize := len(data)
	buf := make([]byte, fileSize)
	copy(buf, data)

	return WriteReq{
		Header:                 header, //Size 64 bytes
		StructureSize:          49,
		DataOffset:             0x70,
		Length:                 uint32(fileSize),
		Offset:                 offset,
		FileId:                 fileid,
		Channel:                0,
		RemainingBytes:         0,
		WriteChannelInfoOffset: 0,
		WriteChannelInfoLength: 0,
		Buffer:                 buf,
	}, nil
}

func (f *File) NewIoCTLReq(operation uint32, data []byte) (*IoCtlReq, error) {
	if f.fd == nil {
		return nil, fmt.Errorf("can't operate on a closed file")
	}
	header := newHeader()
	header.Command = CommandIOCtl
	f.applyCreditCharge(&header)
	header.SessionID = f.sessionID
	header.TreeID = f.shareid

	dataLen := len(data)
	buf := make([]byte, dataLen)
	if dataLen > 0 {
		copy(buf, data)
	}

	return &IoCtlReq{
		Header:            header, //Size 64 bytes
		StructureSize:     57,
		Reserved:          0,
		CtlCode:           operation,
		FileId:            f.fd,
		InputOffset:       120, // Static value?
		InputCount:        uint32(dataLen),
		MaxInputResponse:  0,
		OutputOffset:      120,
		OutputCount:       0,
		MaxOutputResponse: 4280,
		Flags:             IoctlIsFsctl,
		Reserved2:         0,
		Buffer:            buf,
	}, nil
}

func (s *Session) NewSetInfoReq(share string, fileId []byte) (SetInfoReq, error) {

	header := newHeader()
	header.Command = CommandSetInfo
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	return SetInfoReq{
		Header:        header,
		StructureSize: 33,
		InfoType:      OInfoFile,
		FileInfoClass: FileDispositionInformation,
		FileId:        fileId,
	}, nil
}

func (s *Session) NewQueryInfoReq(
	share string,
	fileId []byte,
	infoType byte,
	fileInformationClass byte,
	additionalInformation uint32,
	flags uint32,
	outputBufferLength uint32,
	inputBuffer []byte,
) (QueryInfoReq, error) {
	header := newHeader()
	header.Command = CommandQueryInfo
	header.CreditCharge = calcCreditCharge(outputBufferLength)
	s.applyCreditCharge(&header)
	header.SessionID = s.sessionID
	header.TreeID = s.treeId(share)

	return QueryInfoReq{
		Header:                header, //Size 64 bytes
		StructureSize:         41,
		InfoType:              infoType,
		FileInfoClass:         fileInformationClass,
		AdditionalInformation: additionalInformation,
		Flags:                 flags,
		FileId:                fileId,
		OutputBufferLength:    outputBufferLength,
		Buffer:                inputBuffer,
	}, nil
}
