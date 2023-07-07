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
	"errors"
	"fmt"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/encoder"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb")

const ProtocolSmb = "\xFFSMB"
const ProtocolSmb2 = "\xFESMB"
const ProtocolTransformHdr = "\xFDSMB"

const SHA512 = 0x001

const (
	StatusOk                     = 0x00000000
	StatusPending                = 0x00000103
	StatusBufferOverflow         = 0x80000005
	StatusNoMoreFiles            = 0x80000006
	StatusInfoLengthMismatch     = 0xc0000004
	StatusInvalidParameter       = 0xc000000d
	StatusNoSuchFile             = 0xc000000f
	StatusEndOfFile              = 0xc0000011
	StatusMoreProcessingRequired = 0xc0000016
	StatusAccessDenied           = 0xc0000022
	StatusObjectNameNotFound     = 0xc0000034
	StatusLogonFailure           = 0xc000006d
	StatusBadNetworkName         = 0xc00000cc
	StatusUserSessionDeleted     = 0xc0000203
)

var StatusMap = map[uint32]error{
	StatusOk:                     fmt.Errorf("OK"),
	StatusPending:                fmt.Errorf("Status Pending"),
	StatusBufferOverflow:         fmt.Errorf("Response buffer overflow"),
	StatusNoMoreFiles:            fmt.Errorf("No more files"),
	StatusInfoLengthMismatch:     fmt.Errorf("Insuffient size of response buffer"),
	StatusInvalidParameter:       fmt.Errorf("Invalid Parameter"),
	StatusNoSuchFile:             fmt.Errorf("No such file"),
	StatusEndOfFile:              fmt.Errorf("The end-of-file marker has been reached"),
	StatusMoreProcessingRequired: fmt.Errorf("More Processing Required"),
	StatusAccessDenied:           fmt.Errorf("Access denied!"),
	StatusObjectNameNotFound:     fmt.Errorf("Requested file does not exist"),
	StatusLogonFailure:           fmt.Errorf("Logon failed"),
	StatusBadNetworkName:         fmt.Errorf("Bad network name"),
	StatusUserSessionDeleted:     fmt.Errorf("User session deleted"),
}

const DialectSmb_2_0_2 = 0x0202
const DialectSmb_2_1 = 0x0210
const DialectSmb_3_0 = 0x0300
const DialectSmb_3_0_2 = 0x0302
const DialectSmb_3_1_1 = 0x0311
const DialectSmb2_ALL = 0x02FF

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

// MS-SMB2 Section 2.2.3.1.2 Ciphers
const (
	AES128CCM uint16 = 0x0001
	AES128GCM uint16 = 0x0002
	AES256CCM uint16 = 0x0003
	AES256GCM uint16 = 0x0004
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

// MS-FSCC Status codes
const (
	FsctlStatusPipeDisconnected      uint32 = 0xC00000B0 //The specified named pipe is in the disconnected state.
	FsctlStatusInvalidPipeState      uint32 = 0xC00000AD //The named pipe is not in the connected state or not in the full-duplex message mode.
	FsctlStatusPipeBusy              uint32 = 0xC00000AE //The named pipe contains unread data.
	FsctlStatusInvalidUserBuffer     uint32 = 0xC00000E8 //An exception was raised while accessing a user buffer.
	FsctlStatusInsufficientResources uint32 = 0xC000009A //There were insufficient resources to complete the operation.
	FsctlStatusInvalidDeviceRequest  uint32 = 0xC0000010 //The type of the handle is not a pipe.
	FsctlStatusBufferOverflow        uint32 = 0x80000005 //The data was too large to fit into
)

var FsctlStatusMap = map[uint32]error{
	FsctlStatusPipeDisconnected:      fmt.Errorf("FSCTL_STATUS_PIPE_DISCONNECTED"),
	FsctlStatusInvalidPipeState:      fmt.Errorf("FSCTL_STATUS_INVALID_PIPE_STATE"),
	FsctlStatusPipeBusy:              fmt.Errorf("FSCTL_STATUS_PIPE_BUSY"),
	FsctlStatusInvalidUserBuffer:     fmt.Errorf("FSCTL_STATUS_INVALID_USER_BUFFER"),
	FsctlStatusInsufficientResources: fmt.Errorf("FSCTL_STATUS_INSUFFICIENT_RESOURCES"),
	FsctlStatusInvalidDeviceRequest:  fmt.Errorf("FSCTL_STATUS_INVALID_DEVICE_REQUEST"),
	FsctlStatusBufferOverflow:        fmt.Errorf("FSCTL_STATUS_BUFFER_OVERFLOW"),
}

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

type TransformHeader struct { // 52 bytes
	ProtcolID           uint32
	Signature           []byte `smb:"fixed:16"`
	Nonce               []byte `smb:"fixed:16"` // 12 bytes nonce + 4 bytes set to 0
	OriginalMessageSize uint32
	Reserved            uint16
	Flags               uint16 //SMB 3.1.1
	SessionId           uint64
}

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

type NegotiateRes struct {
	Header
	StructureSize          uint16
	SecurityMode           uint16
	DialectRevision        uint16
	NegotiateContextCount  uint16 `smb:"count:ContextList"`
	ServerGuid             []byte `smb:"fixed:16"`
	Capabilities           uint32
	MaxTransactSize        uint32
	MaxReadSize            uint32
	MaxWriteSize           uint32
	SystemTime             uint64
	ServerStartTime        uint64
	SecurityBufferOffset   uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength   uint16 `smb:"len:SecurityBlob"`
	NegotiateContextOffset uint32 `smb:"offset:ContextList"`
	SecurityBlob           *gss.NegTokenInit
	Padding                []byte `smb:"align:8"` // Perhaps remove this and move padding from NegContext to beginning of struct?
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

type Filetime struct {
	DwLowDateTime  uint32
	DwHighDateTime uint32
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

func (self *NegotiateReq) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for NegotiateReq")
	fmt.Println("Here in marshal binary")
	buf := make([]byte, 0, 100)
	padding := 0
	hBuf, err := encoder.Marshal(self.Header)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}
	buf = append(buf, hBuf...)
	// StructureSize
	buf = binary.LittleEndian.AppendUint16(buf, self.StructureSize)
	// DialectCount
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(self.Dialects)))
	// SecurityMode
	buf = binary.LittleEndian.AppendUint16(buf, self.SecurityMode)
	//Reserved
	buf = binary.LittleEndian.AppendUint16(buf, 0)
	// Capabilities
	buf = binary.LittleEndian.AppendUint32(buf, self.Capabilities)
	buf = append(buf, make([]byte, 16)...)
	//buf = append(buf, self.ClientGuid...)
	if len(self.ContextList) == 0 {
		buf = binary.LittleEndian.AppendUint32(buf, 0)
		buf = binary.LittleEndian.AppendUint16(buf, 0)
	} else {
		fmt.Printf("Len of contextlist is : %d\n", len(self.ContextList))
		padding = 8 - ((36 + len(self.Dialects)*2) % 8)
		offset := 64 + 36 + len(self.Dialects)*2 + padding
		buf = binary.LittleEndian.AppendUint32(buf, uint32(offset))
		buf = binary.LittleEndian.AppendUint16(buf, self.NegotiateContextCount)
	}
	// Reserved2
	buf = binary.LittleEndian.AppendUint16(buf, 0)

	if len(self.Dialects) != 0 {
		for _, d := range self.Dialects {
			buf = binary.LittleEndian.AppendUint16(buf, d)
		}
	}
	if len(self.ContextList) != 0 {
		// Padding
		buf = append(buf, make([]byte, padding)...)
		for _, c := range self.ContextList {
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

func (self *NegotiateReq) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for NegotiateReq")
}

func newHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  1,
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
	header.CreditCharge = 1

	var dialects []uint16

	if s.options.ForceSMB2 {
		dialects = []uint16{uint16(DialectSmb_2_1)}
	} else {
		dialects = []uint16{
			uint16(DialectSmb_3_1_1),
			uint16(DialectSmb_2_1),
		}
	}

	req = NegotiateReq{
		Header:        header,
		StructureSize: 36,
		DialectCount:  uint16(len(dialects)),
		SecurityMode:  SecurityModeSigningEnabled,
		Reserved:      0,
		Capabilities:  GlobalCapLargeMTU,
		ClientGuid:    s.clientGuid,
		Dialects:      dialects,
	}
	if s.IsSigningRequired.Load() {
		req.SecurityMode = SecurityModeSigningRequired
	}

	if !s.options.DisableEncryption {
		req.Capabilities |= GlobalCapEncryption
	}

	if !s.options.ForceSMB2 {
		pic := PreauthIntegrityContext{
			HashAlgorithmCount: 1,
			HashAlgorithms:     []uint16{SHA512},
			SaltLength:         32,
			Salt:               make([]byte, 32),
		}
		if _, err := rand.Read(pic.Salt); err != nil {
			log.Errorln(err)
			return req, err
		}
		cc := EncryptionContext{
			CipherCount: 2,
			Ciphers:     []uint16{AES128GCM, AES256GCM},
		}
		sc := SigningContext{
			SigningAlgorithmCount: 3,
			SigningAlgorithms:     []uint16{HMAC_SHA256, AES_CMAC, AES_GMAC},
		}

		picBuf, err := encoder.Marshal(pic)
		if err != nil {
			log.Errorln(err)
			return NegotiateReq{}, err
		}

		ccBuf, err := encoder.Marshal(cc)
		if err != nil {
			log.Errorln(err)
			return NegotiateReq{}, err
		}

		scBuf, err := encoder.Marshal(sc)
		if err != nil {
			log.Errorln(err)
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
		n = NegContext{
			ContextType: SigningCapabilities,
			Data:        scBuf,
			DataLength:  uint16(len(scBuf)),
			Padd:        make([]byte, (8-(len(scBuf)%8))%8),
		}
		req.ContextList = append(req.ContextList, n)

		req.NegotiateContextCount = uint16(len(req.ContextList))
	}

	return
}

func NewNegotiateRes() NegotiateRes {
	return NegotiateRes{
		Header:                 newHeader(),
		StructureSize:          0,
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
}

func (s *Connection) NewSessionSetup1Req(spnegoClient *spnegoClient) (req SessionSetup1Req, err error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.SessionID = s.sessionID

	negTokenInitbytes, err := spnegoClient.initSecContext()
	if err != nil {
		log.Errorln(err)
		return
	}

	var init gss.NegTokenInit
	err = encoder.Unmarshal(negTokenInitbytes, &init)
	if err != nil {
		log.Errorln(err)
		return
	}

	if s.sessionID != 0 {
		return SessionSetup1Req{}, errors.New("Bad session ID for session setup 1 message")
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

	if s.IsSigningRequired.Load() {
		req.SecurityMode = byte(SecurityModeSigningRequired)
	} else {
		req.SecurityMode = byte(SecurityModeSigningEnabled)
	}

	return req, nil
}

func NewSessionSetup1Res() (SessionSetup1Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup1Res{}, err
	}
	ret := SessionSetup1Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

func (s *Connection) NewSessionSetup2Req(client *spnegoClient, msg *SessionSetup1Res) (SessionSetup2Req, error) {
	header := newHeader()
	header.Command = CommandSessionSetup
	header.CreditCharge = 1
	header.SessionID = s.sessionID

	securityBlob, err := encoder.Marshal(msg.SecurityBlob)
	if err != nil {
		log.Errorln(err)
		return SessionSetup2Req{}, err
	}

	respBytes, err := client.acceptSecContext(securityBlob)
	var resp gss.NegTokenResp
	err = encoder.Unmarshal(respBytes, &resp)
	if err != nil {
		log.Errorln(err)
		return SessionSetup2Req{}, err
	}

	if s.sessionID == 0 {
		return SessionSetup2Req{}, errors.New("Bad session ID for session setup 2 message")
	}

	// Session setup request #2
	req := SessionSetup2Req{
		Header:        header,
		StructureSize: 25,
		Flags:         0x00,
		//SecurityMode:         byte(SecurityModeSigningEnabled),
		Capabilities:         s.capabilities,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &resp,
	}

	if s.IsSigningRequired.Load() {
		req.SecurityMode = byte(SecurityModeSigningRequired)
	} else {
		req.SecurityMode = byte(SecurityModeSigningEnabled)
	}

	return req, nil
}

func NewSessionSetup2Res() (SessionSetup2Res, error) {
	resp, err := gss.NewNegTokenResp()
	if err != nil {
		return SessionSetup2Res{}, err
	}
	ret := SessionSetup2Res{
		Header:       newHeader(),
		SecurityBlob: &resp,
	}
	return ret, nil
}

// NewTreeConnectReq creates a new TreeConnect message and accepts the share name
// as input.
func (s *Session) NewTreeConnectReq(name string) (TreeConnectReq, error) {
	header := newHeader()
	header.Command = CommandTreeConnect
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
	header.CreditCharge = 1
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
	header.CreditCharge = 1
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]
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

	if (s.dialect != DialectSmb_2_0_2) && s.supportsMultiCredit {
		header.Credits = 127
		if header.CreditCharge > 127 {
			header.Credits = header.CreditCharge
		}
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
	header.CreditCharge = 1
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]

	return CloseReq{
		Header:        header,
		StructureSize: 24,
		Flags:         0x0000,
		Reserved:      0,
		FileId:        fileId,
	}, nil
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
	header.CreditCharge = uint16((outputBufferLength-1)/65536 + 1)
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]

	if (s.dialect != DialectSmb_2_0_2) && s.supportsMultiCredit {
		header.Credits = 127
		if header.CreditCharge > 127 {
			header.Credits = header.CreditCharge
		}
	}

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
	header.CreditCharge = uint16((length-1)/65536 + 1)
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]

	if (s.dialect != DialectSmb_2_0_2) && s.supportsMultiCredit {
		header.Credits = 127
		if header.CreditCharge > 127 {
			header.Credits = header.CreditCharge
		}
		header.Credits = header.CreditCharge
	}

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
	header.CreditCharge = uint16((len(data)-1)/65536 + 1)
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]

	if (s.dialect != DialectSmb_2_0_2) && s.supportsMultiCredit {
		header.Credits = 127
		if header.CreditCharge > 127 {
			header.Credits = header.CreditCharge
		}
		header.Credits = header.CreditCharge
	}

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
	header := newHeader()
	header.Command = CommandIOCtl
	header.CreditCharge = 1
	header.Credits = 127
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
	header.CreditCharge = 1
	header.SessionID = s.sessionID
	header.TreeID = s.trees[share]

	if (s.dialect != DialectSmb_2_0_2) && s.supportsMultiCredit {
		header.Credits = 127
		if header.CreditCharge > 127 {
			header.Credits = header.CreditCharge
		}
	}

	return SetInfoReq{
		Header:        header,
		StructureSize: 33,
		InfoType:      OInfoFile,
		FileInfoClass: FileDispositionInformation,
		FileId:        fileId,
	}, nil
}
