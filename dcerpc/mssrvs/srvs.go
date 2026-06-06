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

package mssrvs

import (
	"fmt"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/mssrvs").SetDisplayName("mssrvs")

const (
	MSRPCUuidSrvSvc                = "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	MSRPCSrvSvcPipe                = "srvsvc"
	MSRPCSrvSvcMajorVersion uint16 = 3
	MSRPCSrvSvcMinorVersion uint16 = 0
)

// MSRPC Server Service (srvsvc) Operations
const (
	SrvSvcOpNetrSessionEnum      uint16 = 12
	SrvSvcOpNetShareEnumAll      uint16 = 15
	SrvSvcOpNetrShareGetInfo     uint16 = 16
	SrvSvcOpNetrShareSetInfo     uint16 = 17
	SrvSvcOpNetServerGetInfo     uint16 = 21
	SrvSvcOpNetrServerDiskEnum   uint16 = 23
	SrvSvcOpNetrpGetFileSecurity uint16 = 39
)

const (
	StypeDisktree    uint32 = 0x00000000 // Disk drive
	StypePrintq      uint32 = 0x00000001 // Print queue
	StypeDevice      uint32 = 0x00000002 // Communication device
	StypeIPC         uint32 = 0x00000003 // Interprocess communication (IPC)
	StypeClusterFS   uint32 = 0x02000000 // A cluster share
	StypeClusterSOFS uint32 = 0x04000000 // A Scale-Out cluster share
	StypeClusterDFS  uint32 = 0x08000000 // A DFS share in a cluster
	StypeSpecial     uint32 = 0x80000000 // Special share reserved for interprocess communication (IPC$) or remote administration of the server (ADMIN$). Can also refer to administrative shares such as C$, D$, E$, and so forth.
	StypeTemporary   uint32 = 0x40000000 // A temporary share that is not persisted for creation each time the file server initializes.
)

var ShareTypeMap = map[uint32]string{
	StypeDisktree:    "Disk Drive",
	StypePrintq:      "Print Queue",
	StypeDevice:      "Communication Device",
	StypeIPC:         "IPC",
	StypeClusterFS:   "Cluster Share",
	StypeClusterSOFS: "Scale-Out cluster share",
	StypeClusterDFS:  "DFS Share in cluster",
	StypeSpecial:     "Hidden",
	StypeTemporary:   "Temp",
}

const ErrorSuccess uint32 = 0

// MS-SRVS Response codes from 2.2.2.10 Common Error Codes
const (
	SRVSErrorFileNotFound        uint32 = 2
	SRVSErrorAccessDenied        uint32 = 5
	SRVSErrorNotSupported        uint32 = 50
	SRVSErrorDupName             uint32 = 52
	SRVSErrorInvalidParameter    uint32 = 87
	SRVSErrorInvalidLevel        uint32 = 124
	SRVSErrorMoreData            uint32 = 234
	SRVSErrorServiceDoesNotExist uint32 = 1060
	SRVSErrorInvalidDomainName   uint32 = 1212
	SRVSNERRUnknownDevDir        uint32 = 2116
	SRVSNERRRedirectedPath       uint32 = 2117
	SRVSNERRDuplicateShare       uint32 = 2118
	SRVSNERRBufTooSmall          uint32 = 2123
	SRVSNERRUserNotFound         uint32 = 2221
	SRVSNERRNetNameNotFound      uint32 = 2310
	SRVSNERRDeviceNotShared      uint32 = 2311
	SRVSNERRClientNameNotFound   uint32 = 2312
	SRVSNERRInvalidComputer      uint32 = 2351
)

var SRVSResponseCodeMap = map[uint32]error{
	SRVSErrorFileNotFound:        fmt.Errorf("The system cannot find the file specified"),
	SRVSErrorAccessDenied:        fmt.Errorf("The user does not have access to the requested information"),
	SRVSErrorNotSupported:        fmt.Errorf("The server does not support branch cache"),
	SRVSErrorDupName:             fmt.Errorf("A duplicate name exists on the network"),
	SRVSErrorInvalidParameter:    fmt.Errorf("One or more of the specified parameters is invalid"),
	SRVSErrorInvalidLevel:        fmt.Errorf("The value that is specified for the level parameter is invalid"),
	SRVSErrorMoreData:            fmt.Errorf("More entries are available. Specify a large enough buffer to receive all entries"),
	SRVSErrorServiceDoesNotExist: fmt.Errorf("The branch cache component does not exist as an installed service"),
	SRVSErrorInvalidDomainName:   fmt.Errorf("The format of the specified NetBIOS name of a domain is invalid"),
	SRVSNERRUnknownDevDir:        fmt.Errorf("The device or directory does not exist"),
	SRVSNERRRedirectedPath:       fmt.Errorf("The operation is not valid for a redirected resource. The specified device name is assigned to a shared resource"),
	SRVSNERRDuplicateShare:       fmt.Errorf("The share name is already in use on this server"),
	SRVSNERRBufTooSmall:          fmt.Errorf("The client request succeeded. More entries are available. The buffer size that is specified by PreferedMaximumLength was too small to fit even a single entry"),
	SRVSNERRUserNotFound:         fmt.Errorf("The user name could not be found"),
	SRVSNERRNetNameNotFound:      fmt.Errorf("The share name does not exist"),
	SRVSNERRDeviceNotShared:      fmt.Errorf("The device is not shared"),
	SRVSNERRClientNameNotFound:   fmt.Errorf("A session does not exist with the computer name"),
	SRVSNERRInvalidComputer:      fmt.Errorf("The computer name is not valid"),
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

func NewNetSessionEnumRequest(clientName, userName string, level uint32) *NetSessionEnumRequest {
	if level != 0 && level != 10 && level != 502 {
		log.Errorln("Invalid level for NetSessionEnum request. Falling back to level 10")
		level = 10
	}
	resumeHandle := uint32(0)
	nr := NetSessionEnumRequest{
		ServerName:         nil,
		ClientName:         &clientName,
		UserName:           &userName,
		Info:               SessionEnumStruct{Level: level},
		PreferredMaxLength: 0xffffffff,
		ResumeHandle:       &resumeHandle,
	}

	switch level {
	case 0:
		nr.Info.Level0 = &SessionInfoContainer0{}
	case 10:
		nr.Info.Level10 = &SessionInfoContainer10{}
	case 502:
		nr.Info.Level502 = &SessionInfoContainer502{}
	}

	return &nr
}

/*
Send a NetSessionEnum request to the server. Supported levels: 0, 10, 502
*/
func (sb *RPCCon) NetSessionEnum(clientName, username string, level int) (res *SessionEnumStruct, err error) {
	log.Traceln("In NetSessionEnum")
	if level < 0 {
		return nil, fmt.Errorf("Only levels 0, 10 and 502 are valid")
	}
	netReq := NewNetSessionEnumRequest(clientName, username, uint32(level))
	netBuf, err := netReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetrSessionEnum, netBuf)
	if err != nil {
		return
	}

	var response NetSessionEnumResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		return
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetSessionEnum returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetSessionEnum return error: %v\n", responseCode)
		return nil, responseCode
	}

	res = &response.Info
	return
}

func NewNetServerGetInfoRequest(serverName string, level int) *NetServerGetInfoRequest {
	if level < 100 || level > 102 {
		log.Errorln("Invalid level for NetServerGetInfo request. Falling back to level 100")
		level = 100
	}
	nr := NetServerGetInfoRequest{
		ServerName: &serverName,
		Level:      uint32(level),
	}

	return &nr
}

/*
Send a NetServerGetInfo request to the server. Level can be 100, 101, or 102
*/
func (sb *RPCCon) NetServerGetInfo(host string, level int) (res *ServerInfoUnion, err error) {
	log.Traceln("In NetServerGetInfo")
	netReq := NewNetServerGetInfoRequest(host, level)
	netBuf, err := netReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetServerGetInfo, netBuf)
	if err != nil {
		return
	}

	var response NetServerGetInfoResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		return
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetServerGetInfo returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetServerGetInfo return error: %v\n", responseCode)
		return nil, responseCode
	}

	res = &response.Info
	return
}

// parseShareType decodes a SHARE_INFO *_type bitfield into a human-readable
// type string, the dominant Stype* constant, and whether the share is hidden
// (StypeSpecial). Shared by all NetShareEnumAll levels.
func parseShareType(t uint32) (typeStr string, typeId uint32, hidden bool) {
	if (t & StypeClusterDFS) == StypeClusterDFS {
		typeStr = ShareTypeMap[StypeClusterDFS]
		typeId = StypeClusterDFS
	} else if (t & StypeClusterSOFS) == StypeClusterSOFS {
		typeStr = ShareTypeMap[StypeClusterSOFS]
		typeId = StypeClusterSOFS
	} else if (t & StypeClusterFS) == StypeClusterFS {
		typeStr = ShareTypeMap[StypeClusterFS]
		typeId = StypeClusterFS
	} else if (t & StypeIPC) == StypeIPC {
		typeStr = ShareTypeMap[StypeIPC]
		typeId = StypeIPC
	} else if (t & StypeDevice) == StypeDevice {
		typeStr = ShareTypeMap[StypeDevice]
		typeId = StypeDevice
	} else if (t & StypePrintq) == StypePrintq {
		typeStr = ShareTypeMap[StypePrintq]
		typeId = StypePrintq
	} else {
		typeStr = ShareTypeMap[StypeDisktree]
		typeId = StypeDisktree
	}

	if (t & StypeSpecial) == StypeSpecial {
		typeStr += "_" + ShareTypeMap[StypeSpecial]
		hidden = true
	} else if (t & StypeTemporary) == StypeTemporary {
		typeStr += "_" + ShareTypeMap[StypeTemporary]
	}
	return
}

// NetShareEnumAll enumerates the shares on host at info level 1 (name, type,
// comment). For the richer levels see NetShareEnumAllExt.
func (sb *RPCCon) NetShareEnumAll(host string) ([]NetShare, error) {
	return sb.NetShareEnumAllExt(host, 1)
}

// NetShareEnumAllExt enumerates the shares on host at the given info level.
// Supported levels are 1, 501 and 502. The higher levels populate the extra
// NetShare fields: Flags (level 501) and Permissions, MaxUses, CurrentUses,
// Path and SecurityDescriptor (level 502).
func (sb *RPCCon) NetShareEnumAllExt(host string, level int) (res []NetShare, err error) {
	log.Traceln("In NetShareEnumAllExt")
	switch level {
	case 1, 501, 502:
	default:
		return nil, fmt.Errorf("unsupported share enum level %d", level)
	}

	netReq := NewNetShareEnumAllRequestExt(host, uint32(level))
	netBuf, err := netReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetShareEnumAll, netBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	var response NetShareEnumAllResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetShareEnumAll returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetShareEnumAll return error: %v\n", responseCode)
		return nil, responseCode
	}

	switch response.InfoStruct.Level {
	case 1:
		ctr := response.InfoStruct.Level1
		if ctr == nil {
			return nil, nil
		}
		res = make([]NetShare, len(ctr.Buffer))
		for i := range ctr.Buffer {
			res[i].Name = ctr.Buffer[i].Name
			res[i].Comment = ctr.Buffer[i].Comment
			res[i].Type, res[i].TypeId, res[i].Hidden = parseShareType(ctr.Buffer[i].Type)
		}
	case 501:
		ctr := response.InfoStruct.Level501
		if ctr == nil {
			return nil, nil
		}
		res = make([]NetShare, len(ctr.Buffer))
		for i := range ctr.Buffer {
			res[i].Name = ctr.Buffer[i].Name
			res[i].Comment = ctr.Buffer[i].Comment
			res[i].Type, res[i].TypeId, res[i].Hidden = parseShareType(ctr.Buffer[i].Type)
			res[i].Flags = ctr.Buffer[i].Flags
		}
	case 502:
		ctr := response.InfoStruct.Level502
		if ctr == nil {
			return nil, nil
		}
		res = make([]NetShare, len(ctr.Buffer))
		for i := range ctr.Buffer {
			res[i].Name = ctr.Buffer[i].Name
			res[i].Comment = ctr.Buffer[i].Comment
			res[i].Type, res[i].TypeId, res[i].Hidden = parseShareType(ctr.Buffer[i].Type)
			res[i].Permissions = ctr.Buffer[i].Permissions
			res[i].MaxUses = ctr.Buffer[i].MaxUses
			res[i].CurrentUses = ctr.Buffer[i].CurrentUses
			res[i].Path = ctr.Buffer[i].Path
			if len(ctr.Buffer[i].SecurityDescriptor) > 0 {
				var sd msdtyp.SecurityDescriptor
				if perr := sd.UnmarshalBinary(ctr.Buffer[i].SecurityDescriptor); perr != nil {
					log.Errorf("failed to parse security descriptor for share %s: %v\n", ctr.Buffer[i].Name, perr)
				} else {
					res[i].SecurityDescriptor = &sd
				}
			}
		}
	default:
		return nil, fmt.Errorf("server returned unexpected share enum level %d", response.InfoStruct.Level)
	}

	return res, nil
}

// NewNetShareEnumAllRequestExt builds a NetShareEnumAllRequest for the given
// info level (1, 501 or 502). The matching container is left empty for the
// request; the server fills it in the response.
func NewNetShareEnumAllRequestExt(serverName string, level uint32) *NetShareEnumAllRequest {
	resumeHandle := uint32(0)
	nr := &NetShareEnumAllRequest{
		ServerName:   &serverName,
		InfoStruct:   ShareEnumStruct{Level: level},
		MaxBuffer:    0xffffffff,
		ResumeHandle: &resumeHandle,
	}
	switch level {
	case 1:
		nr.InfoStruct.Level1 = &ShareInfoContainer1{}
	case 501:
		nr.InfoStruct.Level501 = &ShareInfoContainer501{}
	case 502:
		nr.InfoStruct.Level502 = &ShareInfoContainer502{}
	}
	return nr
}

func NewNetShareEnumAllRequest(serverName string) *NetShareEnumAllRequest {
	return NewNetShareEnumAllRequestExt(serverName, 1)
}

func (sb *RPCCon) NetGetFileSecurity(share, path string) (sd *msdtyp.SecurityDescriptor, err error) {
	log.Traceln("In NetGetFileSecurity")
	// TODO Validate path
	netReq := NetrpGetFileSecurityReq{
		ServerName:           "",
		ShareName:            share,
		FileName:             path,
		RequestedInformation: 0x4, // DACL Security Information

	}
	netBuf, err := netReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetrpGetFileSecurity, netBuf)
	if err != nil {
		return
	}

	if len(buffer) < 8 {
		return nil, fmt.Errorf("Server response to NetGetFileSecurity was too small. Expected at atleast 8 bytes")
	}
	var response NetrpGetFileSecurityRes
	err = response.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}
	if response.WindowsError != 0 {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetGetFileSecurity returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetGetFileSecurity return error: %v\n", responseCode)
		return nil, responseCode
	}
	var secInfo msdtyp.SecurityDescriptor
	if response.SecurityDescriptor.Length > 0 {
		err = secInfo.UnmarshalBinary(response.SecurityDescriptor.Buffer)
		if err != nil {
			log.Errorln(err)
			return
		}
		sd = &secInfo
	}

	return
}

func NewNetShareGetInfoRequest(serverName, netName string, level uint32) *NetShareGetInfoRequest {
	return &NetShareGetInfoRequest{
		ServerName: &serverName,
		NetName:    netName,
		Level:      level,
	}
}

// NetShareGetInfo retrieves information about a single share at info level 2.
// For other levels see NetShareGetInfoExt.
func (sb *RPCCon) NetShareGetInfo(host, share string) (*NetShare, error) {
	return sb.NetShareGetInfoExt(host, share, 2)
}

// NetShareGetInfoExt retrieves information about a single named share at the
// given info level. Supported levels are 0, 1, 2, 501 and 502. The returned
// NetShare carries whichever fields the level populates (see NetShare).
func (sb *RPCCon) NetShareGetInfoExt(host, share string, level int) (res *NetShare, err error) {
	log.Traceln("In NetShareGetInfoExt")
	switch level {
	case 0, 1, 2, 501, 502:
	default:
		return nil, fmt.Errorf("unsupported share info level %d", level)
	}

	netReq := NewNetShareGetInfoRequest(host, share, uint32(level))
	netBuf, err := netReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetrShareGetInfo, netBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	var response NetShareGetInfoResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetShareGetInfo returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetShareGetInfo return error: %v\n", responseCode)
		return nil, responseCode
	}

	res = &NetShare{}
	switch response.Info.Level {
	case 0:
		info := response.Info.Level0
		if info == nil {
			return nil, nil
		}
		res.Name = info.Name
	case 1:
		info := response.Info.Level1
		if info == nil {
			return nil, nil
		}
		res.Name = info.Name
		res.Comment = info.Comment
		res.Type, res.TypeId, res.Hidden = parseShareType(info.Type)
	case 2:
		info := response.Info.Level2
		if info == nil {
			return nil, nil
		}
		res.Name = info.Name
		res.Comment = info.Comment
		res.Type, res.TypeId, res.Hidden = parseShareType(info.Type)
		res.Permissions = info.Permissions
		res.MaxUses = info.MaxUses
		res.CurrentUses = info.CurrentUses
		res.Path = info.Path
	case 501:
		info := response.Info.Level501
		if info == nil {
			return nil, nil
		}
		res.Name = info.Name
		res.Comment = info.Comment
		res.Type, res.TypeId, res.Hidden = parseShareType(info.Type)
		res.Flags = info.Flags
	case 502:
		info := response.Info.Level502
		if info == nil {
			return nil, nil
		}
		res.Name = info.Name
		res.Comment = info.Comment
		res.Type, res.TypeId, res.Hidden = parseShareType(info.Type)
		res.Permissions = info.Permissions
		res.MaxUses = info.MaxUses
		res.CurrentUses = info.CurrentUses
		res.Path = info.Path
		if len(info.SecurityDescriptor) > 0 {
			var sd msdtyp.SecurityDescriptor
			if perr := sd.UnmarshalBinary(info.SecurityDescriptor); perr != nil {
				log.Errorf("failed to parse security descriptor for share %s: %v\n", info.Name, perr)
			} else {
				res.SecurityDescriptor = &sd
			}
		}
	default:
		return nil, fmt.Errorf("server returned unexpected share info level %d", response.Info.Level)
	}

	return res, nil
}

// netShareSetInfo sends a NetrShareSetInfo request for the given share with the
// supplied info union at the given level. It returns the ParmErr value reported
// by the server (the index of the offending member when WindowsError ==
// SRVSErrorInvalidParameter) together with any error.
func (sb *RPCCon) netShareSetInfo(host, share string, level uint32, info ShareInfoUnion) (parmErr uint32, err error) {
	log.Traceln("In netShareSetInfo")
	info.Level = level
	netReq := &NetShareSetInfoRequest{
		ServerName: &host,
		NetName:    share,
		Level:      level,
		ShareInfo:  info,
	}
	netBuf, err := netReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetrShareSetInfo, netBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	var response NetShareSetInfoResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if response.ParmErr != nil {
		parmErr = *response.ParmErr
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetShareSetInfo returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetShareSetInfo return error: %v (parmErr=%d)\n", responseCode, parmErr)
		err = responseCode
		return
	}

	return
}

// NetShareSetInfo updates a share using a caller-supplied SHARE_INFO union.
// Supported levels are 1, 2, 502, 1004, 1005 and 1501 (the levels MS-SRVS
// allows for NetrShareSetInfo that this package models); the union member
// matching the level must be populated. For the common single-field updates the
// dedicated setters (NetShareSetInfoComment / NetShareSetInfoFlags /
// NetShareSetInfoSecurityDescriptor) are more convenient. It returns the server
// ParmErr index.
func (sb *RPCCon) NetShareSetInfo(host, share string, level int, info *ShareInfoUnion) (uint32, error) {
	if info == nil {
		return 0, fmt.Errorf("NetShareSetInfo requires a non-nil info union")
	}
	var populated bool
	switch level {
	case 1:
		populated = info.Level1 != nil
	case 2:
		populated = info.Level2 != nil
	case 502:
		populated = info.Level502 != nil
	case 1004:
		populated = info.Level1004 != nil
	case 1005:
		populated = info.Level1005 != nil
	case 1501:
		populated = info.Level1501 != nil
	default:
		return 0, fmt.Errorf("unsupported share set-info level %d", level)
	}
	if !populated {
		return 0, fmt.Errorf("NetShareSetInfo level %d requires the matching info union member to be set", level)
	}
	return sb.netShareSetInfo(host, share, uint32(level), *info)
}

// NetShareSetInfoComment sets a share's comment/remark (SHARE_INFO_1004).
func (sb *RPCCon) NetShareSetInfoComment(host, share, comment string) error {
	_, err := sb.netShareSetInfo(host, share, 1004, ShareInfoUnion{
		Level1004: &ShareInfo1004{Comment: comment},
	})
	return err
}

// NetShareSetInfoFlags sets a share's flags (SHARE_INFO_1005), e.g. CSC caching
// or access-based-enumeration flags.
func (sb *RPCCon) NetShareSetInfoFlags(host, share string, flags uint32) error {
	_, err := sb.netShareSetInfo(host, share, 1005, ShareInfoUnion{
		Level1005: &ShareInfo1005{Flags: flags},
	})
	return err
}

// NetShareSetInfoSecurityDescriptor sets a share's security descriptor
// (SHARE_INFO_1501).
func (sb *RPCCon) NetShareSetInfoSecurityDescriptor(host, share string, sd *msdtyp.SecurityDescriptor) error {
	if sd == nil {
		return fmt.Errorf("NetShareSetInfoSecurityDescriptor requires a non-nil security descriptor")
	}
	sdBytes, err := sd.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return err
	}
	_, err = sb.netShareSetInfo(host, share, 1501, ShareInfoUnion{
		Level1501: &ShareInfo1501{
			Reserved:           uint32(len(sdBytes)),
			SecurityDescriptor: sdBytes,
		},
	})
	return err
}

// NetServerDiskEnum enumerates the disk drives configured on host. Only level 0
// is defined by MS-SRVS. It returns the drive names (e.g. "A:", "C:", "D:").
func (sb *RPCCon) NetServerDiskEnum(host string) (res []string, err error) {
	log.Traceln("In NetServerDiskEnum")
	resumeHandle := uint32(0)
	netReq := &NetServerDiskEnumRequest{
		ServerName:   &host,
		Level:        0,
		PrefMaxLen:   0xffffffff,
		ResumeHandle: &resumeHandle,
	}
	netBuf, err := netReq.Marshal()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeRequest(SrvSvcOpNetrServerDiskEnum, netBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	var response NetServerDiskEnumResponse
	err = response.Unmarshal(buffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	if response.WindowsError != ErrorSuccess {
		responseCode, found := SRVSResponseCodeMap[response.WindowsError]
		if !found {
			err = fmt.Errorf("NetServerDiskEnum returned unknown error code: 0x%x\n", response.WindowsError)
			log.Errorln(err)
			return
		}
		log.Debugf("NetServerDiskEnum return error: %v\n", responseCode)
		return nil, responseCode
	}

	for _, di := range response.DiskInfo.Buffer {
		name := diskInfoToString(di.Disk)
		if name == "" {
			// Windows appends a trailing empty DISK_INFO entry; skip it.
			continue
		}
		res = append(res, name)
	}

	return res, nil
}

// diskInfoToString decodes a fixed 3-WCHAR DISK_INFO.Disk field into a Go
// string, stopping at the first NUL.
func diskInfoToString(d [3]uint16) string {
	n := 0
	for n < len(d) && d[n] != 0 {
		n++
	}
	return string(utf16.Decode(d[:n]))
}

// stringToDiskInfo encodes a drive name into a fixed 3-WCHAR DISK_INFO.Disk
// field, truncating anything past 3 UTF-16 code units. Used for symmetry/tests.
func stringToDiskInfo(s string) (d [3]uint16) {
	u := utf16.Encode([]rune(s))
	copy(d[:], u)
	return
}
