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

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/dcerpc/mssrvs")

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
	SrvSvcOpNetServerGetInfo     uint16 = 21
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

func (sb *RPCCon) NetShareEnumAll(host string) (res []NetShare, err error) {
	log.Traceln("In NetShareEnumAll")
	netReq := NewNetShareEnumAllRequest(host)
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

	ctr1 := response.InfoStruct.Level1
	if ctr1 == nil {
		return nil, nil
	}
	res = make([]NetShare, response.TotalEntries)

	for i := 0; i < int(response.TotalEntries); i++ {
		res[i].Name = ctr1.Buffer[i].Name
		res[i].Comment = ctr1.Buffer[i].Comment

		// Parse the TYPE
		t := ""
		if (ctr1.Buffer[i].Type & StypeClusterDFS) == StypeClusterDFS {
			t += ShareTypeMap[StypeClusterDFS]
			res[i].TypeId = StypeClusterDFS
		} else if (ctr1.Buffer[i].Type & StypeClusterSOFS) == StypeClusterSOFS {
			t += ShareTypeMap[StypeClusterSOFS]
			res[i].TypeId = StypeClusterSOFS
		} else if (ctr1.Buffer[i].Type & StypeClusterFS) == StypeClusterFS {
			t += ShareTypeMap[StypeClusterFS]
			res[i].TypeId = StypeClusterFS
		} else if (ctr1.Buffer[i].Type & StypeIPC) == StypeIPC {
			t += ShareTypeMap[StypeIPC]
			res[i].TypeId = StypeIPC
		} else if (ctr1.Buffer[i].Type & StypeDevice) == StypeDevice {
			t += ShareTypeMap[StypeDevice]
			res[i].TypeId = StypeDevice
		} else if (ctr1.Buffer[i].Type & StypePrintq) == StypePrintq {
			t += ShareTypeMap[StypePrintq]
			res[i].TypeId = StypePrintq
		} else {
			t += ShareTypeMap[StypeDisktree]
			res[i].TypeId = StypeDisktree
		}

		if (ctr1.Buffer[i].Type & StypeSpecial) == StypeSpecial {
			t += "_" + ShareTypeMap[StypeSpecial]
			res[i].Hidden = true
		} else if (ctr1.Buffer[i].Type & StypeTemporary) == StypeTemporary {
			t += "_" + ShareTypeMap[StypeTemporary]
		}
		res[i].Type = t
	}

	return res, nil
}

func NewNetShareEnumAllRequest(serverName string) *NetShareEnumAllRequest {
	resumeHandle := uint32(0)
	nr := NetShareEnumAllRequest{
		ServerName: &serverName,
		InfoStruct: ShareEnumStruct{
			Level: 1,
			Level1: &ShareInfoContainer1{
				EntriesRead: 0,
			},
		},
		MaxBuffer:    0xffffffff,
		ResumeHandle: &resumeHandle,
	}
	return &nr
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
