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
// The marshal/unmarshal of requests and responses according to the NDR syntax
// has been implemented on a per RPC request basis and not in any complete way.
// As such, for each new functionality, a manual marshal and unmarshal method
// has to be written for the relevant messages. This makes it a bit easier to
// define the message structs but more of the heavy lifting has to be performed
// by the marshal/unmarshal functions.

package mssrvs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/smb/dcerpc/mssrvs")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidSrvSvc                = "4B324FC8-1670-01D3-1278-5A47BF6EE188"
	MSRPCSrvSvcPipe                = "srvsvc"
	MSRPCSrvSvcMajorVersion uint16 = 3
	MSRPCSrvSvcMinorVersion uint16 = 0
)

// MSRPC Server Service (srvsvc) Operations
const (
	SrvSvcOpNetrSessionEnum  uint16 = 12
	SrvSvcOpNetShareEnumAll  uint16 = 15
	SrvSvcOpNetServerGetInfo uint16 = 21
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
	if (level > 2) && level != 10 && level != 502 {
		// Valid levels are 0, 1, 2, 10, 502
		log.Errorln("Invalid level for NetSessionEnum request. Falling back to level 10")
		level = 10
	}
	nr := NetSessionEnumRequest{
		Info: SessionEnum{Level: uint32(level)},
	}
	if clientName != "" {
		nr.ClientName = clientName
	}
	if userName != "" {
		nr.UserName = userName
	}
	nr.PreferredMaxLength = 0xffffffff

	switch level {
	case 0:
		nr.Info.SessionInfo = SessionInfoContainer0{}
	case 10:
		nr.Info.SessionInfo = SessionInfoContainer10{}
	case 502:
		nr.Info.SessionInfo = SessionInfoContainer502{}
	default:
		log.Errorln("Not yet implemented level %d\n", level)
		return nil
	}

	return &nr
}

/*
Send a NetSessionEnum request to the server. Level can be 0, 1, 2, 10 or 502
But so far only level 0, 10 and 502 are implemented
*/
func (sb *RPCCon) NetSessionEnum(clientName, username string, level int) (res *SessionEnum, err error) {
	log.Debugln("In NetServerGetInfo")
	if level < 0 {
		return nil, fmt.Errorf("Only levels 0, 1, 2, 10 and 502 are valid")
	}
	netReq := NewNetSessionEnumRequest(clientName, username, uint32(level))
	netBuf, err := netReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SrvSvcOpNetrSessionEnum, netBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return nil, fmt.Errorf("Server response to NetSessionEnum was too small. Expected at atleast 20 bytes")
	}
	werror := binary.LittleEndian.Uint32(buffer[len(buffer)-4:])
	if werror != 0 {
		responseCode, found := SRVSResponseCodeMap[werror]
		if !found {
			err = fmt.Errorf("NetServerGetInfo returned unknown error code: 0x%x\n", werror)
			log.Errorln(err)
			return
		}
		log.Debugf("NetServerGetInfo return error: %v\n", responseCode)
		return nil, responseCode
	}

	var response NetSessionEnumResponse
	err = response.UnmarshalBinary(buffer)
	if err != nil {
		return
	}
	switch response.Info.Level {
	case 0, 10, 502:
	default:
		return nil, fmt.Errorf("Server returned response with info level %d which is not yet implementet\n", response.Info.Level)
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
		ServerName: serverName,
		Level:      uint32(level),
	}

	return &nr
}

/*
Send a NetServerGetInfo request to the server. Level can be 100, 101, or 102
*/
func (sb *RPCCon) NetServerGetInfo(host string, level int) (res *NetServerInfo, err error) {
	log.Debugln("In NetServerGetInfo")
	netReq := NewNetServerGetInfoRequest(host, level)
	netBuf, err := netReq.MarshalBinary()
	if err != nil {
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SrvSvcOpNetServerGetInfo, netBuf)
	if err != nil {
		return
	}

	if len(buffer) < 12 {
		return nil, fmt.Errorf("Server response to NetServerGetInfo was too small. Expected at atleast 12 bytes")
	}
	werror := binary.LittleEndian.Uint32(buffer[len(buffer)-4:])
	if werror != 0 {
		responseCode, found := SRVSResponseCodeMap[werror]
		if !found {
			err = fmt.Errorf("NetServerGetInfo returned unknown error code: 0x%x\n", werror)
			log.Errorln(err)
			return
		}
		log.Debugf("NetServerGetInfo return error: %v\n", responseCode)
		return nil, responseCode
	}

	var response NetServerGetInfoResponse
	err = response.UnmarshalBinary(buffer)
	if err != nil {
		return
	}
	switch response.Info.Level {
	case 100, 101, 102:
	default:
		return nil, fmt.Errorf("Server returned response with info level %d which is not yet implementet\n", response.Info.Level)
	}
	res = response.Info

	return
}

func (sb *RPCCon) NetShareEnumAll(host string) (res []NetShare, err error) {
	log.Debugln("In NetShareEnumAll")
	netReq := NewNetShareEnumAllRequest(host)
	netBuf, err := netReq.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return
	}

	buffer, err := sb.MakeIoCtlRequest(SrvSvcOpNetShareEnumAll, netBuf)
	if err != nil {
		log.Errorln(err)
		return
	}

	var response NetShareEnumAllResponse
	err = response.UnmarshalBinary(buffer)
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

	res = make([]NetShare, response.TotalEntries)
	var ctr1 *ShareInfoContainer1
	ctr1 = response.InfoStruct.ShareInfo.(*ShareInfoContainer1)

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
	//Add support for requesting other levels than 1?
	nr := NetShareEnumAllRequest{
		ServerName: serverName,
		InfoStruct: &NetShareEnum{
			Level: 1,
			ShareInfo: &ShareInfoContainer1{
				EntriesRead: 0,
			},
		},
		MaxBuffer: 0xffffffff,
	}

	return &nr
}

func (self *NetShareEnumAllRequest) MarshalBinary() (ret []byte, err error) {
	log.Debugln("In MarshalBinary for NetShareEnumAllRequest")

	refId := uint32(1)

	w := bytes.NewBuffer(ret)
	if self.ServerName != "" {
		// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
		_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.ServerName, &refId, true)
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	} else {
		_, err = w.Write([]byte{0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
	}

	// Ptr to a struct (Share Enum Struct)
	// Not sure why there is no Referent ptr here

	// Encode Share Enum Union discriminator (Level switch)
	err = binary.Write(w, le, self.InfoStruct.Level)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the Level in the Share Enum Union
	err = binary.Write(w, le, self.InfoStruct.Level)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Ptr to NetshareCtr
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}
	refId++

	switch self.InfoStruct.Level {
	case 1:
		ptr := self.InfoStruct.ShareInfo.(*ShareInfoContainer1)
		err = binary.Write(w, le, ptr.EntriesRead)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Add support for specifying an argument array? Is that every used?
		if ptr.EntriesRead > 0 {
			return nil, fmt.Errorf("Not yet implemented support for specifying ShareInfo1 array items")
		} else {
			err = binary.Write(w, le, uint32(0)) // Null Ptr
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	default:
		return nil, fmt.Errorf("Not yet implemented support for marshalling a ShareInfoContainer%d\n", self.InfoStruct.Level)
	}

	err = binary.Write(w, le, self.MaxBuffer)
	if err != nil {
		log.Errorln(err)
		return
	}

	// ResumeHandle is a ptr to a DWORD, so need a ReferentId first
	err = binary.Write(w, le, refId)
	if err != nil {
		log.Errorln(err)
		return
	}

	binary.Write(w, le, self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (s *NetShareEnumAllRequest) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetShareEnumAllRequest")
}

func (s *NetShareEnumAllResponse) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshaBinary of NetShareEnumAllResponse")
}

func (self *NetShareEnumAllResponse) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for NetShareEnumAllResponse")
	r := bytes.NewReader(buf)
	self.InfoStruct = &NetShareEnum{}

	// Skip the Share Enum Union discriminator (Level switch)
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Decode the Level in the Share Enum Union
	err = binary.Read(r, le, &self.InfoStruct.Level)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip Ptr to NetshareCtr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}

	switch self.InfoStruct.Level {
	case 1:
		ptr := &ShareInfoContainer1{}
		err = binary.Read(r, le, &ptr.EntriesRead)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Ptr to ShareInfo1 struct so skip referrent ID Ptr
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		if ptr.EntriesRead > 0 {
			// Skip Max count in front of the array
			_, err = r.Seek(4, io.SeekCurrent)
			if err != nil {
				log.Errorln(err)
				return
			}
			ptr.Buffer = make([]ShareInfo1, ptr.EntriesRead)
			for i := 0; i < int(ptr.EntriesRead); i++ {
				// Skip ReferentID ptr for Name
				_, err = r.Seek(4, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
				// Decode the share Type
				err = binary.Read(r, le, &ptr.Buffer[i].Type)
				if err != nil {
					log.Errorln(err)
					return
				}
				// Skip ReferentID ptr for Comment
				_, err = r.Seek(4, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
			for i := 0; i < int(ptr.EntriesRead); i++ {
				// Decode the Name
				ptr.Buffer[i].Name, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}
				// Decode the Comment
				ptr.Buffer[i].Comment, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
		}

		self.InfoStruct.ShareInfo = ptr
	default:
		return fmt.Errorf("NOT IMPLEMENTED NetShareEnumAllResponse with ShareInfo level %d\n", self.InfoStruct.Level)
	}

	err = binary.Read(r, le, &self.TotalEntries)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip ReferentId Ptr for ResumeHandle
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Read(r, le, &self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	err = binary.Read(r, le, &self.WindowsError)
	if err != nil {
		log.Errorln(err)
		return
	}

	return nil
}
