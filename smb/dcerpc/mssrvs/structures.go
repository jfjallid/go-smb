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
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/smb/dcerpc"
	"io"
)

type RPCCon struct {
	*dcerpc.ServiceBind
}

// Returned to clients calling the NetShareEnumAll request
type NetShare struct {
	Name    string
	Comment string
	Type    string
	TypeId  uint32
	Hidden  bool
}

type ShareInfo1 struct {
	Name    string
	Type    uint32
	Comment string
}

/*
	typedef struct _SHARE_INFO_1_CONTAINER {
	  DWORD EntriesRead;
	  [size_is(EntriesRead)] LPSHARE_INFO_1 Buffer;
	} SHARE_INFO_1_CONTAINER;
*/
type ShareInfoContainer1 struct {
	EntriesRead uint32
	Buffer      []ShareInfo1
}

/*
	typedef struct _SHARE_ENUM_STRUCT {
	  DWORD Level;
	  [switch_is(Level)] SHARE_ENUM_UNION ShareInfo;
	} SHARE_ENUM_STRUCT,

*PSHARE_ENUM_STRUCT,
*LPSHARE_ENUM_STRUCT;
*/
type NetShareEnum struct {
	Level     uint32
	ShareInfo any
}

type NetShareEnumAllRequest struct {
	ServerName   string
	InfoStruct   *NetShareEnum
	MaxBuffer    uint32
	ResumeHandle uint32
}

type NetShareEnumAllResponse struct {
	InfoStruct   *NetShareEnum
	TotalEntries uint32
	ResumeHandle uint32
	WindowsError uint32
}

// Could this be done in a better way? Perhaps with an interface?
type NetSessionInfo0 struct {
	Cname string
}

type NetSessionInfo1 struct {
	NetSessionInfo0
	Username  string
	NumOpens  uint32
	Time      uint32
	IdleTime  uint32
	UserFlags uint32 // Must be a combination of one or more of the values that are defined in 2.2.2.3
}

type NetSessionInfo2 struct {
	NetSessionInfo1
	ClType string
}

type NetSessionInfo10 struct {
	NetSessionInfo0
	Username string
	Time     uint32
	IdleTime uint32
}

type NetSessionInfo502 struct {
	NetSessionInfo2
	Transport string
}

// Could this be done in a better way? Perhaps with an interface?
type SessionInfoContainer0 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo0
}

type SessionInfoContainer1 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo1
}

type SessionInfoContainer2 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo2
}

type SessionInfoContainer10 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo10
}

type SessionInfoContainer502 struct {
	EntriesRead uint32
	Buffer      []NetSessionInfo502
}

type SessionEnum struct {
	Level       uint32
	SessionInfo interface{}
}

// NET_API_STATUS
// NetrSessionEnum (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in,string,unique] WCHAR * ClientName,
// [in,string,unique] WCHAR * UserName,
// [in,out] PSESSION_ENUM_STRUCT InfoStruct,
// [in] DWORD PreferedMaximumLength,
// [out] DWORD * TotalEntries,
// [in,out,unique] DWORD * ResumeHandle
// );
type NetSessionEnumRequest struct {
	ServerName         string
	ClientName         string
	UserName           string
	Info               SessionEnum
	PreferredMaxLength uint32
	ResumeHandle       uint32 // Ptr to dword
}

type NetSessionEnumResponse struct {
	Info         SessionEnum
	TotalEntries uint32 // Ptr to dword
	ResumeHandle uint32 // Ptr to dword
	WindowsError uint32
}

type NetServerInfo100 struct {
	PlatformId uint32
	Name       string
}

type NetServerInfo101 struct {
	NetServerInfo100
	VersionMajor uint32
	VersionMinor uint32
	SvType       uint32
	Comment      string
}

type NetServerInfo102 struct {
	NetServerInfo101
	Users    uint32
	Disc     int32
	Hidden   uint32
	Announce uint32
	Anndelta uint32
	Licences uint32
	Userpath string
}

type NetServerInfo struct {
	Level   uint32
	Pointer interface{}
}

// NET_API_STATUS
// NetrServerGetInfo (
// [in,string,unique] SRVSVC_HANDLE ServerName,
// [in] DWORD Level,
// [out, switch_is(Level)] LPSERVER_INFO InfoStruct
// );
type NetServerGetInfoRequest struct {
	ServerName string
	Level      uint32
}

type NetServerGetInfoResponse struct {
	Info         *NetServerInfo
	WindowsError uint32
}

func (self *NetServerGetInfoRequest) MarshalBinary() ([]byte, error) {
	log.Debugln("In MarshalBinary for NetServerGetInfoRequest")

	var ret []byte
	var err error
	refId := uint32(1)
	w := bytes.NewBuffer(ret)
	if self.ServerName != "" {
		// Pointer to a conformant and varying string, so include ReferentId Ptr and MaxCount
		/*
		   In each instance where a string should be encoded, check the IDL to see if it is a ptr so a referent ID is needed and if MaxLen should be encoded as well.
		*/
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
	err = binary.Write(w, le, self.Level)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	return w.Bytes(), nil
}

func (self *NetServerGetInfoRequest) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetServerGetInfoRequest")
}

func (self *NetServerGetInfoResponse) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshaBinary of NetServerGetInfoResponse")
}

func (self *NetServerGetInfoResponse) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for NetServerGetInfoResponse")

	r := bytes.NewReader(buf)
	self.Info = &NetServerInfo{}
	err = binary.Read(r, le, &self.Info.Level)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip over a ReferentId Ptr of 4 bytes
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch self.Info.Level {
	case 100:
		if len(buf[8:]) < 8 {
			return fmt.Errorf("Buffer is too short to contain a NetServerInfo100 struct\n")
		}
		si := NetServerInfo100{}
		err = binary.Read(r, le, &si.PlatformId)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Skip over a ReferentId Ptr for Name
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		si.Name, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
		self.Info.Pointer = &si
	case 101:
		if len(buf[8:]) < 24 {
			return fmt.Errorf("Buffer is too short to contain a NetServerInfo102 struct\n")
		}
		si := NetServerInfo101{}
		err = binary.Read(r, le, &si.PlatformId)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Skip over a ReferentId Ptr for Name
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.VersionMajor)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Read(r, le, &si.VersionMinor)
		if err != nil {
			log.Errorln(err)
			return
		}

		err = binary.Read(r, le, &si.SvType)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Skip over a ReferentId Ptr for Comment
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Read and decode the Name
		si.Name, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Read and decode the Comment
		si.Comment, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}

		self.Info.Pointer = &si
	case 102:
		/*
			Order of serialization:
			platformId
			ReferentId Ptr from name struct
			versionMajor
			versionMinor
			svType
			ReferentId Ptr from comment struct
			Users
			disc
			hidden
			announce
			anndelta
			licenses
			ReferentId Ptr from UserPath struct

			Then finally comes the content of the three UnicodeStr structs
		*/
		if len(buf[8:]) < 52 {
			return fmt.Errorf("Buffer is too short to contain a NetServerInfo102 struct\n")
		}
		si := NetServerInfo102{}
		err = binary.Read(r, le, &si.PlatformId)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Skip over a ReferentId Ptr for Name
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.VersionMajor)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.VersionMinor)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.SvType)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Skip over a ReferentId Ptr for Comment
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Users)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Disc)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Hidden)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Announce)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Anndelta)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Read(r, le, &si.Licences)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Skip over a ReferentId Ptr for UserPath
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Read and decode the Name
		si.Name, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Read and decode the Comment
		si.Comment, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}
		// Read and decode the UserPath
		si.Userpath, err = msdtyp.ReadConformantVaryingString(r, true)
		if err != nil {
			log.Errorln(err)
			return
		}

		self.Info.Pointer = &si
	}

	err = binary.Read(r, le, &self.WindowsError)
	if err != nil {
		log.Errorln(err)
		return
	}
	return nil
}

func (self *NetSessionEnumRequest) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for NetSessionEnumRequest")

	var ret []byte
	w := bytes.NewBuffer(ret)
	refid := uint32(1)
	if self.ServerName != "" {
		_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.ServerName, &refid, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		_, err = w.Write([]byte{0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	if self.ClientName != "" {
		_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.ClientName, &refid, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		_, err = w.Write([]byte{0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if self.UserName != "" {
		_, err = msdtyp.WriteConformantVaryingStringPtr(w, self.UserName, &refid, true)
		if err != nil {
			log.Errorln(err)
			return
		}
	} else {
		_, err = w.Write([]byte{0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	// Encode the level (union discriminator)
	err = binary.Write(w, le, self.Info.Level)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Encode the union of ptrs
	switch self.Info.Level {
	case 0:
		err = binary.Write(w, le, self.Info.Level) // Encode the level
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, refid) // ReferentID
		if err != nil {
			log.Errorln(err)
			return
		}
		refid++

		ptr := self.Info.SessionInfo.(SessionInfoContainer0)
		err = binary.Write(w, le, ptr.EntriesRead) // How many items in array (sessions)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, []byte{0x0, 0x0, 0x0, 0x0}) // Null ptr
		if err != nil {
			log.Errorln(err)
			return
		}
		//TODO Add support for specifying an argument array?
		if ptr.EntriesRead > 0 {
			return nil, fmt.Errorf("Not yet implemented support for specifying NetSession0 array items")
		}

	case 10:
		err = binary.Write(w, le, self.Info.Level) // Encode the level
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, refid) // ReferentID
		if err != nil {
			log.Errorln(err)
			return
		}
		refid++

		ptr := self.Info.SessionInfo.(SessionInfoContainer10)
		err = binary.Write(w, le, ptr.EntriesRead) // How many items in array (sessions)
		if err != nil {
			log.Errorln(err)
			return
		}

		if len(ptr.Buffer) > 0 {
			// This block is probably unnecessary as the request will likely never contain any elements
			// Also it is untested so not sure it works
			err = binary.Write(w, le, refid) // ReferentID
			if err != nil {
				log.Errorln(err)
				return
			}
			refid++
			err = binary.Write(w, le, ptr.EntriesRead) // Max Count
			if err != nil {
				log.Errorln(err)
				return
			}
			// Encode the ReferentID ptrs for each element in the array
			for i := range ptr.Buffer {
				if ptr.Buffer[i].Cname != "" {
					err = binary.Write(w, le, refid)
					refid++
				} else {
					// Not sure it is correct to encode a null pointer
					err = binary.Write(w, le, []byte{0, 0, 0, 0})
				}
				if err != nil {
					log.Errorln(err)
					return
				}
				if ptr.Buffer[i].Username != "" {
					err = binary.Write(w, le, refid)
					refid++
				} else {
					// Not sure it is correct to encode a null pointer
					err = binary.Write(w, le, []byte{0, 0, 0, 0})
				}
				if err != nil {
					log.Errorln(err)
					return
				}
				// Encode the last members of the SessionInfo10 struct
				err = binary.Write(w, le, ptr.Buffer[i].Time)
				if err != nil {
					log.Errorln(err)
					return
				}
				err = binary.Write(w, le, ptr.Buffer[i].IdleTime)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
			// Now encode the actual Client and UserNames if they are present
			for i := range ptr.Buffer {
				if ptr.Buffer[i].Cname != "" {
					_, err = msdtyp.WriteConformantVaryingString(w, ptr.Buffer[i].Cname, true)
					if err != nil {
						log.Errorln(err)
						return
					}
				}
				if ptr.Buffer[i].Username != "" {
					_, err = msdtyp.WriteConformantVaryingString(w, ptr.Buffer[i].Username, true)
					if err != nil {
						log.Errorln(err)
						return
					}
				}
			}
		} else {
			err = binary.Write(w, le, []byte{0x0, 0x0, 0x0, 0x0}) // Null ptr
			if err != nil {
				log.Errorln(err)
				return
			}
		}
	case 502:
		refid := uint32(1)
		err = binary.Write(w, le, self.Info.Level) // Encode the level
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, refid) // ReferentID
		if err != nil {
			log.Errorln(err)
			return
		}
		refid++

		ptr := self.Info.SessionInfo.(SessionInfoContainer502)
		err = binary.Write(w, le, ptr.EntriesRead) // How many items in array (sessions)
		if err != nil {
			log.Errorln(err)
			return
		}
		err = binary.Write(w, le, []byte{0x0, 0x0, 0x0, 0x0}) // Null ptr
		if err != nil {
			log.Errorln(err)
			return
		}
		//TODO Add support for specifying an argument array?
		if ptr.EntriesRead > 0 {
			return nil, fmt.Errorf("Not yet implemented support for specifying NetSession502 array items")
		}
	default:
		return nil, fmt.Errorf("Not implemented marshal of level %d\n", self.Info.Level)
	}

	err = binary.Write(w, le, self.PreferredMaxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	// ResumeHandle is a ptr to a DWORD, so need a ReferentId first
	err = binary.Write(w, le, refid)
	if err != nil {
		log.Errorln(err)
		return
	}
	err = binary.Write(w, le, self.ResumeHandle)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}

func (self *NetSessionEnumRequest) UnmarshalBinary(buf []byte) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary of NetSessionEnumRequest")
}

func (self *NetSessionEnumResponse) MarshalBinary() ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshaBinary of NetSessionEnumResponse")
}

func (self *NetSessionEnumResponse) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for NetSessionEnumResponse")

	r := bytes.NewReader(buf)
	// Skip the SessionEnum Union Discriminator (Level)
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Decode the level of the SessionEnum Union
	err = binary.Read(r, le, &self.Info.Level)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Skip referrent ID for SessionEnum Union ptr to the Session Info container
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	switch self.Info.Level {
	case 0:
		container := SessionInfoContainer0{}
		self.Info.SessionInfo = &container
		err = binary.Read(r, le, container.EntriesRead)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Ptr to SessionInfo struct so skip referrent ID Ptr
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		if container.EntriesRead > 0 {
			// Skip Max count of strings in front of the array
			_, err = r.Seek(4, io.SeekCurrent)
			if err != nil {
				log.Errorln(err)
				return
			}
			container.Buffer = make([]NetSessionInfo0, container.EntriesRead)
			for i := 0; i < int(container.EntriesRead); i++ {
				// Skip ReferentID ptrs for Cname
				_, err = r.Seek(4, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
			for i := 0; i < int(container.EntriesRead); i++ {
				// Decode the Cname
				container.Buffer[i].Cname, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
		}
	case 10:
		container := SessionInfoContainer10{}
		self.Info.SessionInfo = &container
		err = binary.Read(r, le, &container.EntriesRead)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Skip referrent ID
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		if container.EntriesRead > 0 {
			// Skip Max count in front of the array
			_, err = r.Seek(4, io.SeekCurrent)
			if err != nil {
				log.Errorln(err)
				return
			}
			container.Buffer = make([]NetSessionInfo10, container.EntriesRead)
			for i := 0; i < int(container.EntriesRead); i++ {
				// Skip ReferentID ptrs for Cname and Username
				_, err = r.Seek(8, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
				err = binary.Read(r, le, &container.Buffer[i].Time)
				if err != nil {
					log.Errorln(err)
					return
				}
				err = binary.Read(r, le, &container.Buffer[i].IdleTime)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
			for i := 0; i < int(container.EntriesRead); i++ {
				// Decode the Cname
				container.Buffer[i].Cname, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}

				// Decode the Username
				container.Buffer[i].Username, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
		}
	case 502:
		container := SessionInfoContainer502{}
		self.Info.SessionInfo = &container
		err = binary.Read(r, le, container.EntriesRead)
		if err != nil {
			log.Errorln(err)
			return
		}

		// Skip referrent ID
		_, err = r.Seek(4, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
		if container.EntriesRead > 0 {
			// Skip Max count in front of the array
			_, err = r.Seek(4, io.SeekCurrent)
			if err != nil {
				log.Errorln(err)
				return
			}
			container.Buffer = make([]NetSessionInfo502, container.EntriesRead)
			for i := 0; i < int(container.EntriesRead); i++ {
				// Skip ReferentID ptrs for Cname and Username
				_, err = r.Seek(8, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
				err = binary.Read(r, le, container.Buffer[i].NumOpens)
				if err != nil {
					log.Errorln(err)
					return
				}

				err = binary.Read(r, le, container.Buffer[i].Time)
				if err != nil {
					log.Errorln(err)
					return
				}

				err = binary.Read(r, le, container.Buffer[i].IdleTime)
				if err != nil {
					log.Errorln(err)
					return
				}

				err = binary.Read(r, le, container.Buffer[i].UserFlags)
				if err != nil {
					log.Errorln(err)
					return
				}

				// Skip ReferentID ptrs for ClientType and Transport
				_, err = r.Seek(8, io.SeekCurrent)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
			for i := 0; i < int(container.EntriesRead); i++ {
				// Decode the Cname
				container.Buffer[i].Cname, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}

				// Decode the Username
				container.Buffer[i].Username, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}

				// Decode the ClientType
				container.Buffer[i].ClType, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}

				// Decode the Transport
				container.Buffer[i].Transport, err = msdtyp.ReadConformantVaryingString(r, true)
				if err != nil {
					log.Errorln(err)
					return
				}
			}
		}

	default:
		return fmt.Errorf("Not implemented UnmarshalBinary for level %d\n", self.Info.Level)
	}

	err = binary.Read(r, le, &self.TotalEntries)
	if err != nil {
		log.Errorln(err)
		return
	}

	// Skip ReferentID ptr for ResumeHandle
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
	return nil
}
