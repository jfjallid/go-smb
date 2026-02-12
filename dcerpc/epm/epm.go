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

package epm

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/epm")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidEpm                = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"
	MSRPCEpmMajorVersion uint16 = 3
	MSRPCEpmMinorVersion uint16 = 0
	EpmOpEptMap          uint16 = 3
)

// Tower floor protocol identifiers
const (
	FloorProtoUUID    byte = 0x0d
	FloorProtoRPCConn byte = 0x0b
	FloorProtoTCP     byte = 0x07
	FloorProtoIP      byte = 0x09
	FloorProtoUDP     byte = 0x08
	FloorProtoNPipe   byte = 0x0f
	FloorProtoNBName  byte = 0x11
)

const ContextHandleSize = 20

// EPT_S_NOT_REGISTERED - no entries found for the requested interface
const EptSNotRegistered uint32 = 0x16C9A0D6

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

// EptMap sends an ept_map request and returns the response towers.
func (c *RPCCon) EptMap(requestTower *Tower, maxTowers uint32) ([]Tower, error) {
	req := &EptMapRequest{
		Tower:     requestTower,
		MaxTowers: maxTowers,
	}

	buf, err := req.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	result, err := c.MakeRequest(EpmOpEptMap, buf)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	var resp EptMapResponse
	if err := resp.UnmarshalBinary(result); err != nil {
		log.Errorln(err)
		return nil, err
	}

	if resp.Status == EptSNotRegistered {
		return nil, fmt.Errorf("EPT_S_NOT_REGISTERED: interface not registered with endpoint mapper")
	}
	if resp.Status != 0 {
		return nil, fmt.Errorf("ept_map returned error status: 0x%08x", resp.Status)
	}

	return resp.Towers, nil
}

// GetTCPPortForInterface queries the EPM for the TCP port of the given interface.
func (c *RPCCon) GetTCPPortForInterface(interfaceUUID string, majorVersion, minorVersion uint16) (uint16, error) {
	tower, err := NewRequestTower(interfaceUUID, majorVersion, minorVersion)
	if err != nil {
		return 0, err
	}

	towers, err := c.EptMap(tower, 4)
	if err != nil {
		return 0, err
	}

	if len(towers) == 0 {
		return 0, fmt.Errorf("no towers returned for interface %s", interfaceUUID)
	}

	port, err := towers[0].GetTCPPort()
	if err != nil {
		return 0, err
	}

	return port, nil
}

// GetStringBindingForInterface is a convenience function that connects to the
// EPM on port 135, queries for the TCP port of the given RPC interface, and
// returns the port number.
func GetStringBindingForInterface(host, interfaceUUID string, majorVersion, minorVersion uint16, timeout time.Duration) (uint16, error) {
	addr := net.JoinHostPort(host, "135")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, fmt.Errorf("failed to connect to EPM at %s: %w", addr, err)
	}

	transport := dcerpc.NewTCPTransport(conn)
	defer transport.Close()

	sb, err := dcerpc.Bind(transport, MSRPCUuidEpm, MSRPCEpmMajorVersion, MSRPCEpmMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return 0, fmt.Errorf("failed to bind to EPM: %w", err)
	}

	rpcCon := NewRPCCon(sb)
	return rpcCon.GetTCPPortForInterface(interfaceUUID, majorVersion, minorVersion)
}
