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
)

var le binary.ByteOrder = binary.LittleEndian

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

// StringBinding holds the host address and TCP port returned by the Endpoint Mapper.
type StringBinding struct {
	Host string // IPv4 address string (e.g. "10.0.0.1" or "0.0.0.0" for wildcard)
	Port uint16
}

// String returns the address in "host:port" form, suitable for use with net.Dial.
func (sb StringBinding) String() string {
	return net.JoinHostPort(sb.Host, fmt.Sprintf("%d", sb.Port))
}

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
		return nil, err
	}

	result, err := c.MakeRequest(EpmOpEptMap, buf)
	if err != nil {
		return nil, err
	}

	var resp EptMapResponse
	if err := resp.UnmarshalBinary(result); err != nil {
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

// GetTCPPortForInterface queries the EPM for the TCP endpoints of the given
// interface. Each returned StringBinding corresponds to one tower that contains
// a TCP floor. Towers without a TCP floor (e.g. UDP-only) are skipped. The
// Host field is taken directly from the tower's IP floor and may be "0.0.0.0"
// when the service is bound to all interfaces; callers that need a dialable
// address should substitute their own host in that case (as
// GetStringBindingForInterface does).
func (c *RPCCon) GetTCPPortForInterface(interfaceUUID string, majorVersion, minorVersion uint16) ([]StringBinding, error) {
	tower, err := NewRequestTower(interfaceUUID, majorVersion, minorVersion)
	if err != nil {
		return nil, err
	}

	towers, err := c.EptMap(tower, 4)
	if err != nil {
		return nil, err
	}

	if len(towers) == 0 {
		return nil, fmt.Errorf("no towers returned for interface %s", interfaceUUID)
	}

	var bindings []StringBinding
	for _, t := range towers {
		ports, err := t.GetTCPPorts()
		if err != nil {
			return nil, err
		}
		if len(ports) == 0 {
			continue // skip non-TCP towers
		}

		addrs, err := t.GetIPAddresses()
		if err != nil {
			return nil, err
		}

		host := ""
		if len(addrs) > 0 {
			host = addrs[0]
		}
		bindings = append(bindings, StringBinding{Host: host, Port: ports[0]})
	}

	if len(bindings) == 0 {
		return nil, fmt.Errorf("no TCP bindings found in towers for interface %s", interfaceUUID)
	}
	return bindings, nil
}

// GetStringBindingForInterface is a convenience function that connects to the
// EPM on port 135, queries for the TCP endpoints of the given RPC interface,
// and returns all StringBindings found. When a tower reports a wildcard address
// ("0.0.0.0"), the original host parameter is substituted so that every
// returned StringBinding.String() is always directly dialable.
func GetStringBindingForInterface(host, interfaceUUID string, majorVersion, minorVersion uint16, timeout time.Duration) ([]StringBinding, error) {
	addr := net.JoinHostPort(host, "135")
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to EPM at %s: %w", addr, err)
	}

	transport := dcerpc.NewTCPTransport(conn)
	defer transport.Close()

	svcBind, err := dcerpc.Bind(transport, MSRPCUuidEpm, MSRPCEpmMajorVersion, MSRPCEpmMinorVersion, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to EPM: %w", err)
	}

	rpcCon := NewRPCCon(svcBind)
	bindings, err := rpcCon.GetTCPPortForInterface(interfaceUUID, majorVersion, minorVersion)
	if err != nil {
		return nil, err
	}

	for i := range bindings {
		if bindings[i].Host == "" || bindings[i].Host == "0.0.0.0" {
			bindings[i].Host = host
		}
	}

	return bindings, nil
}
