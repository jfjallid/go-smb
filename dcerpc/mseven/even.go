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

// Package mseven implements a minimal client for the MS-EVEN (EventLog
// Remoting Protocol) supporting ElfrOpenBELW and ElfrCloseEL.
package mseven

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
	"github.com/jfjallid/mstypes"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/mseven").SetDisplayName("mseven")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidEven                = "82273FDC-E32A-18C3-3F78-827929DC23EA"
	MSRPCEvenPipe                = "eventlog"
	MSRPCEvenMajorVersion uint16 = 0
	MSRPCEvenMinorVersion uint16 = 0
)

// Operation codes
const (
	OpElfrCloseEL  uint16 = 2
	OpElfrOpenBELW uint16 = 9
)

// NTSTATUS error codes
const (
	StatusSuccess          uint32 = 0x00000000
	StatusAccessDenied     uint32 = 0x00000005
	StatusInvalidParameter uint32 = 0x00000057
	StatusInvalidHandle    uint32 = 0x00000006
)

var ResponseCodeMap = map[uint32]error{
	StatusAccessDenied:     fmt.Errorf("ERROR_ACCESS_DENIED"),
	StatusInvalidParameter: fmt.Errorf("ERROR_INVALID_PARAMETER"),
	StatusInvalidHandle:    fmt.Errorf("ERROR_INVALID_HANDLE"),
}

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

// ElfrOpenBELW opens a handle to a backup event log file on the server.
// backupFileName is the path to the backup event log file on the remote system.
func (c *RPCCon) ElfrOpenBELW(backupFileName string) (handle [20]byte, err error) {
	log.Traceln("In ElfrOpenBELW")

	nameLen := uint16(len(backupFileName) * 2)
	req := elfrOpenBELWReq{
		UNCServerName: nil,
		BackupFileName: mstypes.RPCUnicodeString{
			Length:        nameLen,
			MaximumLength: nameLen,
			Value:         backupFileName,
		},
		MajorVersion: 1,
		MinorVersion: 1,
	}

	buf, err := req.Marshal()
	if err != nil {
		return handle, err
	}

	result, err := c.MakeRequest(OpElfrOpenBELW, buf)
	if err != nil {
		return handle, err
	}

	var resp elfrOpenBELWRes
	if err = resp.Unmarshal(result); err != nil {
		return handle, err
	}

	if err = checkReturnCode("ElfrOpenBELW", resp.ReturnCode); err != nil {
		return handle, err
	}

	handle = resp.LogHandle
	return
}

// ElfrCloseEL closes an event log handle obtained from ElfrOpenBELW.
func (c *RPCCon) ElfrCloseEL(handle *[20]byte) error {
	log.Traceln("In ElfrCloseEL")

	req := elfrCloseELReq{
		LogHandle: *handle,
	}

	buf, err := req.Marshal()
	if err != nil {
		return err
	}

	result, err := c.MakeRequest(OpElfrCloseEL, buf)
	if err != nil {
		return err
	}

	var resp elfrCloseELRes
	if err = resp.Unmarshal(result); err != nil {
		return err
	}

	if err = checkReturnCode("ElfrCloseEL", resp.ReturnCode); err != nil {
		return err
	}

	*handle = resp.LogHandle
	return nil
}

// checkReturnCode maps a non-success RPC return code to a *dcerpc.StatusError
// carrying the op, the raw code and the mapped sentinel from ResponseCodeMap
// (nil when unmapped). Codes in okCodes are treated as success.
func checkReturnCode(op string, code uint32, okCodes ...uint32) error {
	if code == StatusSuccess {
		return nil
	}
	for _, ok := range okCodes {
		if code == ok {
			return nil
		}
	}
	return &dcerpc.StatusError{Op: op, Code: code, Err: ResponseCodeMap[code]}
}
