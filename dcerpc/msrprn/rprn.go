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

// Package msrprn implements a minimal client for the MS-RPRN (Print System
// Remote Protocol) supporting RpcOpenPrinterEx, RpcClosePrinter,
// RpcRemoteFindFirstPrinterChangeNotification, and
// RpcRemoteFindFirstPrinterChangeNotificationEx.
package msrprn

import (
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/golog"
)

var (
	log                  = golog.Get("github.com/jfjallid/go-smb/dcerpc/msrprn").SetDisplayName("msrprn")
	le  binary.ByteOrder = binary.LittleEndian
)

const (
	MSRPCUuidRprn                = "12345678-1234-ABCD-EF00-0123456789AB"
	MSRPCRprnPipe                = "spoolss"
	MSRPCRprnMajorVersion uint16 = 1
	MSRPCRprnMinorVersion uint16 = 0
)

// Operation codes
const (
	OpRpcClosePrinter                               uint16 = 29
	OpRpcRemoteFindFirstPrinterChangeNotification   uint16 = 62
	OpRpcRemoteFindFirstPrinterChangeNotificationEx uint16 = 65
	OpRpcOpenPrinterEx                              uint16 = 69
)

// Access rights
const (
	ServerAccessAdminister  uint32 = 0x00000001
	ServerAccessEnumerate   uint32 = 0x00000002
	PrinterAccessAdminister uint32 = 0x00000004
	PrinterAccessUse        uint32 = 0x00000008
)

// Processor architectures
const (
	ProcessorArchitectureIntel uint16 = 0
	ProcessorArchitectureAMD64 uint16 = 9
)

// Win32 error codes
const (
	ErrorSuccess              uint32 = 0x00000000
	ErrorAccessDenied         uint32 = 0x00000005
	ErrorInvalidHandle        uint32 = 0x00000006
	ErrorInvalidParameter     uint32 = 0x00000057
	ErrorInvalidPrinterName   uint32 = 0x00000709
	ErrorUnknownPrinterDriver uint32 = 0x0000070E
	RpcSServerUnavailable     uint32 = 0x000006BA
)

var ResponseCodeMap = map[uint32]error{
	ErrorAccessDenied:         fmt.Errorf("ERROR_ACCESS_DENIED"),
	ErrorInvalidHandle:        fmt.Errorf("ERROR_INVALID_HANDLE"),
	ErrorInvalidParameter:     fmt.Errorf("ERROR_INVALID_PARAMETER"),
	ErrorInvalidPrinterName:   fmt.Errorf("ERROR_INVALID_PRINTER_NAME"),
	ErrorUnknownPrinterDriver: fmt.Errorf("ERROR_UNKNOWN_PRINTER_DRIVER"),
	RpcSServerUnavailable:     fmt.Errorf("RPC_S_SERVER_UNAVAILABLE"),
}

type RPCCon struct {
	*dcerpc.ServiceBind
}

func NewRPCCon(sb *dcerpc.ServiceBind) *RPCCon {
	return &RPCCon{ServiceBind: sb}
}

// RpcOpenPrinterEx opens a handle to the specified printer or print server.
// printerName should be in UNC form, e.g., "\\\\server" or "\\\\server\\printer".
func (c *RPCCon) RpcOpenPrinterEx(printerName string) (handle [20]byte, err error) {
	log.Traceln("In RpcOpenPrinterEx")

	pName := printerName
	machineName := "CLI"
	userName := "CLI"

	req := rpcOpenPrinterExReqNDR{
		PrinterName: &pName,
		// PDataType: nil (NULL)
		DevModeContainer: devModeContainerNDR{
			CbBuf: 0,
			// PDevMode: nil (NULL)
		},
		AccessRequired: ServerAccessAdminister,
		ClientInfo: splClientContainerNDR{
			Level: 1,
			Info1: splClientInfo1NDR{
				DwSize:                 28,
				PMachineName:           machineName,
				PUserName:              userName,
				DwBuildNum:             0,
				DwMajorVersion:         10,
				DwMinorVersion:         0,
				WProcessorArchitecture: ProcessorArchitectureAMD64,
			},
		},
	}

	buf, err := req.Marshal()
	if err != nil {
		return handle, err
	}

	result, err := c.MakeRequest(OpRpcOpenPrinterEx, buf)
	if err != nil {
		return handle, err
	}

	var resp rpcOpenPrinterExResNDR
	if err = resp.Unmarshal(result); err != nil {
		return handle, err
	}

	if err = checkReturnCode("RpcOpenPrinterEx", resp.ReturnCode); err != nil {
		return handle, err
	}

	handle = resp.Handle
	return
}

// RpcClosePrinter closes a printer handle obtained from RpcOpenPrinterEx.
func (c *RPCCon) RpcClosePrinter(handle *[20]byte) error {
	log.Traceln("In RpcClosePrinter")

	req := rpcClosePrinterReqNDR{
		Handle: *handle,
	}

	buf, err := req.Marshal()
	if err != nil {
		return err
	}

	result, err := c.MakeRequest(OpRpcClosePrinter, buf)
	if err != nil {
		return err
	}

	var resp rpcClosePrinterResNDR
	if err = resp.Unmarshal(result); err != nil {
		return err
	}

	if err = checkReturnCode("RpcClosePrinter", resp.ReturnCode); err != nil {
		return err
	}

	*handle = resp.Handle
	return nil
}

// RpcRemoteFindFirstPrinterChangeNotification creates a remote change
// notification object (opnum 62). localMachine should be a UNC path like
// "\\\\10.0.0.1".
func (c *RPCCon) RpcRemoteFindFirstPrinterChangeNotification(
	handle [20]byte, fdwFlags, fdwOptions uint32, localMachine string,
	dwPrinterLocal uint32,
) error {
	log.Traceln("In RpcRemoteFindFirstPrinterChangeNotification")

	req := rpcRFFPCNReqNDR{
		Handle:          handle,
		FdwFlags:        fdwFlags,
		FdwOptions:      fdwOptions,
		PszLocalMachine: &localMachine,
		DwPrinterLocal:  dwPrinterLocal,
		CbBuffer:        0,
		// PBuffer: nil (NULL)
	}

	buf, err := req.Marshal()
	if err != nil {
		return err
	}

	result, err := c.MakeRequest(OpRpcRemoteFindFirstPrinterChangeNotification, buf)
	if err != nil {
		return err
	}

	var resp rpcRFFPCNResNDR
	if err = resp.Unmarshal(result); err != nil {
		return err
	}

	if err = checkReturnCode("RpcRemoteFindFirstPrinterChangeNotification", resp.ReturnCode); err != nil {
		return err
	}

	return nil
}

// RpcRemoteFindFirstPrinterChangeNotificationEx creates a remote change
// notification object with extended options (opnum 65). localMachine should be
// a UNC path like "\\\\10.0.0.1". pOptions can be nil.
func (c *RPCCon) RpcRemoteFindFirstPrinterChangeNotificationEx(
	handle [20]byte, fdwFlags, fdwOptions uint32, localMachine string,
	dwPrinterLocal uint32, pOptions *RpcV2NotifyOptions,
) error {
	log.Traceln("In RpcRemoteFindFirstPrinterChangeNotificationEx")

	var opts *rpcV2NotifyOptionsNDR
	if pOptions != nil {
		opts = &rpcV2NotifyOptionsNDR{
			Version:  pOptions.Version,
			Reserved: pOptions.Reserved,
			Count:    pOptions.Count,
			PTypes:   0, // NULL
		}
	}

	req := rpcRFFPCNExReqNDR{
		Handle:          handle,
		FdwFlags:        fdwFlags,
		FdwOptions:      fdwOptions,
		PszLocalMachine: &localMachine,
		DwPrinterLocal:  dwPrinterLocal,
		POptions:        opts,
	}

	buf, err := req.Marshal()
	if err != nil {
		return err
	}

	result, err := c.MakeRequest(OpRpcRemoteFindFirstPrinterChangeNotificationEx, buf)
	if err != nil {
		return err
	}

	var resp rpcRFFPCNExResNDR
	if err = resp.Unmarshal(result); err != nil {
		return err
	}

	if err = checkReturnCode("RpcRemoteFindFirstPrinterChangeNotificationEx", resp.ReturnCode); err != nil {
		return err
	}

	return nil
}

// checkReturnCode maps a non-success RPC return code to a *dcerpc.StatusError
// carrying the op, the raw code and the mapped sentinel from ResponseCodeMap
// (nil when unmapped). Codes in okCodes are treated as success.
func checkReturnCode(op string, code uint32, okCodes ...uint32) error {
	if code == ErrorSuccess {
		return nil
	}
	for _, ok := range okCodes {
		if code == ok {
			return nil
		}
	}
	return &dcerpc.StatusError{Op: op, Code: code, Err: ResponseCodeMap[code]}
}
