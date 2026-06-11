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

package msrprn

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/ndr"
)

// devModeContainerNDR represents DEVMODE_CONTAINER (MS-RPRN 2.2.1.3.1).
// For our use case, always empty (cbBuf=0, pDevMode=NULL).
type devModeContainerNDR struct {
	CbBuf    uint32
	PDevMode *devModeDataNDR `ndr:"fullpointer"` // [unique] embedded pointer
}

type devModeDataNDR struct {
	Data []byte `ndr:"conformant"`
}

// splClientContainerNDR represents SPLCLIENT_CONTAINER (MS-RPRN 2.2.1.3.9).
// Non-encapsulated union with Level as discriminant.
type splClientContainerNDR struct {
	Level uint32            `ndr:"unionTag"`
	Info1 splClientInfo1NDR `ndr:"unionField,pointer"`
}

// SwitchFunc implements the ndr.Union interface for SPLCLIENT_CONTAINER.
func (s splClientContainerNDR) SwitchFunc(t interface{}) string {
	level, ok := t.(uint32)
	if !ok {
		return ""
	}
	switch level {
	case 1:
		return "Info1"
	}
	return ""
}

// splClientInfo1NDR represents SPLCLIENT_INFO_1 (MS-RPRN 2.2.1.3.7).
type splClientInfo1NDR struct {
	DwSize                 uint32
	PMachineName           string `ndr:"fullpointer,conformant,varying"`
	PUserName              string `ndr:"fullpointer,conformant,varying"`
	DwBuildNum             uint32
	DwMajorVersion         uint32
	DwMinorVersion         uint32
	WProcessorArchitecture uint16
}

// conformantByteArrayNDR wraps a conformant byte array for use as a nullable pointer target.
type conformantByteArrayNDR struct {
	Data []byte `ndr:"conformant"`
}

// RpcV2NotifyOptions represents RPC_V2_NOTIFY_OPTIONS (MS-RPRN 2.2.1.13.1).
// Exported for callers who need non-NULL pOptions (rare).
type RpcV2NotifyOptions struct {
	Version  uint32
	Reserved uint32
	Count    uint32
}

// rpcV2NotifyOptionsNDR is the NDR wire representation of RPC_V2_NOTIFY_OPTIONS.
type rpcV2NotifyOptionsNDR struct {
	Version  uint32
	Reserved uint32
	Count    uint32
	PTypes   uint32 // NULL pointer (we don't support pTypes)
}

// --- RpcOpenPrinterEx (Opnum 69) ---

type rpcOpenPrinterExReqNDR struct {
	PrinterName      *string               `ndr:"toplevel,fullpointer,conformant,varying"` // [in, string, unique]
	PDataType        *string               `ndr:"toplevel,fullpointer,conformant,varying"` // [in, string, unique] - always NULL
	DevModeContainer devModeContainerNDR   // [in]
	AccessRequired   uint32                // [in]
	ClientInfo       splClientContainerNDR // [in]
}

type rpcOpenPrinterExResNDR struct {
	Handle     [20]byte // PRINTER_HANDLE
	ReturnCode uint32
}

// --- RpcClosePrinter (Opnum 29) ---

type rpcClosePrinterReqNDR struct {
	Handle [20]byte
}

type rpcClosePrinterResNDR struct {
	Handle     [20]byte // zeroed by server
	ReturnCode uint32
}

// --- RpcRemoteFindFirstPrinterChangeNotification (Opnum 62) ---

type rpcRFFPCNReqNDR struct {
	Handle          [20]byte
	FdwFlags        uint32
	FdwOptions      uint32
	PszLocalMachine *string `ndr:"toplevel,fullpointer,conformant,varying"` // [in, string, unique]
	DwPrinterLocal  uint32
	CbBuffer        uint32
	PBuffer         *conformantByteArrayNDR `ndr:"toplevel,fullpointer"` // [in, out, unique] - NULL
}

type rpcRFFPCNResNDR struct {
	PBuffer    *conformantByteArrayNDR `ndr:"toplevel,fullpointer"` // [in, out]
	ReturnCode uint32
}

// --- RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65) ---

type rpcRFFPCNExReqNDR struct {
	Handle          [20]byte
	FdwFlags        uint32
	FdwOptions      uint32
	PszLocalMachine *string `ndr:"toplevel,fullpointer,conformant,varying"` // [in, string, unique]
	DwPrinterLocal  uint32
	POptions        *rpcV2NotifyOptionsNDR `ndr:"toplevel,fullpointer"` // [in, unique] - NULL
}

type rpcRFFPCNExResNDR struct {
	ReturnCode uint32
}

// Marshal/Unmarshal methods

func (s *rpcOpenPrinterExReqNDR) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RpcOpenPrinterExReq: %w", err)
	}
	return b, nil
}

func (s *rpcOpenPrinterExResNDR) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RpcOpenPrinterExRes: %w", err)
	}
	return nil
}

func (s *rpcClosePrinterReqNDR) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RpcClosePrinterReq: %w", err)
	}
	return b, nil
}

func (s *rpcClosePrinterResNDR) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RpcClosePrinterRes: %w", err)
	}
	return nil
}

func (s *rpcRFFPCNReqNDR) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RpcRemoteFindFirstPrinterChangeNotificationReq: %w", err)
	}
	return b, nil
}

func (s *rpcRFFPCNResNDR) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RpcRemoteFindFirstPrinterChangeNotificationRes: %w", err)
	}
	return nil
}

func (s *rpcRFFPCNExReqNDR) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling RpcRemoteFindFirstPrinterChangeNotificationExReq: %w", err)
	}
	return b, nil
}

func (s *rpcRFFPCNExResNDR) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling RpcRemoteFindFirstPrinterChangeNotificationExRes: %w", err)
	}
	return nil
}
