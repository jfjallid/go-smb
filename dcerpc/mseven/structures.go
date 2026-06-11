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

package mseven

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/mstypes"
	"github.com/jfjallid/ndr"
)

// --- ElfrOpenBELW (Opnum 9) ---

type elfrOpenBELWReq struct {
	UNCServerName  *string                  `ndr:"toplevel,fullpointer,conformant,varying"` // [in] EVENTLOG_HANDLE_W, unique ptr (NULL for local)
	BackupFileName mstypes.RPCUnicodeString `ndr:"toplevel"`                                // [in] PRPC_UNICODE_STRING, ref ptr (inline, Buffer deferred)
	MajorVersion   uint32                   // [in] must be 1
	MinorVersion   uint32                   // [in] must be 1
}

type elfrOpenBELWRes struct {
	LogHandle  [20]byte // IELF_HANDLE context handle
	ReturnCode uint32
}

// --- ElfrCloseEL (Opnum 2) ---

type elfrCloseELReq struct {
	LogHandle [20]byte // [in, out] IELF_HANDLE
}

type elfrCloseELRes struct {
	LogHandle  [20]byte // zeroed by server
	ReturnCode uint32
}

// Marshal/Unmarshal methods

func (s *elfrOpenBELWReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ElfrOpenBELWReq: %w", err)
	}
	return b, nil
}

func (s *elfrOpenBELWRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling ElfrOpenBELWRes: %w", err)
	}
	return nil
}

func (s *elfrCloseELReq) Marshal() ([]byte, error) {
	enc := ndr.NewEncoder(bytes.NewBuffer([]byte{}), false)
	enc.SetEndianness(binary.LittleEndian)
	b, err := enc.Encode(s)
	if err != nil {
		return nil, fmt.Errorf("error marshaling ElfrCloseELReq: %w", err)
	}
	return b, nil
}

func (s *elfrCloseELRes) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b), false)
	err := dec.Decode(s)
	if err != nil {
		return fmt.Errorf("error unmarshaling ElfrCloseELRes: %w", err)
	}
	return nil
}
