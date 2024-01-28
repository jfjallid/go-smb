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
package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/jfjallid/go-smb/smb/encoder"
)

const (
	SMB1CommandNegotiate byte = 0x72
)

// MS-CIFS 2.2.3.1 SMB Header
type SMB1Header struct { // 32 bytes
	Protocol         []byte `smb:"fixed:4"` // Must contain 0xff, S, M, B
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type SMB1Dialect struct {
	BufferFormat  uint8  // Must be 0x2
	DialectString string // Null-terminated string
}

type SMB1NegotiateReq struct {
	Header    SMB1Header
	WordCount uint8
	ByteCount uint16
	Dialects  []SMB1Dialect
}

func (self *SMB1NegotiateReq) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for SMB1NegotiateReq")
	buf := make([]byte, 0, 46)
	w := bytes.NewBuffer(buf)
	hBuf, err := encoder.Marshal(self.Header)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	w.Write(hBuf)

	// WordCount
	w.WriteByte(self.WordCount)

	dialectsBuffer := make([]byte, 0, 11)
	for _, item := range self.Dialects {
		dialectsBuffer = append(dialectsBuffer, 0x2)
		dialectsBuffer = append(dialectsBuffer, []byte(item.DialectString)...)
	}
	// ByteCount
	binary.Write(w, binary.LittleEndian, uint16(len(dialectsBuffer)))

	// Dialects
	binary.Write(w, binary.LittleEndian, dialectsBuffer)

	return w.Bytes(), nil
}

func (self *SMB1NegotiateReq) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for SMB1NegotiateReq")
}

func (s *Session) NewSMB1NegotiateReq() (req SMB1NegotiateReq, err error) {
	header := SMB1Header{
		Protocol:         []byte(ProtocolSmb),
		Command:          SMB1CommandNegotiate,
		Flags:            0x18,   // Canonicalized Pathnames, Case sensitivity (path names are caseless)
		Flags2:           0xc801, // Unicode strings, NT Error codes, Extended security negotiation, Long names are allowed
		SecurityFeatures: make([]byte, 8),
		TID:              0xffff,
	}

	// Dialects ordered in increasing preference
	dialects := []SMB1Dialect{
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("SMB 2.100\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("SMB 2.???\x00"),
		},
	}

	req = SMB1NegotiateReq{
		Header:   header,
		Dialects: dialects,
	}

	return
}
