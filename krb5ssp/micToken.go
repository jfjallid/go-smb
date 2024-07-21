// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
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
package krb5ssp

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Length of the first four fields of the Wrap Tokens in RFC 4121 Section 4.2.6.2
const MICTokenHdrLen = 16

var be = binary.BigEndian

// RFC 4121 Section 4.2.6.1
type MICToken struct {
	TokenId      uint16 // big-endian 0x0404
	Flags        byte
	Filler       []byte // Must be 5 bytes of 0xFF
	SenderSeqNum uint64 // big-endian
	Payload      []byte // Not actually part of the MICToken but included for convenience
	Checksum     []byte
}

// Return the header fields to calculate the checksum on
func (self *MICToken) MarshalHeader() []byte {
	buf := make([]byte, MICTokenHdrLen)
	be.PutUint16(buf[0:2], self.TokenId)
	buf[2] = self.Flags
	copy(buf[3:8], self.Filler)
	be.PutUint64(buf[8:16], self.SenderSeqNum)
	return buf
}

func (self *MICToken) MarshalBinary() (ret []byte, err error) {
	w := bytes.NewBuffer(ret)
	if self.Checksum == nil {
		err = fmt.Errorf("Checksum has not been calculated yet so can't marshal MICToken")
		log.Errorln(err)
		return
	}
	_, err = w.Write(self.MarshalHeader())
	if err != nil {
		log.Errorln(err)
		return
	}
	_, err = w.Write(self.Checksum)
	if err != nil {
		log.Errorln(err)
		return
	}

	return w.Bytes(), nil
}
