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

package smbtransport

import (
	"fmt"

	"github.com/jfjallid/go-smb/smb"
)

// SMBTransport implements dcerpc.DCERPCTransport over SMB named pipes.
type SMBTransport struct {
	f *smb.File
}

// NewSMBTransport creates a DCERPCTransport backed by an open SMB named pipe.
func NewSMBTransport(f *smb.File) (*SMBTransport, error) {
	if f == nil {
		return nil, fmt.Errorf("file argument cannot be nil")
	}
	if !f.IsOpen() {
		return nil, fmt.Errorf("file must be opened before creating transport")
	}
	return &SMBTransport{f: f}, nil
}

func (t *SMBTransport) Transceive(pdu []byte) ([]byte, error) {
	ioCtlReq, err := t.f.NewIoCTLReq(smb.FsctlPipeTransceive, pdu)
	if err != nil {
		return nil, err
	}
	ioCtlRes, err := t.f.WriteIoCtlReq(ioCtlReq)
	if err != nil {
		return nil, err
	}
	return ioCtlRes.Buffer, nil
}

func (t *SMBTransport) Write(pdu []byte) error {
	_, err := t.f.WriteFile(pdu, 0)
	return err
}

func (t *SMBTransport) Read(maxSize uint16) ([]byte, error) {
	buf := make([]byte, int(maxSize)+16) // 16 bytes overhead
	n, err := t.f.ReadFile(buf, 0)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *SMBTransport) GetSessionKey() []byte {
	return t.f.GetSessionKey()
}
