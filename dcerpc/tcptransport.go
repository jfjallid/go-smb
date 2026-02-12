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

package dcerpc

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
)

// TCPTransport implements DCERPCTransport over a raw TCP connection.
// DCERPC over TCP is self-framing via the FragLength field in the PDU header.
type TCPTransport struct {
	conn       net.Conn
	mu         sync.Mutex // Serialize access to the connection
	sessionKey []byte     // Populated after authenticated bind (future)
}

func NewTCPTransport(conn net.Conn) *TCPTransport {
	return &TCPTransport{conn: conn}
}

func (t *TCPTransport) Transceive(pdu []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.writePDU(pdu); err != nil {
		return nil, err
	}
	return t.readPDU()
}

func (t *TCPTransport) Write(pdu []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.writePDU(pdu)
}

func (t *TCPTransport) Read(maxSize uint16) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.readPDU()
}

func (t *TCPTransport) Close() error {
	return t.conn.Close()
}

func (t *TCPTransport) GetSessionKey() []byte {
	return t.sessionKey
}

func (t *TCPTransport) SetSessionKey(key []byte) {
	t.sessionKey = make([]byte, len(key))
	copy(t.sessionKey, key)
}

func (t *TCPTransport) writePDU(pdu []byte) error {
	_, err := t.conn.Write(pdu)
	return err
}

// readPDU reads a complete DCERPC PDU. Reads the 16-byte header first
// to get FragLength, then reads the remaining bytes.
func (t *TCPTransport) readPDU() ([]byte, error) {
	header := make([]byte, PDUHeaderCommonSize)
	_, err := io.ReadFull(t.conn, header)
	if err != nil {
		return nil, fmt.Errorf("failed to read DCERPC header: %w", err)
	}
	fragLen := binary.LittleEndian.Uint16(header[8:10])
	if fragLen < uint16(PDUHeaderCommonSize) {
		return nil, fmt.Errorf("invalid DCERPC fragment length: %d", fragLen)
	}
	pdu := make([]byte, fragLen)
	copy(pdu, header)
	if fragLen > uint16(PDUHeaderCommonSize) {
		_, err = io.ReadFull(t.conn, pdu[PDUHeaderCommonSize:])
		if err != nil {
			return nil, fmt.Errorf("failed to read DCERPC PDU body: %w", err)
		}
	}
	return pdu, nil
}
