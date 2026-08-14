// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// TestNegotiateMaxBufSizeDefaults verifies that MaxReadSize/MaxWriteSize/
// MaxTransactSize in the NegotiateRes are 1 MiB on dialects ≥ 2.1 and
// 64 KiB on 2.0.2 — Phase 7 of the dialect-compliance work.
func TestNegotiateMaxBufSizeDefaults(t *testing.T) {
	cases := []struct {
		name    string
		dialect uint16
		wantBuf uint32
	}{
		{"smb_2_0_2", smb.DialectSmb_2_0_2, 65536},
		{"smb_2_1", smb.DialectSmb_2_1, 1 << 20},
		{"smb_3_1_1", smb.DialectSmb_3_1_1, 1 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server.Server{Config: &server.ServerConfig{
				MinDialect: smb.DialectSmb_2_0_2,
			}}
			addr, shutdown := startTestServer(t, srv)
			defer shutdown()

			conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			req := smb.NegotiateReq{
				Header: smb.Header{
					ProtocolID:    []byte(smb.ProtocolSmb2),
					StructureSize: 64,
					Command:       smb.CommandNegotiate,
					Credits:       0,
					Signature:     make([]byte, 16),
				},
				StructureSize: 36,
				Dialects:      []uint16{tc.dialect},
				SecurityMode:  smb.SecurityModeSigningEnabled,
				ClientGuid:    make([]byte, 16),
			}
			if tc.dialect == smb.DialectSmb_3_1_1 {
				// 3.1.1 requires PreauthIntegrity context.
				pic := smb.PreauthIntegrityContext{
					HashAlgorithmCount: 1,
					HashAlgorithms:     []uint16{smb.SHA512},
					SaltLength:         32,
					Salt:               make([]byte, 32),
				}
				picBuf, _ := pic.MarshalBinary()
				req.ContextList = []smb.NegContext{
					{ContextType: smb.PreauthIntegrityCapabilities, Data: picBuf, DataLength: uint16(len(picBuf))},
				}
				req.NegotiateContextCount = uint16(len(req.ContextList))
			}
			body, err := req.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			frame := make([]byte, 4+len(body))
			binary.BigEndian.PutUint32(frame[:4], uint32(len(body)))
			copy(frame[4:], body)
			if _, err := conn.Write(frame); err != nil {
				t.Fatalf("write: %v", err)
			}

			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			var lenBuf [4]byte
			if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
				t.Fatalf("read framing: %v", err)
			}
			respLen := binary.BigEndian.Uint32(lenBuf[:])
			resp := make([]byte, respLen)
			if _, err := io.ReadFull(conn, resp); err != nil {
				t.Fatalf("read body: %v", err)
			}
			// Per MS-SMB2 §2.2.4 layout — MaxTransactSize @92, MaxReadSize @96,
			// MaxWriteSize @100 (header 64 + body offset).
			if len(resp) < 104 {
				t.Fatalf("response too short: %d", len(resp))
			}
			maxTrans := binary.LittleEndian.Uint32(resp[92:96])
			maxRead := binary.LittleEndian.Uint32(resp[96:100])
			maxWrite := binary.LittleEndian.Uint32(resp[100:104])
			if maxTrans != tc.wantBuf || maxRead != tc.wantBuf || maxWrite != tc.wantBuf {
				t.Errorf("buffer sizes mismatch dialect=0x%04x: got T=%d R=%d W=%d want %d",
					tc.dialect, maxTrans, maxRead, maxWrite, tc.wantBuf)
			}
		})
	}
}
