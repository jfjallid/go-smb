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
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
)

// TestNegotiateContextEchoes drives a 3.1.1 Negotiate that includes both
// NetNameNegotiateContextId and CompressionCapabilities and verifies the
// server echoes NetName back (a spec-compliance fix for clients — notably some
// macOS builds — that drop the connection if NetName isn't echoed) while it
// does NOT emit a CompressionCapabilities context. MS-SMB2 §2.2.3.1.3 requires
// CompressionAlgorithmCount > 0, so the reply for "no compression" is to omit
// the context entirely; Windows RSTs the connection on reading a count=0
// context.
func TestNegotiateContextEchoes(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{}}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Build the four contexts the client sends on 3.1.1: PreauthIntegrity
	// (mandatory), Encryption, NetName (UTF-16 "SERVER"), Compression
	// (count=0, just to provoke an echo).
	pic := smb.PreauthIntegrityContext{
		HashAlgorithmCount: 1,
		HashAlgorithms:     []uint16{smb.SHA512},
		SaltLength:         32,
		Salt:               make([]byte, 32),
	}
	picBuf, _ := encoder.Marshal(pic)

	ec := smb.EncryptionContext{
		CipherCount: 1,
		Ciphers:     []uint16{smb.AES128CCM},
	}
	ecBuf, _ := encoder.Marshal(ec)

	netName := encoder.ToUnicode("SERVER")
	// Compression context: minimal 8-byte body with count=0
	compBuf := make([]byte, 8)

	contexts := []smb.NegContext{
		{ContextType: smb.PreauthIntegrityCapabilities, Data: picBuf, DataLength: uint16(len(picBuf)), Padd: make([]byte, (8-len(picBuf)%8)%8)},
		{ContextType: smb.EncryptionCapabilities, Data: ecBuf, DataLength: uint16(len(ecBuf)), Padd: make([]byte, (8-len(ecBuf)%8)%8)},
		{ContextType: smb.CompressionCapabilities, Data: compBuf, DataLength: uint16(len(compBuf)), Padd: make([]byte, (8-len(compBuf)%8)%8)},
		// Last context — no trailing pad.
		{ContextType: smb.NetNameNegotiateContextId, Data: netName, DataLength: uint16(len(netName))},
	}

	req := smb.NegotiateReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandNegotiate,
			Credits:       0,
			Signature:     make([]byte, 16),
		},
		StructureSize:         36,
		Dialects:              []uint16{smb.DialectSmb_3_1_1},
		SecurityMode:          smb.SecurityModeSigningEnabled,
		ClientGuid:            make([]byte, 16),
		ContextList:           contexts,
		NegotiateContextCount: uint16(len(contexts)),
	}
	body, err := encoder.Marshal(&req)
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

	// Parse the response by hand — encoder.Unmarshal(NegotiateRes) panics on
	// the *gss.NegTokenInit pointer when the test doesn't pre-allocate it,
	// and the response-side decoder isn't the point of this test anyway.
	// Field offsets per MS-SMB2 §2.2.4 (header is 64 bytes):
	//   DialectRevision        @68 (uint16)
	//   NegotiateContextCount  @70 (uint16)
	//   NegotiateContextOffset @124 (uint32)
	if len(resp) < 128 {
		t.Fatalf("response too short: %d", len(resp))
	}
	dialect := binary.LittleEndian.Uint16(resp[68:70])
	if dialect != smb.DialectSmb_3_1_1 {
		t.Fatalf("DialectRevision: got 0x%04x want 0x0311", dialect)
	}
	ctxCount := binary.LittleEndian.Uint16(resp[70:72])
	ctxOff := binary.LittleEndian.Uint32(resp[124:128])

	sawNetName := false
	sawCompression := false
	off := int(ctxOff)
	for i := 0; i < int(ctxCount); i++ {
		if off+8 > len(resp) {
			t.Fatalf("ctx %d header out of bounds (off=%d)", i, off)
		}
		ctype := binary.LittleEndian.Uint16(resp[off : off+2])
		dlen := binary.LittleEndian.Uint16(resp[off+2 : off+4])
		dataStart := off + 8
		if dataStart+int(dlen) > len(resp) {
			t.Fatalf("ctx %d data out of bounds (start=%d len=%d resp=%d)", i, dataStart, dlen, len(resp))
		}
		data := resp[dataStart : dataStart+int(dlen)]
		switch ctype {
		case smb.NetNameNegotiateContextId:
			sawNetName = true
			if string(data) != string(netName) {
				t.Errorf("NetName echo mismatch: got %x want %x", data, netName)
			}
		case smb.CompressionCapabilities:
			sawCompression = true
		}
		// Advance to the next context: 8-byte header + DataLength bytes,
		// 8-aligned.
		step := 8 + int(dlen)
		if step%8 != 0 {
			step += 8 - (step % 8)
		}
		off += step
	}
	if !sawNetName {
		t.Error("server did not echo NetNameNegotiateContextId")
	}
	if sawCompression {
		t.Error("server emitted a CompressionCapabilities context; MS-SMB2 §2.2.3.1.3 requires it be omitted when no algorithm is offered")
	}
}

// TestNegotiateUnalignedContextOffsetRejected sends a hand-built 3.1.1
// NegotiateReq whose NegotiateContextOffset points to byte 106 (immediately
// after the dialects, with no alignment padding). MS-SMB2 §2.2.3 requires
// the offset to be 8-byte aligned; the server must reject the request with
// STATUS_INVALID_PARAMETER rather than parse it leniently.
//
// Regression coverage: an earlier version of go-smb's own client produced
// exactly this wire layout because the encoder bypassed the pointer-receiver
// MarshalBinary. Windows correctly rejected it; the go-smb server did not.
// This test locks in the strict server behavior.
func TestNegotiateUnalignedContextOffsetRejected(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{}}
	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	conn, err := net.DialTimeout("tcp", addr.String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	pic := smb.PreauthIntegrityContext{
		HashAlgorithmCount: 1,
		HashAlgorithms:     []uint16{smb.SHA512},
		SaltLength:         32,
		Salt:               make([]byte, 32),
	}
	picBuf, _ := encoder.Marshal(pic)

	// Hand-assemble the SMB2 NegotiateReq with three dialects and one
	// context, but place the context immediately at byte 106 (no padding)
	// and set NegotiateContextOffset = 106 to match. This is the exact
	// malformed shape the historical client bug produced.
	const headerLen = 64
	const fixedBody = 36
	body := make([]byte, 0, 200)
	// SMB2 header.
	hdr := make([]byte, headerLen)
	copy(hdr[:4], smb.ProtocolSmb2)
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(hdr[12:14], smb.CommandNegotiate)
	binary.LittleEndian.PutUint16(hdr[14:16], 1) // Credits
	body = append(body, hdr...)
	// Fixed body.
	fb := make([]byte, fixedBody)
	binary.LittleEndian.PutUint16(fb[0:2], 36)                                // StructureSize
	binary.LittleEndian.PutUint16(fb[2:4], 3)                                 // DialectCount
	binary.LittleEndian.PutUint16(fb[4:6], smb.SecurityModeSigningEnabled)    // SecurityMode
	binary.LittleEndian.PutUint32(fb[28:32], uint32(headerLen+fixedBody+2*3)) // NegotiateContextOffset = 106 (unaligned)
	binary.LittleEndian.PutUint16(fb[32:34], 1)                               // NegotiateContextCount
	body = append(body, fb...)
	// Dialects.
	for _, d := range []uint16{smb.DialectSmb_3_1_1, smb.DialectSmb_2_1, smb.DialectSmb_2_0_2} {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], d)
		body = append(body, b[:]...)
	}
	// First (and only) context, placed RIGHT after dialects — no alignment pad.
	ctx := make([]byte, 8+len(picBuf))
	binary.LittleEndian.PutUint16(ctx[0:2], smb.PreauthIntegrityCapabilities)
	binary.LittleEndian.PutUint16(ctx[2:4], uint16(len(picBuf)))
	copy(ctx[8:], picBuf)
	body = append(body, ctx...)

	// NetBIOS framing.
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
	if len(resp) < 12 {
		t.Fatalf("response too short: %d", len(resp))
	}
	// SMB2 header Status field sits at bytes [8:12].
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb.StatusInvalidParameter {
		t.Fatalf("status = 0x%08x, want STATUS_INVALID_PARAMETER (0x%08x)",
			status, smb.StatusInvalidParameter)
	}
}
