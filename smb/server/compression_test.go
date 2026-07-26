// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// TestCompressionRoundTrip stands up a compression-enabled server, connects with
// a compression-enabled go-smb client, and round-trips a highly compressible
// file. It asserts (a) an inbound compression-transform (0xFCSMB) frame is
// observed on the wire — proving the client compressed a request the server
// then decompressed — and (b) the data survives intact, which also exercises
// the server→client reply-compression path (the client must decompress the READ
// reply to reconstruct the payload).
func TestCompressionRoundTrip(t *testing.T) {
	const (
		user     = "alice"
		password = "password123"
		domain   = "WORKGROUP"
		share    = "data"
		filename = "big.txt"
	)
	// ~24 KiB, highly compressible.
	payload := bytes.Repeat([]byte("COMPRESS-ME-"), 2000)
	ntHash := ntlmssp.Ntowfv1(password)

	var compressedInboundSeen atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			Compression: true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolCompressionHdr {
					compressedInboundSeen.Store(true)
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Compression: true,
		DialTimeout: 2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile: %v", err)
	}

	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
	if !compressedInboundSeen.Load() {
		t.Fatal("no inbound compression-transform frame observed; client did not compress")
	}
}

// TestCompressionWithEncryption exercises the combined path: on send the PDU is
// compressed then encrypted (0xFCSMB inside 0xFDSMB), on receive it is decrypted
// then decompressed. With encryption engaged the compression frame is nested
// inside the TransformHeader, so only 0xFDSMB is visible on the wire; the test
// relies on the round-trip succeeding to prove both nested directions work.
func TestCompressionWithEncryption(t *testing.T) {
	const (
		user     = "bob"
		password = "hunter2xyz"
		domain   = "WORKGROUP"
		share    = "enc"
		filename = "big.txt"
	)
	payload := bytes.Repeat([]byte("ENCRYPT-AND-COMPRESS-"), 1500) // ~31 KiB
	ntHash := ntlmssp.Ntowfv1(password)

	var transformSeen atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			Compression:         true,
			EncryptionSupported: true,
			RequireEncryption:   true,
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
			OnRawRequest: func(c *server.Conn, raw []byte) (bool, error) {
				if len(raw) >= 4 && string(raw[0:4]) == smb.ProtocolTransformHdr {
					transformSeen.Store(true)
				}
				return false, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{}), EncryptData: true})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		Compression: true,
		DialTimeout: 2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	src := bytes.NewReader(payload)
	if err := c.PutFile(share, filename, 0, func(buf []byte) (int, error) {
		n, err := src.Read(buf)
		if err == io.EOF && n == 0 {
			return 0, io.EOF
		}
		return n, nil
	}); err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	var got bytes.Buffer
	if err := c.RetrieveFile(share, filename, 0, func(b []byte) (int, error) {
		got.Write(b)
		return len(b), nil
	}); err != nil {
		t.Fatalf("RetrieveFile: %v", err)
	}
	if !bytes.Equal(got.Bytes(), payload) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", got.Len(), len(payload))
	}
	if !transformSeen.Load() {
		t.Fatal("no TransformHeader observed; encryption did not engage")
	}
}

// TestNegotiateCompressionEnabled drives a 3.1.1 Negotiate with a real
// compression offer against a compression-enabled server and asserts the reply
// carries a CompressionCapabilities context with a non-zero algorithm count and
// the chained flag.
func TestNegotiateCompressionEnabled(t *testing.T) {
	srv := &server.Server{Config: &server.ServerConfig{Compression: true}}
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
	comp := smb.CompressionContext{
		CompressionAlgorithmCount: 2,
		Flags:                     smb.CompressionCapabilitiesFlagChained,
		CompressionAlgorithms:     []uint16{smb.CompressionLZ77Huffman, smb.CompressionLZ77},
	}
	compBuf, _ := encoder.Marshal(comp)

	contexts := []smb.NegContext{
		{ContextType: smb.PreauthIntegrityCapabilities, Data: picBuf, DataLength: uint16(len(picBuf)), Padd: make([]byte, (8-len(picBuf)%8)%8)},
		{ContextType: smb.CompressionCapabilities, Data: compBuf, DataLength: uint16(len(compBuf))},
	}
	req := smb.NegotiateReq{
		Header: smb.Header{
			ProtocolID:    []byte(smb.ProtocolSmb2),
			StructureSize: 64,
			Command:       smb.CommandNegotiate,
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
	resp := make([]byte, binary.BigEndian.Uint32(lenBuf[:]))
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(resp) < 128 {
		t.Fatalf("response too short: %d", len(resp))
	}

	ctxCount := binary.LittleEndian.Uint16(resp[70:72])
	off := int(binary.LittleEndian.Uint32(resp[124:128]))
	var compData []byte
	for i := 0; i < int(ctxCount); i++ {
		if off+8 > len(resp) {
			t.Fatalf("ctx %d header out of bounds", i)
		}
		ctype := binary.LittleEndian.Uint16(resp[off : off+2])
		dlen := int(binary.LittleEndian.Uint16(resp[off+2 : off+4]))
		if off+8+dlen > len(resp) {
			t.Fatalf("ctx %d data out of bounds", i)
		}
		if ctype == smb.CompressionCapabilities {
			compData = resp[off+8 : off+8+dlen]
		}
		step := 8 + dlen
		if step%8 != 0 {
			step += 8 - (step % 8)
		}
		off += step
	}
	if compData == nil {
		t.Fatal("server did not emit a CompressionCapabilities context")
	}
	var rc smb.CompressionContext
	if err := encoder.Unmarshal(compData, &rc); err != nil {
		t.Fatalf("decode response CompressionContext: %v", err)
	}
	if rc.CompressionAlgorithmCount == 0 || len(rc.CompressionAlgorithms) == 0 {
		t.Fatal("response CompressionAlgorithmCount is 0 (invalid per MS-SMB2 §2.2.3.1.3)")
	}
	if rc.Flags&smb.CompressionCapabilitiesFlagChained == 0 {
		t.Error("response did not set CompressionCapabilitiesFlagChained")
	}
	if rc.CompressionAlgorithms[0] != smb.CompressionLZ77Huffman {
		t.Errorf("expected LZ77+Huffman first, got 0x%04x", rc.CompressionAlgorithms[0])
	}
}
