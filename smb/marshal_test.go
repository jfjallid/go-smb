// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package smb

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/smb/unicode"
)

func pat(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// goldenHeader is a fully-populated SMB2 header with distinctive values in every
// field, so a transposed or dropped field shows up in the golden bytes.
func goldenHeader() Header {
	return Header{
		ProtocolID:    []byte(ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  1,
		Command:       5,
		Credits:       33,
		Flags:         0x11,
		MessageID:     0x0102030405060708,
		Reserved:      0xaabbccdd,
		TreeID:        0x12345678,
		SessionID:     0x1122334455667788,
		Signature:     pat(16, 0x40),
	}
}

const goldenHeaderHex = "fe534d4240000100000000000500210011000000000000000807060504030201" +
	"ddccbbaa785634128877665544332211404142434445464748494a4b4c4d4e4f"

// TestMarshalGolden pins the SMB2 wire format to the bytes the reflection
// encoder produced before it was retired. Every expectation below was captured
// from the old smb/encoder path, so a difference here means a hand-written
// marshaller changed what goes on the wire.
//
// Two deliberate deviations, both unreachable from the callers in this repo:
//
//   - ReadRes.DataOffset is now derived (80) rather than passed through. The tag
//     engine ignored len/offset tags on byte-typed fields, so the caller had to
//     set it; smb/server/read.go sets exactly 80, so real output is unchanged.
//   - Fixed-width fields (GUIDs, FileIds) are padded/truncated to their spec
//     length instead of being emitted at the caller's length.
func TestMarshalGolden(t *testing.T) {
	h := goldenHeader()

	blobInit := &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes:    []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
			MechToken:    pat(24, 0x50),
			MechTokenMIC: []byte{},
		},
	}
	blobResp := &gss.NegTokenResp{
		State:         1,
		SupportedMech: gss.NtLmSSPMechTypeOid,
		ResponseToken: pat(20, 0x60),
	}

	tests := []struct {
		name string
		v    Marshaller
		want string
	}{
		{"Header", &h, goldenHeaderHex},
		{
			"TransformHeader",
			&TransformHeader{
				ProtcolID: 0x424d53fd, Signature: pat(16, 1), Nonce: pat(16, 0x20),
				OriginalMessageSize: 0x1000, Flags: 1, SessionId: 0x1122334455667788,
			},
			"fd534d420102030405060708090a0b0c0d0e0f10202122232425262728292a2b" +
				"2c2d2e2f00100000000001008877665544332211",
		},
		{
			"NegContext",
			&NegContext{ContextType: 2, Data: pat(6, 0x90)},
			"0200060000000000909192939495",
		},
		{
			"PreauthIntegrityContext",
			&PreauthIntegrityContext{HashAlgorithms: []uint16{SHA512}, Salt: pat(32, 0x10)},
			// HashAlgorithmCount is written verbatim, so it stays 0 here even
			// though one algorithm follows — see the package comment.
			"000020000100101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
		},
		{
			// Data already a multiple of 8: no alignment tail either way.
			"NegContextAligned",
			&NegContext{ContextType: 2, Data: pat(8, 0x90)},
			"02000800000000009091929394959697",
		},
		{"EncryptionContext", &EncryptionContext{Ciphers: []uint16{2, 1}}, "000002000100"},
		{
			"CompressionContext",
			&CompressionContext{Flags: 1, CompressionAlgorithms: []uint16{3, 2, 1}},
			"0000000001000000030002000100",
		},
		{"SigningContext", &SigningContext{SigningAlgorithms: []uint16{2, 1, 0}}, "0000020001000000"},
		{"LogoffReq", &LogoffReq{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"LogoffRes", &LogoffRes{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"TreeDisconnectReq", &TreeDisconnectReq{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"TreeDisconnectRes", &TreeDisconnectRes{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"EchoReq", &EchoReq{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"EchoRes", &EchoRes{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"CancelReq", &CancelReq{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"FlushRes", &FlushRes{Header: h, StructureSize: 4}, goldenHeaderHex + "04000000"},
		{"SetInfoRes", &SetInfoRes{Header: h, StructureSize: 2}, goldenHeaderHex + "0200"},
		{
			"TreeConnectReq",
			&TreeConnectReq{Header: h, StructureSize: 9, Path: unicode.ToUnicode(`\\srv\IPC$`)},
			goldenHeaderHex + "09000000480014005c005c007300720076005c004900500043002400",
		},
		{
			"TreeConnectRes",
			&TreeConnectRes{
				Header: h, StructureSize: 16, ShareType: 2, ShareFlags: 0x30,
				Capabilities: 8, MaximalAccess: 0x001f01ff,
			},
			goldenHeaderHex + "100002003000000008000000ff011f00",
		},
		{
			"CreateRes",
			&CreateRes{
				Header: h, StructureSize: 89, OplockLevel: 1, CreateAction: 1,
				CreationTime: 0x11, LastAccessTime: 0x22, LastWriteTime: 0x33, ChangeTime: 0x44,
				AllocationSize: 0x1000, EndOfFile: 0x800, FileAttributes: 0x20,
				FileId: pat(16, 0x70), Buffer: pat(8, 0xb0),
			},
			goldenHeaderHex + "5900010001000000110000000000000022000000000000003300000000000000" +
				"4400000000000000001000000000000000080000000000002000000000000000" +
				"707172737475767778797a7b7c7d7e7f9800000008000000b0b1b2b3b4b5b6b7",
		},
		{
			"CloseReq",
			&CloseReq{Header: h, StructureSize: 24, Flags: 1, FileId: pat(16, 0x70)},
			goldenHeaderHex + "1800010000000000707172737475767778797a7b7c7d7e7f",
		},
		{
			"CloseRes",
			&CloseRes{
				Header: h, StructureSize: 60, Flags: 1, CreationTime: 0x11,
				LastAccessTime: 0x22, LastWriteTime: 0x33, ChangeTime: 0x44,
				AllocationSize: 0x1000, EndOfFile: 0x800, FileAttributes: 0x20,
			},
			goldenHeaderHex + "3c00010000000000110000000000000022000000000000003300000000000000" +
				"44000000000000000010000000000000000800000000000020000000",
		},
		{
			"OplockBreak",
			&OplockBreak{Header: h, StructureSize: 24, OplockLevel: 2, FileId: pat(16, 0x70)},
			goldenHeaderHex + "1800020000000000707172737475767778797a7b7c7d7e7f",
		},
		{
			"FlushReq",
			&FlushReq{Header: h, StructureSize: 24, FileId: pat(16, 0x70)},
			goldenHeaderHex + "1800000000000000707172737475767778797a7b7c7d7e7f",
		},
		{
			"QueryDirectoryReq",
			&QueryDirectoryReq{
				Header: h, StructureSize: 33, FileInformationClass: 3,
				FileID: pat(16, 0x70), OutputBufferLength: 0x10000, Buffer: unicode.ToUnicode("*"),
			},
			goldenHeaderHex + "2100030000000000707172737475767778797a7b7c7d7e7f60000200000001002a00",
		},
		{
			"QueryDirectoryRes",
			&QueryDirectoryRes{Header: h, StructureSize: 9, Buffer: pat(24, 0xc0)},
			goldenHeaderHex + "0900480018000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7",
		},
		{
			"FileBothDirectoryInformationStruct",
			&FileBothDirectoryInformationStruct{
				NextEntryOffset: 104, CreationTime: 0x11, LastAccessTime: 0x22,
				LastWriteTime: 0x33, ChangeTime: 0x44, EndOfFile: 0x800, AllocationSize: 0x1000,
				FileAttributes: 0x20, ShortName: pat(24, 0),
				FileName: unicode.ToUnicode("test.txt"),
			},
			"6800000000000000110000000000000022000000000000003300000000000000" +
				"440000000000000000080000000000000010000000000000200000001000000000000000" +
				"0000000102030405060708090a0b0c0d0e0f10111213141516177400650073" +
				"0074002e00740078007400",
		},
		{
			"WriteReq",
			&WriteReq{
				Header: h, StructureSize: 49, Offset: 0x200, FileId: pat(16, 0x70),
				Buffer: pat(16, 0xe0),
			},
			goldenHeaderHex + "31007000100000000002000000000000707172737475767778797a7b7c7d7e7f" +
				"00000000000000000000000000000000e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
		},
		{
			"WriteRes",
			&WriteRes{Header: h, StructureSize: 17, Count: 16},
			goldenHeaderHex + "11000000100000000000000000000000",
		},
		{
			"SetInfoReq",
			&SetInfoReq{
				Header: h, StructureSize: 33, InfoType: 1, FileInfoClass: 13,
				FileId: pat(16, 0x70), Buffer: pat(8, 0xf0),
			},
			goldenHeaderHex + "2100010d080000006000000000000000707172737475767778797a7b7c7d7e7f" +
				"f0f1f2f3f4f5f6f7",
		},
		{
			"SessionSetup1Req",
			&SessionSetup1Req{
				Header: h, StructureSize: 25, SecurityMode: 1, SecurityBlob: blobInit,
			},
			goldenHeaderHex + "19000001000000000000000058003a000000000000000000" +
				"603806062b0601050502a02e302ca00e300c060a2b06010401823702020aa21a0418" +
				"505152535455565758595a5b5c5d5e5f6061626364656667",
		},
		{
			"SessionSetup1Res",
			&SessionSetup1Res{Header: h, StructureSize: 9, SecurityBlob: blobResp},
			goldenHeaderHex + "0900000048002f00" +
				"a12d302ba0030a0101a10c060a2b06010401823702020aa2160414" +
				"606162636465666768696a6b6c6d6e6f70717273",
		},
		{
			"SessionSetup2Req",
			&SessionSetup2Req{
				Header: h, StructureSize: 25, SecurityMode: 1, SecurityBlob: blobResp,
			},
			goldenHeaderHex + "19000001000000000000000058002f000000000000000000" +
				"a12d302ba0030a0101a10c060a2b06010401823702020aa2160414" +
				"606162636465666768696a6b6c6d6e6f70717273",
		},
		{
			"SessionSetup2Res",
			&SessionSetup2Res{Header: h, StructureSize: 9, SecurityBlob: blobResp},
			goldenHeaderHex + "0900000048002f00" +
				"a12d302ba0030a0101a10c060a2b06010401823702020aa2160414" +
				"606162636465666768696a6b6c6d6e6f70717273",
		},
		{
			"NegotiateRes",
			&NegotiateRes{
				Header: h, StructureSize: 65, SecurityMode: 1, DialectRevision: 0x0311,
				ServerGuid: pat(16, 0x30), Capabilities: 0x7f,
				MaxTransactSize: 0x800000, MaxReadSize: 0x800000, MaxWriteSize: 0x800000,
				SystemTime: 0x11, ServerStartTime: 0x22, SecurityBlob: blobInit,
				ContextList: []NegContext{{ContextType: 1, Data: pat(8, 0x90)}},
			},
			goldenHeaderHex + "4100010011030000303132333435363738393a3b3c3d3e3f" +
				"7f00000000008000000080000000800011000000000000002200000000000000" +
				"80003a00ba000000" +
				"603806062b0601050502a02e302ca00e300c060a2b06010401823702020aa21a0418" +
				"505152535455565758595a5b5c5d5e5f606162636465666701000800000000009091929394959697",
		},
		{
			// IoCtlRes was already hand-written (marshal_server.go); pinned here so
			// the whole PDU surface is covered by one table.
			"IoCtlRes",
			&IoCtlRes{
				Header: h, StructureSize: 49, CtlCode: 0x0011c017, FileId: pat(16, 0x70),
				Buffer: pat(12, 0xa0),
			},
			goldenHeaderHex + "3100000017c01100707172737475767778797a7b7c7d7e7f" +
				"0000000000000000700000000c0000000000000000000000a0a1a2a3a4a5a6a7a8a9aaab",
		},
		{
			"NegotiateReq",
			&NegotiateReq{
				Header: h, StructureSize: 36, SecurityMode: 1, Capabilities: 0x7f,
				ClientGuid: pat(16, 0x30), NegotiateContextCount: 1,
				Dialects:    []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311},
				ContextList: []NegContext{{ContextType: 1, Data: pat(8, 0x90)}},
			},
			goldenHeaderHex + "24000500010000007f000000303132333435363738393a3b3c3d3e3f" +
				"70000000010000000202100200030203110300000100080000000000" +
				"9091929394959697",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.v.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			want, err := hex.DecodeString(tt.want)
			if err != nil {
				t.Fatalf("bad golden: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("wire format changed\n got: %x\nwant: %x", got, want)
			}
		})
	}
}

// TestReadResDataOffsetDerived documents the one intentional deviation from the
// old tag engine: it ignored offset tags on byte-typed fields, leaving callers
// to set DataOffset by hand. It is now derived, and equals the value
// smb/server/read.go was already supplying.
func TestReadResDataOffsetDerived(t *testing.T) {
	res := ReadRes{Header: goldenHeader(), StructureSize: 17, Buffer: pat(16, 0xd0)}
	buf, err := res.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if got := buf[headerSize+2]; got != 80 {
		t.Errorf("DataOffset = %d, want 80 (64-byte header + 16-byte body)", got)
	}
	var back ReadRes
	if err := back.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(back.Buffer, res.Buffer) {
		t.Errorf("Buffer = %x, want %x", back.Buffer, res.Buffer)
	}
}

// TestOffsetZeroForEmptyPayload replaces the retired encoder test of the same
// intent: a PDU with no payload MUST advertise offset 0, not the offset the
// payload would have occupied. Servers reject a non-zero offset with a
// zero length.
func TestOffsetZeroForEmptyPayload(t *testing.T) {
	h := goldenHeader()
	cases := []struct {
		name    string
		v       Marshaller
		offAt   int // byte index of the offset field within the marshaled PDU
		is32bit bool
	}{
		{"TreeConnectReq", &TreeConnectReq{Header: h, StructureSize: 9}, headerSize + 4, false},
		{"QueryDirectoryRes", &QueryDirectoryRes{Header: h, StructureSize: 9}, headerSize + 2, false},
		{"WriteReq", &WriteReq{Header: h, StructureSize: 49, FileId: pat(16, 1)}, headerSize + 2, false},
		{"SetInfoReq", &SetInfoReq{Header: h, StructureSize: 33, FileId: pat(16, 1)}, headerSize + 8, false},
		{"CreateRes", &CreateRes{Header: h, StructureSize: 89, FileId: pat(16, 1)}, headerSize + 80, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := tc.v.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			width := 2
			if tc.is32bit {
				width = 4
			}
			for i := tc.offAt; i < tc.offAt+width; i++ {
				if buf[i] != 0 {
					t.Fatalf("offset field is non-zero (byte %d = 0x%02x) for an empty payload", i, buf[i])
				}
			}
		})
	}
}

// TestUnmarshalRejectsOutOfRangePayload replaces the retired encoder bounds
// tests. Every one of these decoders runs on peer-supplied bytes, and the SMB2
// receive loop has no recover(), so an unchecked offset would be fatal.
func TestUnmarshalRejectsOutOfRangePayload(t *testing.T) {
	h := goldenHeader()

	// A well-formed PDU whose payload offset/length are then pushed out of range.
	req := TreeConnectReq{Header: h, StructureSize: 9, Path: unicode.ToUnicode(`\\srv\IPC$`)}
	buf, err := req.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	t.Run("in bounds succeeds", func(t *testing.T) {
		var got TreeConnectReq
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if !bytes.Equal(got.Path, req.Path) {
			t.Errorf("Path = %x, want %x", got.Path, req.Path)
		}
	})

	t.Run("length past end", func(t *testing.T) {
		bad := append([]byte(nil), buf...)
		bad[headerSize+6], bad[headerSize+7] = 0xff, 0xff // PathLength
		var got TreeConnectReq
		if err := got.UnmarshalBinary(bad); err == nil {
			t.Fatal("expected an error for a PathLength past the end of the PDU")
		}
	})

	t.Run("offset past end", func(t *testing.T) {
		bad := append([]byte(nil), buf...)
		bad[headerSize+4], bad[headerSize+5] = 0xff, 0xff // PathOffset
		var got TreeConnectReq
		if err := got.UnmarshalBinary(bad); err == nil {
			t.Fatal("expected an error for a PathOffset past the end of the PDU")
		}
	})

	t.Run("offset plus length wraps", func(t *testing.T) {
		// ReadRes carries a 32-bit DataLength, so offset+length can overflow a
		// naive uint32 addition and slip past a guard that does not widen.
		res := ReadRes{Header: h, StructureSize: 17, Buffer: pat(16, 0xd0)}
		rb, err := res.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		rb[headerSize+2] = 0xff // DataOffset
		for i := headerSize + 4; i < headerSize+8; i++ {
			rb[i] = 0xff // DataLength
		}
		var got ReadRes
		if err := got.UnmarshalBinary(rb); err == nil {
			t.Fatal("expected an error for an offset+length that wraps")
		}
	})

	t.Run("short buffer", func(t *testing.T) {
		var got TreeConnectReq
		if err := got.UnmarshalBinary(buf[:headerSize+2]); err == nil {
			t.Fatal("expected an error for a truncated PDU")
		}
	})
}

// TestRoundTrip checks that each decoder recovers what its encoder emitted —
// something the reflection engine explicitly could not manage for every struct
// ("many of the structs that can be serialized correctly cannot be
// deserialized and the other way around").
func TestRoundTrip(t *testing.T) {
	h := goldenHeader()

	t.Run("Header", func(t *testing.T) {
		buf, err := h.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		var got Header
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if got.MessageID != h.MessageID || got.TreeID != h.TreeID ||
			got.SessionID != h.SessionID || got.Command != h.Command ||
			got.Credits != h.Credits || got.CreditCharge != h.CreditCharge ||
			got.Flags != h.Flags || got.Status != h.Status ||
			got.NextCommand != h.NextCommand || got.Reserved != h.Reserved {
			t.Errorf("header fields not recovered:\n got %+v\nwant %+v", got, h)
		}
		if !bytes.Equal(got.Signature, h.Signature) {
			t.Errorf("Signature = %x, want %x", got.Signature, h.Signature)
		}
	})

	t.Run("TransformHeader", func(t *testing.T) {
		in := TransformHeader{
			ProtcolID: 0x424d53fd, Signature: pat(16, 1), Nonce: pat(16, 0x20),
			OriginalMessageSize: 0x1000, Flags: 1, SessionId: 0x1122334455667788,
		}
		buf, err := in.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		if len(buf) != transformHeaderSize {
			t.Fatalf("marshaled %d bytes, want %d", len(buf), transformHeaderSize)
		}
		var got TransformHeader
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if got.SessionId != in.SessionId || got.OriginalMessageSize != in.OriginalMessageSize ||
			got.Flags != in.Flags || !bytes.Equal(got.Nonce, in.Nonce) {
			t.Errorf("not recovered:\n got %+v\nwant %+v", got, in)
		}
	})

	t.Run("NegotiateRes with contexts", func(t *testing.T) {
		picIn := PreauthIntegrityContext{
			HashAlgorithmCount: 1,
			HashAlgorithms:     []uint16{SHA512},
			SaltLength:         32,
			Salt:               pat(32, 0x10),
		}
		picBuf, err := picIn.MarshalBinary()
		if err != nil {
			t.Fatalf("pic MarshalBinary: %v", err)
		}
		ecIn := EncryptionContext{CipherCount: 2, Ciphers: []uint16{AES128GCM, AES128CCM}}
		ecBuf, err := ecIn.MarshalBinary()
		if err != nil {
			t.Fatalf("ec MarshalBinary: %v", err)
		}
		in := NegotiateRes{
			Header: h, StructureSize: 65, DialectRevision: DialectSmb_3_1_1,
			ServerGuid: pat(16, 0x30),
			SecurityBlob: &gss.NegTokenInit{
				OID:  gss.SpnegoOid,
				Data: gss.NegTokenInitData{MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid}},
			},
			NegotiateContextCount: 2,
			ContextList: []NegContext{
				{
					ContextType: PreauthIntegrityCapabilities,
					DataLength:  uint16(len(picBuf)),
					Data:        picBuf,
				},
				{
					ContextType: EncryptionCapabilities,
					DataLength:  uint16(len(ecBuf)),
					Data:        ecBuf,
				},
			},
		}
		buf, err := in.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		var got NegotiateRes
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if got.DialectRevision != in.DialectRevision {
			t.Errorf("DialectRevision = %#x", got.DialectRevision)
		}
		if len(got.ContextList) != 2 {
			t.Fatalf("recovered %d contexts, want 2", len(got.ContextList))
		}
		if got.ContextList[0].ContextType != PreauthIntegrityCapabilities ||
			got.ContextList[1].ContextType != EncryptionCapabilities {
			t.Errorf("context types = %d, %d", got.ContextList[0].ContextType, got.ContextList[1].ContextType)
		}
		var picOut PreauthIntegrityContext
		if err := picOut.UnmarshalBinary(got.ContextList[0].Data); err != nil {
			t.Fatalf("pic UnmarshalBinary: %v", err)
		}
		if !bytes.Equal(picOut.Salt, picIn.Salt) {
			t.Errorf("Salt = %x, want %x", picOut.Salt, picIn.Salt)
		}
		var ecOut EncryptionContext
		if err := ecOut.UnmarshalBinary(got.ContextList[1].Data); err != nil {
			t.Fatalf("ec UnmarshalBinary: %v", err)
		}
		if len(ecOut.Ciphers) != 2 || ecOut.Ciphers[0] != AES128GCM {
			t.Errorf("Ciphers = %v", ecOut.Ciphers)
		}
		if got.SecurityBlob == nil || len(got.SecurityBlob.Data.MechTypes) != 1 {
			t.Errorf("SecurityBlob not recovered: %+v", got.SecurityBlob)
		}
	})

	t.Run("FileBothDirectoryInformationStruct", func(t *testing.T) {
		in := FileBothDirectoryInformationStruct{
			NextEntryOffset: 104, EndOfFile: 0x800, FileAttributes: 0x20,
			ShortName: pat(24, 0), FileName: unicode.ToUnicode("test.txt"),
		}
		buf, err := in.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		var got FileBothDirectoryInformationStruct
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if !bytes.Equal(got.FileName, in.FileName) {
			t.Errorf("FileName = %x, want %x", got.FileName, in.FileName)
		}
		if got.NextEntryOffset != in.NextEntryOffset || got.EndOfFile != in.EndOfFile {
			t.Errorf("fields not recovered: %+v", got)
		}
	})

	t.Run("SMB1Header", func(t *testing.T) {
		in := SMB1Header{
			Protocol: []byte(ProtocolSmb), Command: SMB1CommandNegotiate,
			Flags: 0x18, Flags2: 0xc801, SecurityFeatures: make([]byte, 8), TID: 0xffff,
		}
		buf, err := in.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary: %v", err)
		}
		if len(buf) != smb1HeaderSize {
			t.Fatalf("marshaled %d bytes, want %d", len(buf), smb1HeaderSize)
		}
		var got SMB1Header
		if err := got.UnmarshalBinary(buf); err != nil {
			t.Fatalf("UnmarshalBinary: %v", err)
		}
		if got.Command != in.Command || got.Flags2 != in.Flags2 || got.TID != in.TID {
			t.Errorf("not recovered: %+v", got)
		}
	})
}

// TestAppendFixedNormalizesLength pins the padding/truncation rule for
// fixed-width fields: a caller supplying a short FileId can no longer shift
// every following field on the wire.
func TestAppendFixedNormalizesLength(t *testing.T) {
	h := goldenHeader()
	for _, n := range []int{0, 8, 16, 24} {
		req := CloseReq{Header: h, StructureSize: 24, FileId: pat(n, 1)}
		buf, err := req.MarshalBinary()
		if err != nil {
			t.Fatalf("FileId of %d bytes: MarshalBinary: %v", n, err)
		}
		if want := headerSize + closeReqBodySize; len(buf) != want {
			t.Errorf("FileId of %d bytes produced a %d-byte PDU, want %d", n, len(buf), want)
		}
	}
}

// TestNegContextListAlignment pins MS-SMB2 §3.3.5.4: consecutive negotiate
// contexts start on 8-byte boundaries, and the last one carries no trailing pad.
//
// The alignment used to be the caller's job — each NegContext carried a Padd
// slice the assembling code had to size, and the final one had to be explicitly
// cleared or the reply ended with stray zeros. It is now derived from position,
// so a caller cannot get it wrong.
func TestNegContextListAlignment(t *testing.T) {
	// DataLength 6 → an 14-byte context, which is not a multiple of 8, so the
	// next context must be preceded by 2 bytes of padding.
	contexts := []NegContext{
		{ContextType: 1, Data: pat(6, 0xa0)},
		{ContextType: 2, Data: pat(6, 0xb0)},
		{ContextType: 3, Data: pat(6, 0xc0)},
	}
	buf, err := marshalNegContextList(contexts)
	if err != nil {
		t.Fatalf("marshalNegContextList: %v", err)
	}
	// 14 + 2 pad + 14 + 2 pad + 14 = 46; no tail after the last context.
	if len(buf) != 46 {
		t.Fatalf("marshaled %d bytes, want 46 (14 + pad2 + 14 + pad2 + 14)", len(buf))
	}
	for i, want := range []int{0, 16, 32} {
		if got := int(buf[want]); got != i+1 {
			t.Errorf("context %d: ContextType at offset %d = %d, want %d", i, want, got, i+1)
		}
		if want%8 != 0 {
			t.Errorf("context %d starts at offset %d, which is not 8-byte aligned", i, want)
		}
	}
	// The gap bytes must be zero padding, not leftover data.
	for _, gap := range []int{14, 15, 30, 31} {
		if buf[gap] != 0 {
			t.Errorf("alignment pad at offset %d = 0x%02x, want 0", gap, buf[gap])
		}
	}

	// And the decoder must walk the same layout back.
	var out []NegContext
	off := 0
	for i := 0; i < 3; i++ {
		var ctx NegContext
		if err := ctx.UnmarshalBinary(buf[off:]); err != nil {
			t.Fatalf("context %d: UnmarshalBinary: %v", i, err)
		}
		out = append(out, ctx)
		off += ctx.NegContextSize()
	}
	for i := range out {
		if out[i].ContextType != uint16(i+1) {
			t.Errorf("recovered context %d has type %d", i, out[i].ContextType)
		}
		if !bytes.Equal(out[i].Data, contexts[i].Data) {
			t.Errorf("recovered context %d data = %x, want %x", i, out[i].Data, contexts[i].Data)
		}
	}
}
