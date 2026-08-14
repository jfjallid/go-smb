// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package ntlmssp

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jfjallid/go-smb/smb/unicode"
)

func genpat(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return b
}

// TestMarshalGolden pins the NTLMSSP wire format to the bytes the reflection
// encoder produced before it was retired. Each expectation was captured from
// the old smb/encoder path, so a byte-level difference here means the
// hand-written marshaller changed what goes on the wire.
func TestMarshalGolden(t *testing.T) {
	hdr := Header{Signature: []byte(Signature), MessageType: TypeNtLmNegotiate}
	avs := AvPairSlice{
		{AvID: MsvAvNbDomainName, Value: unicode.ToUnicode("DOM")},
		{AvID: MsvAvNbComputerName, Value: unicode.ToUnicode("SRV")},
		{AvID: MsvAvEOL, Value: []byte{}},
	}

	type marshaller interface{ MarshalBinary() ([]byte, error) }

	tests := []struct {
		name string
		v    marshaller
		want string
	}{
		{"Header", &hdr, "4e544c4d5353500001000000"},
		{
			"AvPair",
			&AvPair{AvID: MsvAvNbDomainName, Value: unicode.ToUnicode("DOM")},
			"0200060044004f004d00",
		},
		{
			"AvPairSlice", &avs,
			"0200060044004f004d000100060053005200560000000000",
		},
		{
			"NegotiateEmpty",
			&Negotiate{
				Header:         hdr,
				NegotiateFlags: FlgNegUnicode | FlgNegNtLm | FlgNegVersion,
				Version:        0x0a0000000f000000,
			},
			"4e544c4d535350000100000001020002000000000000000000000000000000000000000f0000000a",
		},
		{
			"NegotiatePopulated",
			&Negotiate{
				Header:         hdr,
				NegotiateFlags: FlgNegUnicode | FlgNegNtLm | FlgNegOEMDomainSupplied | FlgNegOEMWorkstationSupplied,
				Version:        0x0a0000000f000000,
				DomainName:     []byte("DOMAIN"),
				Workstation:    []byte("WKSTN"),
			},
			"4e544c4d5353500001000000013200000600060028000000050005002e0000000000000f0000000a444f4d41494e574b53544e",
		},
		{
			// An empty-but-non-nil TargetInfo still gets a real offset (0x38);
			// an empty TargetName gets offset 0. The asymmetry is inherited.
			"ChallengeEmpty",
			&Challenge{
				Header:          Header{Signature: []byte(Signature), MessageType: TypeNtLmChallenge},
				NegotiateFlags:  FlgNegUnicode | FlgNegNtLm | FlgNegTargetInfo,
				ServerChallenge: 0x0102030405060708,
				TargetName:      []byte{},
				TargetInfo:      new(AvPairSlice),
			},
			"4e544c4d53535000020000000000000000000000010280000807060504030201" +
				"000000000000000000000000380000000000000000000000",
		},
		{
			"ChallengePopulated",
			&Challenge{
				Header:          Header{Signature: []byte(Signature), MessageType: TypeNtLmChallenge},
				NegotiateFlags:  FlgNegUnicode | FlgNegNtLm | FlgNegTargetInfo | FlgNegVersion,
				ServerChallenge: 0x0102030405060708,
				Version:         0x0a0000000f000000,
				TargetName:      unicode.ToUnicode("SRV"),
				TargetInfo:      &avs,
			},
			"4e544c4d535350000200000006000600380000000102800208070605040302010000000000000000" +
				"180018003e0000000000000f0000000a5300520056000200060044004f004d00010006005300520056000" +
				"0000000",
		},
		{
			"AuthenticateFull",
			&Authenticate{
				Header:                    Header{Signature: []byte(Signature), MessageType: TypeNtLmAuthenticate},
				NegotiateFlags:            FlgNegUnicode | FlgNegNtLm | FlgNegVersion | FlgNegKeyExch,
				Version:                   0x0a0000000f000000,
				MIC:                       genpat(16, 0x90),
				DomainName:                unicode.ToUnicode("DOM"),
				UserName:                  unicode.ToUnicode("user"),
				Workstation:               unicode.ToUnicode("WKS"),
				LmChallengeResponse:       genpat(24, 0x10),
				NtChallengeResponse:       genpat(48, 0x30),
				EncryptedRandomSessionKey: genpat(16, 0x70),
			},
			"4e544c4d5353500003000000180018007c00000030003000940000000600060058000000080008005e" +
				"0000000600060066000000100010006c000000010200420000000f0000000a909192939495969798999a9b" +
				"9c9d9e9f44004f004d00750073006500720057004b005300707172737475767778797a7b7c7d7e7f101112" +
				"131415161718191a1b1c1d1e1f2021222324252627303132333435363738393a3b3c3d3e3f404142434445" +
				"464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
		},
		{
			"AuthenticateAnonymous",
			&Authenticate{
				Header:         Header{Signature: []byte(Signature), MessageType: TypeNtLmAuthenticate},
				NegotiateFlags: FlgNegUnicode | FlgNegAnonymous,
			},
			"4e544c4d53535000030000000000000040000000000000004000000000000000" +
				"4000000000000000400000000000000040000000000000004000000001080000",
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

// TestNegotiateRoundTrip and TestChallengeRoundTrip check that the decoders
// recover what the encoders emitted, which the reflection engine could not do
// for every struct.
func TestNegotiateRoundTrip(t *testing.T) {
	in := Negotiate{
		Header:         Header{Signature: []byte(Signature), MessageType: TypeNtLmNegotiate},
		NegotiateFlags: FlgNegUnicode | FlgNegNtLm,
		Version:        0x0a0000000f000000,
		DomainName:     []byte("DOMAIN"),
		Workstation:    []byte("WKSTN"),
	}
	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var out Negotiate
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if !bytes.Equal(out.DomainName, in.DomainName) || !bytes.Equal(out.Workstation, in.Workstation) {
		t.Errorf("payloads not recovered: domain=%q workstation=%q", out.DomainName, out.Workstation)
	}
	if out.NegotiateFlags != in.NegotiateFlags || out.Version != in.Version {
		t.Errorf("flags/version not recovered: %#x / %#x", out.NegotiateFlags, out.Version)
	}
}

func TestChallengeRoundTrip(t *testing.T) {
	in := Challenge{
		Header:          Header{Signature: []byte(Signature), MessageType: TypeNtLmChallenge},
		NegotiateFlags:  FlgNegUnicode | FlgNegTargetInfo,
		ServerChallenge: 0x0102030405060708,
		TargetName:      unicode.ToUnicode("SRV"),
		TargetInfo: &AvPairSlice{
			{AvID: MsvAvNbDomainName, Value: unicode.ToUnicode("DOM")},
			{AvID: MsvAvEOL, Value: []byte{}},
		},
	}
	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	var out Challenge
	if err := out.UnmarshalBinary(buf); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}
	if out.ServerChallenge != in.ServerChallenge {
		t.Errorf("ServerChallenge = %#x", out.ServerChallenge)
	}
	if !bytes.Equal(out.TargetName, in.TargetName) {
		t.Errorf("TargetName = %q", out.TargetName)
	}
	if out.TargetInfo == nil || len(*out.TargetInfo) != 2 {
		t.Fatalf("TargetInfo not recovered: %v", out.TargetInfo)
	}
	if (*out.TargetInfo)[0].AvID != MsvAvNbDomainName {
		t.Errorf("first AvPair = %d", (*out.TargetInfo)[0].AvID)
	}
}

// TestChallengeRejectsOutOfRangePayload ensures a hostile CHALLENGE cannot
// drive an out-of-bounds slice: the offsets are server-controlled and this
// decoder runs before authentication completes.
func TestChallengeRejectsOutOfRangePayload(t *testing.T) {
	in := Challenge{
		Header:     Header{Signature: []byte(Signature), MessageType: TypeNtLmChallenge},
		TargetName: unicode.ToUnicode("SRV"),
		TargetInfo: new(AvPairSlice),
	}
	buf, err := in.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// Point TargetInfo past the end of the message with a huge length.
	buf[40], buf[41] = 0xff, 0xff
	buf[44], buf[45], buf[46], buf[47] = 0xff, 0xff, 0xff, 0xff
	var out Challenge
	if err := out.UnmarshalBinary(buf); err == nil {
		t.Fatal("expected an error for an out-of-range TargetInfo")
	}
}
