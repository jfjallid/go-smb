package ntlmssp

import (
	"encoding/binary"
	"testing"

	"github.com/jfjallid/go-smb/smb/encoder"
)

// buildChallengeHeader lays out the 56-byte fixed portion of a CHALLENGE message
// with an empty TargetName and the given TargetInfo length/offset, so tests can
// drive malicious offset/length combinations.
func buildChallengeHeader(targetInfoLen uint16, targetInfoOffset uint32) []byte {
	buf := make([]byte, 56)
	copy(buf[0:8], []byte(Signature))
	binary.LittleEndian.PutUint32(buf[8:12], TypeNtLmChallenge)
	// TargetName: len 0, offset 0
	binary.LittleEndian.PutUint32(buf[20:24], FlgNegTargetInfo|FlgNegUnicode)
	binary.LittleEndian.PutUint16(buf[40:42], targetInfoLen)
	binary.LittleEndian.PutUint16(buf[42:44], targetInfoLen)
	binary.LittleEndian.PutUint32(buf[44:48], targetInfoOffset)
	return buf
}

// TestChallengeMaliciousTargetInfo ensures a CHALLENGE message from a malicious
// server with an out-of-range or malformed TargetInfo offset/length is rejected
// with an error instead of panicking on an out-of-bounds slice. This path is
// reached on every NTLM authentication (SMB, LDAP, DCERPC).
func TestChallengeMaliciousTargetInfo(t *testing.T) {
	cases := []struct {
		name          string
		targetInfoLen uint16
		offset        uint32
		extra         []byte
	}{
		{"offset past end", 16, 0xFFFF, nil},
		{"length past end", 16, 56, nil}, // offset valid, but 16 bytes don't exist
		{
			// offset/length in range, but the AvPair claims a Value longer than the
			// window — must not underflow the loop counter.
			name:          "malformed avpair length",
			targetInfoLen: 4,
			offset:        56,
			extra:         []byte{0x07, 0x00, 0xff, 0xff}, // AvID=7, AvLen=0xffff
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buf := buildChallengeHeader(tc.targetInfoLen, tc.offset)
			buf = append(buf, tc.extra...)

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unmarshal panicked on malicious CHALLENGE: %v", r)
				}
			}()

			chall := NewChallenge()
			if err := encoder.Unmarshal(buf, &chall); err == nil {
				t.Fatalf("expected error for malicious TargetInfo, got nil")
			}
		})
	}
}

// TestChallengeValidTargetInfo confirms the hardened AvPairSlice path still
// accepts a well-formed CHALLENGE with a single AV_PAIR.
func TestChallengeValidTargetInfo(t *testing.T) {
	// One AvPair: AvID=2 (MsvAvNbDomainName), AvLen=4, Value="AB\x00\x00" -> 8 bytes,
	// followed by the MsvAvEOL terminator (AvID=0, AvLen=0) -> 4 bytes. Total 12.
	avPairs := []byte{
		0x02, 0x00, 0x04, 0x00, 'A', 0x00, 'B', 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	buf := buildChallengeHeader(uint16(len(avPairs)), 56)
	buf = append(buf, avPairs...)

	chall := NewChallenge()
	if err := encoder.Unmarshal(buf, &chall); err != nil {
		t.Fatalf("unexpected error unmarshaling valid CHALLENGE: %v", err)
	}
	if chall.TargetInfo == nil || len(*chall.TargetInfo) != 2 {
		t.Fatalf("expected 2 AV pairs, got %v", chall.TargetInfo)
	}
}
