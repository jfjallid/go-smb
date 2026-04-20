package krb5ssp

import (
	"testing"
)

func TestMICRC4RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef")
	sizes := []int{1, 3, 4, 5, 7, 8, 17, 64, 1024}
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i & 0xff)
		}

		token, err := getMICRC4(key, data, uint32(size), true)
		if err != nil {
			t.Fatalf("getMICRC4 size=%d: %v", size, err)
		}
		if len(token) != micRC4TokenLen {
			t.Fatalf("token size=%d: got %d, want %d", size, len(token), micRC4TokenLen)
		}
		// TOK_ID at offset 13 is 0x0101 (LE) → 0x01, 0x01
		if token[13] != 0x01 || token[14] != 0x01 {
			t.Fatalf("TOK_ID mismatch size=%d: %02x%02x", size, token[13], token[14])
		}
		if err := verifyMICRC4(key, data, token, uint32(size), true); err != nil {
			t.Fatalf("verifyMICRC4 size=%d: %v", size, err)
		}
	}
}

func TestMICRC4TamperDetection(t *testing.T) {
	key := []byte("0123456789abcdef")
	data := []byte("integrity-protected payload")

	token, err := getMICRC4(key, data, 5, true)
	if err != nil {
		t.Fatalf("getMICRC4: %v", err)
	}

	// Tampered data → checksum mismatch.
	bad := make([]byte, len(data))
	copy(bad, data)
	bad[0] ^= 0x80
	if err := verifyMICRC4(key, bad, token, 5, true); err == nil {
		t.Fatal("expected checksum failure on tampered data")
	}

	// Tampered token → checksum/seq mismatch.
	badTok := make([]byte, len(token))
	copy(badTok, token)
	badTok[30] ^= 0xff
	if err := verifyMICRC4(key, data, badTok, 5, true); err == nil {
		t.Fatal("expected failure on tampered token")
	}

	// Wrong seq fails.
	if err := verifyMICRC4(key, data, token, 6, true); err == nil {
		t.Fatal("expected seq mismatch failure")
	}

	// Wrong direction fails.
	if err := verifyMICRC4(key, data, token, 5, false); err == nil {
		t.Fatal("expected direction filler failure")
	}
}

func TestMICRC4AcceptorDirection(t *testing.T) {
	key := []byte("0123456789abcdef")
	data := []byte("signed from acceptor side")

	token, err := getMICRC4(key, data, 99, false)
	if err != nil {
		t.Fatalf("getMICRC4 accept: %v", err)
	}
	if err := verifyMICRC4(key, data, token, 99, false); err != nil {
		t.Fatalf("verifyMICRC4 accept: %v", err)
	}
}

func TestMICRC4Size(t *testing.T) {
	if micTokenRC4Size() != micRC4TokenLen {
		t.Fatalf("micTokenRC4Size: got %d, want %d", micTokenRC4Size(), micRC4TokenLen)
	}
}
