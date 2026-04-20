package krb5ssp

import (
	"bytes"
	"testing"
)

func TestWrapDCERC4RoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef") // 16 bytes
	sizes := []int{1, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 64, 100, 255, 256, 1024}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(i & 0xff)
		}

		body, authValue, err := wrapDCERC4(key, plaintext, 0, true)
		if err != nil {
			t.Fatalf("wrapDCERC4 size=%d: %v", size, err)
		}
		if len(authValue) != wrapRC4AuthValueLen {
			t.Fatalf("authValue size=%d: got %d, want %d", size, len(authValue), wrapRC4AuthValueLen)
		}
		expectPad := (8 - (size % 8)) & 0x7
		if len(body) != size+expectPad {
			t.Fatalf("body size=%d: got %d, want %d", size, len(body), size+expectPad)
		}
		// TOK_ID at offset 13 is 0x0102 (LE) → bytes 0x02, 0x01
		if authValue[13] != 0x02 || authValue[14] != 0x01 {
			t.Fatalf("TOK_ID mismatch size=%d: %02x%02x", size, authValue[13], authValue[14])
		}

		recovered, err := unwrapDCERC4(key, body, authValue, 0, true)
		if err != nil {
			t.Fatalf("unwrapDCERC4 size=%d: %v", size, err)
		}
		if len(recovered) != size+expectPad {
			t.Fatalf("recovered size=%d: got %d, want %d", size, len(recovered), size+expectPad)
		}
		if !bytes.Equal(recovered[:size], plaintext) {
			t.Fatalf("round-trip mismatch size=%d", size)
		}
	}
}

func TestWrapDCERC4SequenceNumbers(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("Hello, DCERPC over RC4!")

	body1, auth1, err := wrapDCERC4(key, plaintext, 0, true)
	if err != nil {
		t.Fatalf("wrapDCERC4 seq=0: %v", err)
	}
	body2, auth2, err := wrapDCERC4(key, plaintext, 1, true)
	if err != nil {
		t.Fatalf("wrapDCERC4 seq=1: %v", err)
	}
	if bytes.Equal(body1, body2) {
		t.Fatal("identical body for different sequence numbers")
	}
	if bytes.Equal(auth1, auth2) {
		t.Fatal("identical authValue for different sequence numbers")
	}

	if _, err := unwrapDCERC4(key, body1, auth1, 0, true); err != nil {
		t.Fatalf("unwrap seq=0: %v", err)
	}
	if _, err := unwrapDCERC4(key, body2, auth2, 1, true); err != nil {
		t.Fatalf("unwrap seq=1: %v", err)
	}
	if _, err := unwrapDCERC4(key, body1, auth1, 99, true); err == nil {
		t.Fatal("expected seq mismatch failure")
	}
}

func TestWrapDCERC4TamperDetection(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("secret payload")

	body, authValue, err := wrapDCERC4(key, plaintext, 42, true)
	if err != nil {
		t.Fatalf("wrapDCERC4: %v", err)
	}

	// Flip a body byte → checksum mismatch.
	bad := make([]byte, len(body))
	copy(bad, body)
	bad[0] ^= 0xff
	if _, err := unwrapDCERC4(key, bad, authValue, 42, true); err == nil {
		t.Fatal("expected checksum failure on tampered body")
	}

	// Wrong direction filler → fails.
	if _, err := unwrapDCERC4(key, body, authValue, 42, false); err == nil {
		t.Fatal("expected failure with wrong initiator direction")
	}
}

func TestWrapDCERC4AcceptorDirection(t *testing.T) {
	key := []byte("0123456789abcdef")
	plaintext := []byte("from the acceptor")

	body, authValue, err := wrapDCERC4(key, plaintext, 7, false)
	if err != nil {
		t.Fatalf("wrapDCERC4 accept: %v", err)
	}
	recovered, err := unwrapDCERC4(key, body, authValue, 7, false)
	if err != nil {
		t.Fatalf("unwrapDCERC4 accept: %v", err)
	}
	if !bytes.Equal(recovered[:len(plaintext)], plaintext) {
		t.Fatal("acceptor round-trip mismatch")
	}
}

func TestWrapTokenRC4Overhead(t *testing.T) {
	sig, overhead := wrapTokenRC4Overhead()
	if sig != wrapRC4AuthValueLen {
		t.Fatalf("signature size: got %d, want %d", sig, wrapRC4AuthValueLen)
	}
	if overhead != wrapRC4MaxPad {
		t.Fatalf("encryption overhead: got %d, want %d", overhead, wrapRC4MaxPad)
	}
}
