package krb5ssp

import (
	"bytes"
	"testing"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/gokrb5/v8/types"
)

// TestWrapDCERoundTrip verifies that WrapDCE and UnwrapDCE are inverse operations
// for various plaintext sizes using AES256.
func TestWrapDCERoundTrip(t *testing.T) {
	// AES256-CTS-HMAC-SHA1-96, keytype 18
	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"), // 32-byte key
	}

	sizes := []int{1, 4, 15, 16, 17, 31, 32, 33, 48, 63, 64, 100, 255, 256, 1024}
	for _, size := range sizes {
		plaintext := make([]byte, size)
		for i := range plaintext {
			plaintext[i] = byte(i & 0xFF)
		}

		body, authValue, err := WrapDCE(key, gss.KGUsageInitiatorSeal, plaintext, 0)
		if err != nil {
			t.Fatalf("WrapDCE failed for size %d: %v", size, err)
		}

		// Verify body length equals plaintext length
		if len(body) != size {
			t.Fatalf("WrapDCE body length mismatch for size %d: got %d, want %d", size, len(body), size)
		}

		// Verify authValue starts with WrapToken header (TOK_ID=0x0504)
		if len(authValue) < WrapTokenHdrLen {
			t.Fatalf("WrapDCE authValue too short for size %d: %d bytes", size, len(authValue))
		}
		if authValue[0] != 0x05 || authValue[1] != 0x04 {
			t.Fatalf("WrapDCE authValue TOK_ID mismatch for size %d: got %02x%02x, want 0504", size, authValue[0], authValue[1])
		}

		// Round-trip: UnwrapDCE should recover the original plaintext
		recovered, err := UnwrapDCE(key, gss.KGUsageInitiatorSeal, body, authValue, 0)
		if err != nil {
			t.Fatalf("UnwrapDCE failed for size %d: %v", size, err)
		}

		if !bytes.Equal(recovered, plaintext) {
			t.Fatalf("Round-trip failed for size %d: plaintext mismatch (got %d bytes, want %d bytes)", size, len(recovered), len(plaintext))
		}
	}
}

// TestWrapDCESequenceNumbers verifies that different sequence numbers produce
// different ciphertexts (due to the sequence number being part of the encrypted header).
func TestWrapDCESequenceNumbers(t *testing.T) {
	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	plaintext := []byte("Hello, DCERPC!")

	body1, auth1, err := WrapDCE(key, gss.KGUsageInitiatorSeal, plaintext, 0)
	if err != nil {
		t.Fatalf("WrapDCE seq=0 failed: %v", err)
	}

	body2, auth2, err := WrapDCE(key, gss.KGUsageInitiatorSeal, plaintext, 1)
	if err != nil {
		t.Fatalf("WrapDCE seq=1 failed: %v", err)
	}

	// Bodies should differ (different confounder + different sequence in encrypted header)
	if bytes.Equal(body1, body2) {
		t.Fatal("WrapDCE produced identical body for different sequence numbers")
	}

	// authValues should differ (different sequence in header + different encrypted data)
	if bytes.Equal(auth1, auth2) {
		t.Fatal("WrapDCE produced identical authValue for different sequence numbers")
	}

	// Both should unwrap correctly with matching sequence numbers
	recovered1, err := UnwrapDCE(key, gss.KGUsageInitiatorSeal, body1, auth1, 0)
	if err != nil {
		t.Fatalf("UnwrapDCE seq=0 failed: %v", err)
	}
	recovered2, err := UnwrapDCE(key, gss.KGUsageInitiatorSeal, body2, auth2, 1)
	if err != nil {
		t.Fatalf("UnwrapDCE seq=1 failed: %v", err)
	}

	if !bytes.Equal(recovered1, plaintext) || !bytes.Equal(recovered2, plaintext) {
		t.Fatal("Round-trip failed with different sequence numbers")
	}

	// Unwrap with wrong sequence number should fail
	_, err = UnwrapDCE(key, gss.KGUsageInitiatorSeal, body1, auth1, 99)
	if err == nil {
		t.Fatal("UnwrapDCE should fail with wrong sequence number")
	}
}

// TestWrapDCEFlags verifies the WrapToken header flags in authValue.
func TestWrapDCEFlags(t *testing.T) {
	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	plaintext := []byte("test data for flags check")

	_, authValue, err := WrapDCE(key, gss.KGUsageInitiatorSeal, plaintext, 42)
	if err != nil {
		t.Fatalf("WrapDCE failed: %v", err)
	}

	// Check Flags byte: should be Sealed | AcceptorSubkey = 0x06
	if authValue[2] != 0x06 {
		t.Fatalf("WrapToken Flags mismatch: got 0x%02x, want 0x06", authValue[2])
	}

	// Check Filler byte: should be 0xFF
	if authValue[3] != 0xFF {
		t.Fatalf("WrapToken Filler mismatch: got 0x%02x, want 0xFF", authValue[3])
	}

	// Check RRC: should be 28 (big-endian) for AES
	rrc := be.Uint16(authValue[6:8])
	if rrc != 28 {
		t.Fatalf("WrapToken RRC mismatch: got %d, want 28", rrc)
	}

	// Check SND_SEQ: should be 42 (big-endian)
	seq := be.Uint64(authValue[8:16])
	if seq != 42 {
		t.Fatalf("WrapToken SND_SEQ mismatch: got %d, want 42", seq)
	}
}

// TestWrapTokenOverhead verifies the signature size computation.
func TestWrapTokenOverhead(t *testing.T) {
	sigSize, overhead, err := WrapTokenOverhead(18) // AES256
	if err != nil {
		t.Fatalf("WrapTokenOverhead failed: %v", err)
	}

	// For AES: blockSize=16, hmac=12, rrc=28, maxPad=15
	// sigSize = WrapTokenHdrLen(16) + WrapTokenHdrLen(16) + rrc(28) + maxPad(15) = 75
	if sigSize != 75 {
		t.Fatalf("SignatureSize mismatch: got %d, want 75", sigSize)
	}

	// Encryption overhead should be 0 (body length = plaintext length)
	if overhead != 0 {
		t.Fatalf("EncryptionOverhead mismatch: got %d, want 0", overhead)
	}
}
