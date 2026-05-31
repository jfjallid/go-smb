package smb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/jfjallid/go-smb/smb/crypto/cmac"

	"testing"
)

func TestSign(t *testing.T) {
	s := Session{}
	sessionKey, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned packet
	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4000000000000000000000000000000000900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}

	// Expected signature
	signature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}

	signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"), 128)
	cs, err := cmac.New(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	cv, err := cmac.New(signingKey)
	if err != nil {
		t.Fatal(err)
	}
	s.signer = newHashSigner(cs)
	s.verifier = newHashVerifier(cv)

	// Test sign function
	signedPkt, err := s.sign(pkt)
	if err != nil {
		t.Fatal(err)
	}
	pktSig := make([]byte, 16)
	copy(pktSig, signedPkt[48:64])
	if !bytes.Equal(signature, pktSig) {
		t.Error("Fail")
	}

	// Test verify function
	if !s.verify(signedPkt) {
		t.Error("Fail")
	}
}

func TestSignHmacSha256RoundTrip(t *testing.T) {
	s := Session{}
	key := bytes.Repeat([]byte{0xa5}, 16)
	s.signer = newHashSigner(hmac.New(sha256.New, key))
	s.verifier = newHashVerifier(hmac.New(sha256.New, key))

	pkt := make([]byte, 80)
	pkt[0], pkt[1], pkt[2], pkt[3] = 0xfe, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(pkt[4:6], 64) // StructureSize
	binary.LittleEndian.PutUint16(pkt[12:14], CommandCreate)
	binary.LittleEndian.PutUint64(pkt[24:32], 7)

	signed, err := s.sign(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !s.verify(signed) {
		t.Fatal("HMAC-SHA256 sign/verify round-trip failed")
	}
}

func TestGmacNonce(t *testing.T) {
	pkt := make([]byte, 64)
	binary.LittleEndian.PutUint64(pkt[24:32], 0x123456789abcdef0)
	binary.LittleEndian.PutUint16(pkt[12:14], CommandCreate)

	// Client direction, non-cancel
	got := gmacNonce(pkt, false)
	want := []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("client nonce mismatch:\n  got  %x\n  want %x", got, want)
	}

	// Server direction
	got = gmacNonce(pkt, true)
	want = []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x01, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("server nonce mismatch:\n  got  %x\n  want %x", got, want)
	}

	// CANCEL request, client direction (penultimate bit set)
	binary.LittleEndian.PutUint16(pkt[12:14], CommandCancel)
	got = gmacNonce(pkt, false)
	want = []byte{0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x02, 0x00, 0x00, 0x00}
	if !bytes.Equal(got, want) {
		t.Errorf("client+cancel nonce mismatch:\n  got  %x\n  want %x", got, want)
	}
}

func TestGmacSignSelfVerify(t *testing.T) {
	key := bytes.Repeat([]byte{0xcc}, 16)
	gcm, err := newAESGMAC(key)
	if err != nil {
		t.Fatal(err)
	}

	pkt := make([]byte, 100)
	pkt[0], pkt[1], pkt[2], pkt[3] = 0xfe, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(pkt[12:14], CommandCreate)
	binary.LittleEndian.PutUint64(pkt[24:32], 42)

	signer := &gmacSigner{gcm: gcm}
	sig := signer.Sign(pkt)
	if len(sig) != 16 {
		t.Fatalf("expected 16-byte sig, got %d", len(sig))
	}

	// Re-verify with the same (client) direction nonce: must validate.
	nonce := gmacNonce(pkt, false)
	if _, err := gcm.Open(nil, nonce, sig, pkt); err != nil {
		t.Fatalf("client self-verify failed: %v", err)
	}

	// Server-direction verifier on a client-signed tag MUST fail (different
	// nonce, so GMAC tag won't match).
	v := &gmacVerifier{gcm: gcm}
	if v.Verify(pkt, sig) {
		t.Error("server-direction verifier accepted a client-signed tag")
	}
}

func TestSign2(t *testing.T) {
	key := []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}
	signer, err := cmac.New(key)
	if err != nil {
		t.Fatal(err)
	}
	// Message from RFC4493
	m, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
	signer.Reset()
	_, err = signer.Write(m)
	if err != nil {
		t.Fatal(err)
	}
	mac := signer.Sum(nil)
	// Correct mac from RFC4493
	MAC, _ := hex.DecodeString("51f0bebf7e3b9d92fc49741779363cfe")
	if !bytes.Equal(mac, MAC) {
		t.Error("Fail")
	}
}
