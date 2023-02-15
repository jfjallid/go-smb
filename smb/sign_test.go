package smb

import (
	"bytes"
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
	s.signer, err = cmac.New(signingKey)
	if err != nil {
		t.Fatal(err)
	}

	s.verifier, err = cmac.New(signingKey)
	if err != nil {
		t.Fatal(err)
	}

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
