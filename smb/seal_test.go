package smb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"

	"testing"
)

func TestSeal(t *testing.T) {
	s := Session{}
	sessionKey, err := hex.DecodeString("7786b3244dc6c9a2fe248f283d1bfd9c")
	if err != nil {
		t.Fatal(err)
	}

	preauth, err := hex.DecodeString("c43c196e433c1af4b9851781b5d75b9a88a9c906ab3ad91a5534eae1f5f1bee8e40123d01c1e6e66e7de85b8a3fe5b259ec601643a12d77da2766d3411d72b44")
	if err != nil {
		t.Fatal(err)
	}

	pkt, err := hex.DecodeString("fe534d424000010000000000030001000800000000000000030000000000000000000000000000002d00000000f4000073d393583485c691b5a2c3c247a30af60900000048002e005c005c004400450053004b0054004f0050002d00410049004700300043003100440032005c004900500043002400")
	if err != nil {
		t.Fatal(err)
	}

	encPkt, err := hex.DecodeString("fd534d423dc67abf69d28813787809d56b45ba1fa0e51adb8ef5a1990446dfa30000000076000000000001000000000000000000a072f47625bc2bf582258bd85f4e5f216052bf7e5d209beb5b50065205c347e0bbb4caac101ef4d3769233b436f4b270c43f15f067dedbe3fdacf9595ce16d3851f013f22972277bae3bf5acee4591d16004880c2b90c3c2ccbfefb94f8525e814e4c42570e40d2af1e75ef90350b17c85c8d359a48c")
	if err != nil {
		t.Fatal(err)
	}

	decryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), preauth, 128)
	encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), preauth, 128)

	ciph, err := aes.NewCipher(encryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
	if err != nil {
		t.Fatal(err)
	}

	ciph, err = aes.NewCipher(decryptionKey)
	if err != nil {
		t.Fatal(err)
	}

	s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := s.decrypt(encPkt)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, plaintext) {
		t.Error("Fail")
	}

	ciphertext, err := s.encrypt(pkt)
	if err != nil {
		t.Fatal(err)
	}

	plaintext2, err := s.decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(pkt, plaintext2) {
		t.Error("Fail")
	}
}
