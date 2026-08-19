package smb

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestNewNegotiateReqOffersSMB30Family(t *testing.T) {
	s := &Session{options: Options{}, clientGuid: make([]byte, 16)}
	req, err := s.NewNegotiateReq()
	if err != nil {
		t.Fatalf("NewNegotiateReq: %v", err)
	}

	want := []uint16{
		DialectSmb_3_1_1,
		DialectSmb_3_0_2,
		DialectSmb_3_0,
		DialectSmb_2_1,
		DialectSmb_2_0_2,
	}
	if !reflect.DeepEqual(req.Dialects, want) {
		t.Fatalf("dialects = %#v, want %#v", req.Dialects, want)
	}
}

func TestSMB30Crypto(t *testing.T) {
	key, err := hex.DecodeString("726d4c454e63516446695457664e5042")
	if err != nil {
		t.Fatal(err)
	}

	conn := &Connection{Session: &Session{options: Options{}}}
	conn.dialect = DialectSmb_3_0
	conn.supportsEncryption = true
	conn.cipherId = AES128CCM
	conn.exportedSessionKey = key
	if err := conn.setupSMB30Crypto(key); err != nil {
		t.Fatalf("setupSMB30Crypto: %v", err)
	}

	// Known SMB 3.0 AES-CMAC signing vector.
	pkt, err := hex.DecodeString("fe534d42400001000000000001007f00090000000000000003000000000000000000000000000000020000007bfba3f4000000000000000000000000000000000900000048000900a1073005a0030a0100")
	if err != nil {
		t.Fatal(err)
	}
	wantSignature, err := hex.DecodeString("041393e756a048c9092c4e52dc703719")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := conn.sign(pkt)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !bytes.Equal(signed[48:64], wantSignature) {
		t.Fatalf("signature = %x, want %x", signed[48:64], wantSignature)
	}
	if !conn.verify(signed) {
		t.Fatal("SMB 3.0 signature did not verify")
	}

	if conn.encrypter == nil || conn.decrypter == nil {
		t.Fatal("SMB 3.0 encryption state was not initialized")
	}
	if conn.encrypter.NonceSize() != 11 || conn.decrypter.NonceSize() != 11 {
		t.Fatalf("SMB 3.0 nonce sizes = %d/%d, want 11/11", conn.encrypter.NonceSize(), conn.decrypter.NonceSize())
	}
	// ApplicationKey vector generated with Impacket's KDF_CounterMode.
	wantApplicationKey, err := hex.DecodeString("3f69978aac7d4dec83d3e637ce4c0c2a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(conn.GetSessionKey(), wantApplicationKey) {
		t.Fatalf("SMB 3.0 GetSessionKey = %x, want ApplicationKey %x", conn.GetSessionKey(), wantApplicationKey)
	}
	if bytes.Equal(conn.GetSessionKey(), key) {
		t.Fatal("SMB 3.0 GetSessionKey incorrectly returned the exported authentication key")
	}

	// The server uses the opposite directional keys.
	server := &Session{
		encrypter: conn.decrypter,
		decrypter: conn.encrypter,
	}
	payload := make([]byte, 80)
	copy(payload, ProtocolSmb2)
	wire, err := conn.encrypt(payload)
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	plain, err := server.decrypt(wire)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatal("server decrypted payload differs from client plaintext")
	}

	wire, err = server.encrypt(payload)
	if err != nil {
		t.Fatalf("server encrypt: %v", err)
	}
	plain, err = conn.decrypt(wire)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if !bytes.Equal(plain, payload) {
		t.Fatal("client decrypted payload differs from server plaintext")
	}
}
