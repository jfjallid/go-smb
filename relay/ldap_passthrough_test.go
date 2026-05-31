// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay

import (
	"context"
	"net"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TestLDAPPassthroughSpoofsBind verifies the central feature: a BindRequest
// from the SOCKS-side client is answered locally with a synthetic
// BindResponse {resultCode=success}, without touching the upstream socket.
func TestLDAPPassthroughSpoofsBind(t *testing.T) {
	localCli, localSrv := net.Pipe()
	defer localCli.Close()
	defer localSrv.Close()
	upCli, upSrv := net.Pipe()
	defer upCli.Close()
	defer upSrv.Close()

	up := &ldapUpstream{Target: Target{Protocol: ProtoLDAP, Host: "x:389"}, conn: upCli, nextMessageID: 2}
	ps := &pooledSession{Target: "x:389", LDAP: up}

	p := &LDAPPassthrough{Local: localSrv, Target: "x:389", Upstream: ps}
	doneCh := make(chan error, 1)
	go func() { doneCh <- p.Run(context.Background()) }()

	// Client sends BindRequest (simple bind, empty creds — content is
	// irrelevant since the passthrough spoofs the response without looking).
	bindReq := buildBindRequestEnvelope(1, "")
	if _, err := localCli.Write(bindReq); err != nil {
		t.Fatalf("write bind: %v", err)
	}

	// Read the response back. Expect BindResponse(success) with the same
	// messageID.
	_ = localCli.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	resp, err := ber.ReadPacket(localCli)
	if err != nil {
		t.Fatalf("read bind response: %v", err)
	}
	id, opTag, err := parseLDAPMessage(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if id != 1 {
		t.Errorf("response messageID = %d, want 1", id)
	}
	if opTag != ber.Tag(ldapAppBindResponse) {
		t.Errorf("response op tag = %d, want %d", opTag, ldapAppBindResponse)
	}
	code, _, _, err := parseBindResultCode(resp)
	if err != nil {
		t.Fatalf("parseBindResultCode: %v", err)
	}
	if code != ldapResultSuccess {
		t.Errorf("resultCode = %d, want 0", code)
	}

	// Sanity: nothing should have been written to the upstream socket.
	_ = upSrv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	n, _ := upSrv.Read(buf)
	if n > 0 {
		t.Errorf("upstream socket saw %d bytes during bind spoof", n)
	}

	// Closing the local side terminates the loop cleanly.
	localCli.Close()
	select {
	case <-doneCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not exit after local close")
	}
}

// TestLDAPPassthroughForwardsSearchWithIDRewrite verifies the forwarding path:
// a non-bind operation (Search) is forwarded to the upstream with a rewritten
// MessageID, and the upstream's response is forwarded back with the original
// local MessageID. The continuation-tag handling is exercised by a single
// SearchResultDone (no SearchResultEntry needed for this test).
func TestLDAPPassthroughForwardsSearchWithIDRewrite(t *testing.T) {
	localCli, localSrv := net.Pipe()
	defer localCli.Close()
	defer localSrv.Close()
	upCli, upSrv := net.Pipe()
	defer upCli.Close()
	defer upSrv.Close()

	up := &ldapUpstream{Target: Target{Protocol: ProtoLDAP, Host: "x:389"}, conn: upCli, nextMessageID: 2}
	ps := &pooledSession{Target: "x:389", LDAP: up}
	p := &LDAPPassthrough{Local: localSrv, Target: "x:389", Upstream: ps}

	go p.Run(context.Background())

	// Mock upstream: read one request, answer with SearchResultDone.
	upDone := make(chan struct{})
	var upReqID int64
	go func() {
		defer close(upDone)
		req, err := ber.ReadPacket(upSrv)
		if err != nil {
			return
		}
		id, _, err := parseLDAPMessage(req)
		if err != nil {
			return
		}
		upReqID = id
		// Write SearchResultDone with the matching upstream id.
		resp := buildSearchResultDoneEnvelope(id)
		_, _ = upSrv.Write(resp)
	}()

	// Client sends SearchRequest with localID = 1.
	searchReq := buildSearchRequestEnvelope(1)
	if _, err := localCli.Write(searchReq); err != nil {
		t.Fatalf("write search: %v", err)
	}

	// Read the response on the local socket.
	_ = localCli.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp, err := ber.ReadPacket(localCli)
	if err != nil {
		t.Fatalf("read search response: %v", err)
	}
	id, opTag, err := parseLDAPMessage(resp)
	if err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if id != 1 {
		t.Errorf("local-side response messageID = %d, want 1 (original)", id)
	}
	if opTag != 5 { // SearchResultDone
		t.Errorf("response op tag = %d, want 5", opTag)
	}

	<-upDone
	// The forwarded request must have had a rewritten messageID — upstream's
	// nextMessageID starts at 2 (bind used 1, 2), so the rewrite assigns 3.
	if upReqID != 3 {
		t.Errorf("upstream observed messageID = %d, want 3 (after rewrite)", upReqID)
	}
	localCli.Close()
}

// TestLDAPPassthroughDropsUnbindWithoutTouchingUpstream verifies that an
// UnbindRequest from the SOCKS-side closes the local conn but leaves the
// upstream alive — the pinned upstream is shared across SOCKS connections so
// we must never forward Unbind.
func TestLDAPPassthroughDropsUnbindWithoutTouchingUpstream(t *testing.T) {
	localCli, localSrv := net.Pipe()
	defer localCli.Close()
	defer localSrv.Close()
	upCli, upSrv := net.Pipe()
	defer upCli.Close()
	defer upSrv.Close()

	up := &ldapUpstream{Target: Target{Protocol: ProtoLDAP, Host: "x:389"}, conn: upCli, nextMessageID: 2}
	ps := &pooledSession{Target: "x:389", LDAP: up}
	p := &LDAPPassthrough{Local: localSrv, Target: "x:389", Upstream: ps}
	doneCh := make(chan error, 1)
	go func() { doneCh <- p.Run(context.Background()) }()

	// Send Unbind.
	unbind := buildUnbindRequestEnvelope(1)
	if _, err := localCli.Write(unbind); err != nil {
		t.Fatalf("write unbind: %v", err)
	}

	// Run should exit cleanly.
	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("Run returned error after Unbind: %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not exit after Unbind")
	}

	// Upstream socket must not have been written to.
	_ = upSrv.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := upSrv.Read(buf)
	if n > 0 {
		t.Errorf("upstream saw %d bytes after Unbind; got=%x err=%v", n, buf[:n], err)
	}
	if up.IsClosed() {
		t.Errorf("Unbind from SOCKS client closed pinned upstream — must be left alive")
	}
}

// --- helpers ---

func buildBindRequestEnvelope(messageID int64, dn string) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindRequest), nil, "BindRequest")
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(3), "Version"))
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "Name"))
	// Simple auth (context primitive tag 0) — empty password.
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, 0, nil, "simple")
	req.AppendChild(auth)
	env.AppendChild(req)
	return env.Bytes()
}

func buildSearchRequestEnvelope(messageID int64) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	// SearchRequest = [APPLICATION 3]
	req := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 3, nil, "SearchRequest")
	// baseObject, scope=0, derefAliases=0, sizeLimit=0, timeLimit=0,
	// typesOnly=false, filter=(objectClass=*), attributes={}
	req.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "baseObject"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "scope"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "derefAliases"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "sizeLimit"))
	req.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "timeLimit"))
	req.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, "typesOnly"))
	// filter = present "objectClass" ([CONTEXT 7] primitive octet string)
	filter := ber.Encode(ber.ClassContext, ber.TypePrimitive, 7, nil, "filter:present")
	filter.Data.Write([]byte("objectClass"))
	req.AppendChild(filter)
	req.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	env.AppendChild(req)
	return env.Bytes()
}

func buildSearchResultDoneEnvelope(messageID int64) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	// SearchResultDone = [APPLICATION 5]
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 5, nil, "SearchResultDone")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)
	return env.Bytes()
}

func buildUnbindRequestEnvelope(messageID int64) []byte {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	// UnbindRequest = [APPLICATION 2], NULL value (no content).
	req := ber.Encode(ber.ClassApplication, ber.TypePrimitive, ber.Tag(ldapAppUnbindRequest), nil, "UnbindRequest")
	env.AppendChild(req)
	return env.Bytes()
}

