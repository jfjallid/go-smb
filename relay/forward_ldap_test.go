// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/jfjallid/go-smb/ntlmssp"
)

// TestEncodeBindRequestShape verifies the BER shape of the BindRequest we
// emit: a SEQUENCE of (version=3, name="", auth choice carrying the NTLMSSP
// token). The auth choice's class/tag determines phase: TagEnumerated for
// NEGOTIATE, TagEmbeddedPDV for AUTHENTICATE — same convention goldap uses
// for the AD sicily extension.
func TestEncodeBindRequestShape(t *testing.T) {
	ntlmTok := []byte("NTLMSSP\x00\x01stub")
	for _, tag := range []ber.Tag{ldapAuthNTLMNegotiate, ldapAuthNTLMAuthenticate} {
		req := encodeBindRequest(tag, ntlmTok)
		if req.ClassType != ber.ClassApplication || req.Tag != ber.Tag(ldapAppBindRequest) {
			t.Errorf("BindRequest envelope class/tag = %d/%d, want app/0", req.ClassType, req.Tag)
		}
		if len(req.Children) != 3 {
			t.Fatalf("BindRequest children = %d, want 3", len(req.Children))
		}
		version := req.Children[0].Value
		if v, ok := version.(int64); !ok || v != 3 {
			t.Errorf("version = %v, want int64(3)", version)
		}
		name := req.Children[1].Value
		if s, ok := name.(string); !ok || s != "" {
			t.Errorf("name = %v, want empty string", name)
		}
		auth := req.Children[2]
		if auth.ClassType != ber.ClassContext || auth.Tag != tag {
			t.Errorf("auth class/tag = %d/%d, want context/%d", auth.ClassType, auth.Tag, tag)
		}
		// The NTLM token bytes are stored in the packet's Data buffer.
		if got := auth.Data.Bytes(); !bytes.Equal(got, ntlmTok) {
			t.Errorf("auth data = %x, want %x", got, ntlmTok)
		}
	}
}

// TestParseBindNegotiateResponseSicilyMatchedDN parses the AD sicily NTLM
// layout: the CHALLENGE is packed in matchedDN (Children[1] of BindResponse)
// rather than in the standard serverSaslCreds [CONTEXT 7] slot. resultCode is
// 14 (saslBindInProgress) in this example but could equally be 0 — sicily
// servers don't always set it to 14, so the parser ignores resultCode when a
// CHALLENGE is found.
func TestParseBindNegotiateResponseSicilyMatchedDN(t *testing.T) {
	challenge := []byte("NTLMSSP\x00\x02sicilyMatchedDN")

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindResponse), nil, "BindResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSaslBindInProgress), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(challenge), "matchedDN-as-CHALLENGE"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	got, err := parseBindNegotiateResponse(decoded)
	if err != nil {
		t.Fatalf("parseBindNegotiateResponse: %v", err)
	}
	if !bytes.Equal(got, challenge) {
		t.Errorf("CHALLENGE = %x, want %x", got, challenge)
	}
}

// TestParseBindNegotiateResponseStandardServerSaslCreds covers the spec-
// correct layout: serverSaslCreds [CONTEXT 7] OPTIONAL after the standard
// LDAPResult fields. This path is taken when the upstream isn't AD.
func TestParseBindNegotiateResponseStandardServerSaslCreds(t *testing.T) {
	challenge := []byte("NTLMSSP\x00\x02standard")

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindResponse), nil, "BindResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSaslBindInProgress), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	sasl := ber.Encode(ber.ClassContext, ber.TypePrimitive, 7, nil, "serverSaslCreds")
	sasl.Data.Write(challenge)
	resp.AppendChild(sasl)
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	got, err := parseBindNegotiateResponse(decoded)
	if err != nil {
		t.Fatalf("parseBindNegotiateResponse: %v", err)
	}
	if !bytes.Equal(got, challenge) {
		t.Errorf("CHALLENGE = %x, want %x", got, challenge)
	}
}

// TestParseBindNegotiateResponseAnonymousFallback verifies the loud-failure
// path: BindResponse with resultCode=0 and an empty matchedDN means the DC
// treated our sicily bind as anonymous. The relay must reject this — the
// caller explicitly wants an authenticated upstream — with a message that
// explains why.
func TestParseBindNegotiateResponseAnonymousFallback(t *testing.T) {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindResponse), nil, "BindResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSuccess), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	_, err = parseBindNegotiateResponse(decoded)
	if err == nil {
		t.Fatal("expected error for anonymous fallback, got nil")
	}
	if !strings.Contains(err.Error(), "anonymous") || !strings.Contains(err.Error(), "resultCode=0") {
		t.Errorf("error %q does not surface the diagnostic (resultCode + anonymous)", err)
	}
}

// TestInboundRequestsSigning verifies the warning trigger: SIGN or SEAL
// flags in the inbound NEGOTIATE return true; their absence returns false.
// ALWAYS_SIGN is intentionally NOT a trigger — it's a session-key generation
// hint that doesn't imply on-the-wire signing enforcement, so flagging it
// would produce noisy warnings. Malformed input fails closed.
func TestInboundRequestsSigning(t *testing.T) {
	build := func(flags uint32) []byte {
		b := make([]byte, 16)
		copy(b[:8], []byte("NTLMSSP\x00"))
		binary.LittleEndian.PutUint32(b[8:12], ntlmssp.TypeNtLmNegotiate)
		binary.LittleEndian.PutUint32(b[12:16], flags)
		return b
	}
	cases := []struct {
		name  string
		flags uint32
		want  bool
	}{
		{"sign", ntlmssp.FlgNegSign | ntlmssp.FlgNegUnicode, true},
		{"seal", ntlmssp.FlgNegSeal | ntlmssp.FlgNegUnicode, true},
		{"always-sign-only", ntlmssp.FlgNegAlwaysSign | ntlmssp.FlgNegUnicode, false},
		{"none", ntlmssp.FlgNegUnicode | ntlmssp.FlgNegNtLm, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := inboundRequestsSigning(build(c.flags)); got != c.want {
				t.Errorf("flags=0x%08x → %v, want %v", c.flags, got, c.want)
			}
		})
	}

	if inboundRequestsSigning(nil) {
		t.Error("nil input must return false")
	}
	if inboundRequestsSigning([]byte("not-ntlm")) {
		t.Error("non-NTLMSSP input must return false")
	}
}

// TestEncodeStartTLSRequestShape verifies the BER shape of the StartTLS
// ExtendedRequest we emit: [APPLICATION 23] SEQUENCE with a single
// [CONTEXT 0] PRIMITIVE child carrying the StartTLS OID bytes (RFC 4511
// §4.12, §4.14).
func TestEncodeStartTLSRequestShape(t *testing.T) {
	req := encodeStartTLSRequest()
	if req.ClassType != ber.ClassApplication || req.Tag != ldapAppExtendedRequest {
		t.Errorf("ExtendedRequest envelope class/tag = %d/%d, want app/23", req.ClassType, req.Tag)
	}
	if len(req.Children) != 1 {
		t.Fatalf("ExtendedRequest children = %d, want 1", len(req.Children))
	}
	name := req.Children[0]
	if name.ClassType != ber.ClassContext || name.Tag != 0 {
		t.Errorf("requestName class/tag = %d/%d, want context/0", name.ClassType, name.Tag)
	}
	if got := name.Data.Bytes(); string(got) != startTLSOID {
		t.Errorf("requestName data = %q, want %q", got, startTLSOID)
	}
}

// TestParseStartTLSResponseSuccess builds an ExtendedResponse with
// resultCode=0 and confirms the parser surfaces it. dialUpstream uses that
// signal to upgrade the socket to TLS.
func TestParseStartTLSResponseSuccess(t *testing.T) {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppExtendedResponse, nil, "ExtendedResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSuccess), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	rc, err := parseStartTLSResponse(decoded)
	if err != nil {
		t.Fatalf("parseStartTLSResponse: %v", err)
	}
	if rc != ldapResultSuccess {
		t.Errorf("resultCode = %d, want 0", rc)
	}
}

// TestParseStartTLSResponseRejection covers the "server says no" path:
// resultCode=2 (protocolError) is the standard StartTLS-unsupported response.
// The parser must surface the non-zero code with no error — the caller treats
// that as "fall back to plain LDAP".
func TestParseStartTLSResponseRejection(t *testing.T) {
	const protocolError = 2
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppExtendedResponse, nil, "ExtendedResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(protocolError), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "unsupported extended operation", "diagnosticMessage"))
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	rc, err := parseStartTLSResponse(decoded)
	if err != nil {
		t.Fatalf("parseStartTLSResponse returned error on rejection: %v", err)
	}
	if rc != protocolError {
		t.Errorf("resultCode = %d, want %d", rc, protocolError)
	}
}

// TestParseStartTLSResponseWrongTag verifies envelope validation: when the
// inner application packet isn't an ExtendedResponse (e.g. server replied with
// BindResponse by mistake), the parser must return an error so the caller can
// surface the protocol violation rather than misinterpret resultCode.
func TestParseStartTLSResponseWrongTag(t *testing.T) {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(1), "MessageID"))
	wrong := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldapAppBindResponse, nil, "BindResponse")
	wrong.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(0), "resultCode"))
	env.AppendChild(wrong)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	if _, err := parseStartTLSResponse(decoded); err == nil {
		t.Fatal("expected error for non-ExtendedResponse envelope, got nil")
	}
}

// TestParseBindResultCodeSuccess verifies Phase-2 parsing: pull resultCode
// from a BindResponse that has no CHALLENGE bytes.
func TestParseBindResultCodeSuccess(t *testing.T) {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPMessage")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(2), "MessageID"))
	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(ldapAppBindResponse), nil, "BindResponse")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ldapResultSuccess), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	env.AppendChild(resp)

	decoded, err := ber.DecodePacketErr(env.Bytes())
	if err != nil {
		t.Fatalf("DecodePacketErr: %v", err)
	}
	code, _, _, err := parseBindResultCode(decoded)
	if err != nil {
		t.Fatalf("parseBindResultCode: %v", err)
	}
	if code != ldapResultSuccess {
		t.Errorf("resultCode = %d, want 0", code)
	}
}
