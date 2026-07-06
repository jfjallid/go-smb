// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay

import "testing"

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in        string
		wantProto Protocol
		wantHost  string
		wantTLS   bool
		wantPath  string
		wantErr   bool
	}{
		// SMB
		{"smb://host", ProtoSMB, "host:445", false, "", false},
		{"smb://host:1445", ProtoSMB, "host:1445", false, "", false},
		// HTTP
		{"http://host", ProtoHTTP, "host:80", false, "/", false},
		{"http://host:8080", ProtoHTTP, "host:8080", false, "/", false},
		{"http://host:8080/api", ProtoHTTP, "host:8080", false, "/api", false},
		// HTTPS
		{"https://host", ProtoHTTPS, "host:443", true, "/", false},
		{"https://host:8443/admin", ProtoHTTPS, "host:8443", true, "/admin", false},
		// LDAP
		{"ldap://host", ProtoLDAP, "host:389", false, "", false},
		{"ldap://host:3389", ProtoLDAP, "host:3389", false, "", false},
		// LDAPS
		{"ldaps://host", ProtoLDAPS, "host:636", true, "", false},
		{"ldaps://host:3636", ProtoLDAPS, "host:3636", true, "", false},
		// Mixed-case scheme is accepted (URL scheme is case-insensitive per RFC 3986)
		{"SMB://host", ProtoSMB, "host:445", false, "", false},
		{"HTTPS://host:8443/x", ProtoHTTPS, "host:8443", true, "/x", false},
		// Rejections
		{"host:445", "", "", false, "", true},         // bare host:port
		{"", "", "", false, "", true},                 // empty
		{"ftp://host:21", "", "", false, "", true},    // unsupported scheme
		{"smb://", "", "", false, "", true},           // missing host
		{"://host", "", "", false, "", true},          // empty scheme
		{"smb://host:0", "", "", false, "", true},     // port = 0
		{"smb://host:65536", "", "", false, "", true}, // port > 65535
		{"smb://host:99999", "", "", false, "", true}, // 5-digit garbage
		{"smb://host:abc", "", "", false, "", true},   // non-numeric port (caught by url.Parse)
	}
	for _, tc := range cases {
		got, err := ParseTarget(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseTarget(%q) wanted error, got %+v", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseTarget(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if got.Protocol != tc.wantProto || got.Host != tc.wantHost || got.TLS != tc.wantTLS || got.Path != tc.wantPath {
			t.Errorf("ParseTarget(%q) = %+v, want proto=%s host=%s tls=%v path=%s",
				tc.in, got, tc.wantProto, tc.wantHost, tc.wantTLS, tc.wantPath)
		}
	}
}

func TestParseTargetsMixed(t *testing.T) {
	in := []string{
		"smb://10.0.0.1",
		"http://app01:8080/auth",
		"https://app02/login",
	}
	got, err := ParseTargets(in)
	if err != nil {
		t.Fatalf("ParseTargets: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len=%d want 3", len(got))
	}
	if got[0].Protocol != ProtoSMB || got[0].Host != "10.0.0.1:445" {
		t.Errorf("smb entry = %+v", got[0])
	}
	if got[1].Protocol != ProtoHTTP || got[1].Host != "app01:8080" || got[1].Path != "/auth" {
		t.Errorf("http entry = %+v", got[1])
	}
	if got[2].Protocol != ProtoHTTPS || !got[2].TLS || got[2].Host != "app02:443" || got[2].Path != "/login" {
		t.Errorf("https entry = %+v", got[2])
	}
}

func TestTargetFilters(t *testing.T) {
	all := []Target{
		{Protocol: ProtoSMB, Host: "a:445"},
		{Protocol: ProtoHTTP, Host: "b:80"},
		{Protocol: ProtoHTTPS, Host: "c:443"},
		{Protocol: ProtoLDAP, Host: "d:389"},
		{Protocol: ProtoLDAPS, Host: "e:636"},
	}
	if got := smbAnyTargets(all); len(got) != 1 || got[0].Host != "a:445" {
		t.Errorf("smbAnyTargets = %+v", got)
	}
	if got := httpTargets(all); len(got) != 2 {
		t.Errorf("httpTargets len=%d want 2", len(got))
	}
	if got := ldapTargets(all); len(got) != 2 {
		t.Errorf("ldapTargets len=%d want 2", len(got))
	}
}

func TestParseTargetErrorMentionsSchemeRequirement(t *testing.T) {
	_, err := ParseTarget("10.0.0.1:445")
	if err == nil {
		t.Fatal("expected error")
	}
	// Error should hint that scheme is required so users migrating from the
	// old config style get a useful diagnostic.
	if msg := err.Error(); msg == "" || !contains(msg, "scheme") {
		t.Errorf("error %q does not mention scheme", msg)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
