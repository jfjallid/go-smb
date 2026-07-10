package ntlmssp

import (
	"testing"
)

// newTestServer returns a Server configured like a modern Windows host so the
// CHALLENGE it produces (populated TargetInfo + Version) is accepted by the
// client's Authenticate path.
func newTestServer() *Server {
	return &Server{
		TargetName:      "TESTSRV",
		NetBIOSName:     "TESTSRV",
		NetBIOSDomain:   "TESTDOM",
		DnsComputerName: "testsrv.testdom.local",
		DnsDomainName:   "testdom.local",
	}
}

// driveAuth runs a full in-process NEGOTIATE -> CHALLENGE -> AUTHENTICATE
// exchange for the given client and returns the parsed AUTHENTICATE message as
// the server sees it on the wire.
func driveAuth(t *testing.T, c *Client) *Authenticate {
	t.Helper()

	negMsg, err := c.Negotiate()
	if err != nil {
		t.Fatalf("Negotiate: %v", err)
	}

	srv := newTestServer()
	chall, err := srv.AcceptNegotiate(negMsg)
	if err != nil {
		t.Fatalf("AcceptNegotiate: %v", err)
	}

	authMsg, err := c.Authenticate(chall)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}

	parsed, err := srv.AcceptAuthenticate(authMsg)
	if err != nil {
		t.Fatalf("AcceptAuthenticate: %v", err)
	}
	return parsed
}

// TestAuthModes verifies the on-the-wire AUTHENTICATE message for each of the
// three NTLM auth modes, including that guest no longer (incorrectly) sets the
// NTLMSSP_NEGOTIATE_ANONYMOUS flag while still sending a real response.
func TestAuthModes(t *testing.T) {
	cases := []struct {
		name       string
		client     *Client
		wantUser   bool // UserName present on the wire
		wantNTResp bool // non-empty NtChallengeResponse
		wantAnonFl bool // NTLMSSP_NEGOTIATE_ANONYMOUS set
	}{
		{
			name:       "credentials (explicit)",
			client:     &Client{User: "alice", Password: "p4ss", Domain: "TESTDOM", AuthMode: NTLMAuthCredentials},
			wantUser:   true,
			wantNTResp: true,
			wantAnonFl: false,
		},
		{
			name:       "anonymous (explicit)",
			client:     &Client{User: "alice", Password: "p4ss", Domain: "TESTDOM", AuthMode: NTLMAuthAnonymous},
			wantUser:   false,
			wantNTResp: false,
			wantAnonFl: true,
		},
		{
			name:       "guest (explicit)",
			client:     &Client{User: "alice", Password: "p4ss", Domain: "TESTDOM", AuthMode: NTLMAuthGuest},
			wantUser:   false,
			wantNTResp: true,
			wantAnonFl: false, // defect-3 fix: guest is NOT anonymous
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			auth := driveAuth(t, tc.client)

			if gotUser := auth.UserNameLen > 0; gotUser != tc.wantUser {
				t.Errorf("UserName present = %v, want %v (len=%d)", gotUser, tc.wantUser, auth.UserNameLen)
			}
			if gotNT := auth.NtChallengeResponseLen > 0; gotNT != tc.wantNTResp {
				t.Errorf("NtChallengeResponse present = %v, want %v (len=%d)", gotNT, tc.wantNTResp, auth.NtChallengeResponseLen)
			}
			gotAnon := auth.NegotiateFlags&FlgNegAnonymous != 0
			if gotAnon != tc.wantAnonFl {
				t.Errorf("FlgNegAnonymous = %v, want %v", gotAnon, tc.wantAnonFl)
			}

			// Anonymous mode must produce zero-length LM/NT responses.
			if tc.name == "anonymous (explicit)" {
				if auth.LmChallengeResponseLen != 0 {
					t.Errorf("anonymous LmChallengeResponseLen = %d, want 0", auth.LmChallengeResponseLen)
				}
				if auth.NtChallengeResponseLen != 0 {
					t.Errorf("anonymous NtChallengeResponseLen = %d, want 0", auth.NtChallengeResponseLen)
				}
			}
		})
	}
}

// TestAuthModeLegacyInference verifies the backwards-compatible fallbacks:
// the deprecated NullSession bool still selects anonymous, and an empty User
// with no explicit mode still selects guest.
func TestAuthModeLegacyInference(t *testing.T) {
	t.Run("NullSession bool => anonymous", func(t *testing.T) {
		auth := driveAuth(t, &Client{NullSession: true})
		if auth.NegotiateFlags&FlgNegAnonymous == 0 {
			t.Errorf("NullSession=true did not set FlgNegAnonymous")
		}
		if auth.NtChallengeResponseLen != 0 || auth.LmChallengeResponseLen != 0 {
			t.Errorf("NullSession=true sent non-empty responses (NT=%d LM=%d)",
				auth.NtChallengeResponseLen, auth.LmChallengeResponseLen)
		}
		if auth.UserNameLen != 0 {
			t.Errorf("NullSession=true sent a username (len=%d)", auth.UserNameLen)
		}
	})

	t.Run("empty User => guest", func(t *testing.T) {
		auth := driveAuth(t, &Client{User: "", Password: ""})
		// Guest: real response, no username, and NOT anonymous.
		if auth.NtChallengeResponseLen == 0 {
			t.Errorf("inferred guest sent an empty NtChallengeResponse")
		}
		if auth.UserNameLen != 0 {
			t.Errorf("inferred guest sent a username (len=%d)", auth.UserNameLen)
		}
		if auth.NegotiateFlags&FlgNegAnonymous != 0 {
			t.Errorf("inferred guest incorrectly set FlgNegAnonymous")
		}
	})
}
