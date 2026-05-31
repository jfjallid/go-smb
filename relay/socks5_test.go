// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay

import (
	"net"
	"testing"
	"time"
)

// TestSocks5HandshakeDomain exercises socks5Handshake against a synthetic
// SOCKS5 client request using the domain ATYP. We pipe both sides through
// net.Pipe to avoid touching the network.
func TestSocks5HandshakeDomain(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		// Greeting: VER=5 NMETHODS=1 NoAuth.
		client.Write([]byte{0x05, 0x01, 0x00})
		// Read method selection.
		buf := make([]byte, 2)
		_, _ = client.Read(buf)
		// CONNECT example.com:445 by domain.
		host := "example.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		req = append(req, 0x01, 0xbd) // 445
		client.Write(req)
	}()

	// socks5Handshake reads from the server side of the pipe.
	target, err := socks5Handshake(server)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	want := "example.com:445"
	if target != want {
		t.Errorf("target=%q want %q", target, want)
	}
}

// TestSocks5HandshakeIPv4 covers the IPv4 ATYP path.
func TestSocks5HandshakeIPv4(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		client.Write([]byte{0x05, 0x01, 0x00})
		buf := make([]byte, 2)
		_, _ = client.Read(buf)
		req := []byte{0x05, 0x01, 0x00, 0x01, 10, 1, 2, 3, 0x01, 0xbb} // 10.1.2.3:443
		client.Write(req)
	}()

	target, err := socks5Handshake(server)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if target != "10.1.2.3:443" {
		t.Errorf("target=%q want 10.1.2.3:443", target)
	}
}

// TestSocks5HandshakeRejectsNonNoAuth checks that a client that doesn't offer
// no-auth gets a 0xff method-selection rejection.
func TestSocks5HandshakeRejectsNonNoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	got := make(chan []byte, 1)
	go func() {
		// Offer only 0x02 (user/pass).
		client.Write([]byte{0x05, 0x01, 0x02})
		buf := make([]byte, 2)
		n, _ := client.Read(buf)
		got <- buf[:n]
	}()

	_, err := socks5Handshake(server)
	if err == nil {
		t.Fatalf("handshake unexpectedly succeeded")
	}
	select {
	case b := <-got:
		if len(b) != 2 || b[0] != 0x05 || b[1] != 0xff {
			t.Errorf("expected [05 ff], got % x", b)
		}
	case <-time.After(time.Second):
		t.Fatalf("client did not see method-selection reply")
	}
}

// TestPoolRoundRobin exercises the RoundRobin selector across two targets.
func TestPoolRoundRobin(t *testing.T) {
	rr := RoundRobin()
	targets := []Target{
		{Protocol: ProtoSMB, Host: "a:1"},
		{Protocol: ProtoSMB, Host: "b:2"},
	}
	got := []string{}
	for i := 0; i < 4; i++ {
		got = append(got, rr(targets, nil, nil).Host)
	}
	want := []string{"a:1", "b:2", "a:1", "b:2"}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("rr[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

// TestParseAuthUser exercises the user-spec parser used by FindMatches.
func TestParseAuthUser(t *testing.T) {
	cases := []struct {
		in           string
		domain, user string
	}{
		{"", "", ""},
		{"alice", "", "alice"},
		{"CONTOSO\\alice", "CONTOSO", "alice"},
		{"CONTOSO/alice", "CONTOSO", "alice"},
		{"alice@CONTOSO", "CONTOSO", "alice"},
	}
	for _, c := range cases {
		d, u := parseAuthUser(c.in)
		if d != c.domain || u != c.user {
			t.Errorf("parseAuthUser(%q) = (%q,%q), want (%q,%q)", c.in, d, u, c.domain, c.user)
		}
	}
}

// TestFindMatchesFilters validates target/user filtering, case-insensitivity,
// and dead-entry exclusion.
func TestFindMatchesFilters(t *testing.T) {
	sp := newSessionPool(0, 0)
	mk := func(target, user, domain string) *pooledSession {
		ps := &pooledSession{
			Target:      target,
			Cred:        &Credential{Username: user, Domain: domain},
			Established: time.Now(),
		}
		sp.Add(ps)
		return ps
	}
	a1 := mk("host:445", "alice", "CONTOSO")
	mk("host:445", "bob", "CONTOSO")
	mk("other:445", "alice", "CONTOSO")
	dead := mk("host:445", "alice", "CONTOSO")
	dead.MarkDead()

	if got := len(sp.FindMatches("host:445", "")); got != 2 {
		t.Errorf("no user filter: got %d matches, want 2 (live alice + bob)", got)
	}
	if got := sp.FindMatches("host:445", "alice"); len(got) != 1 || got[0] != a1 {
		t.Errorf("user=alice: got %v, want [a1]", got)
	}
	if got := sp.FindMatches("host:445", "ALICE"); len(got) != 1 || got[0] != a1 {
		t.Errorf("case-insensitive: got %d matches", len(got))
	}
	if got := sp.FindMatches("host:445", "CONTOSO\\alice"); len(got) != 1 || got[0] != a1 {
		t.Errorf("domain\\\\user: got %v", got)
	}
	if got := sp.FindMatches("host:445", "alice@CONTOSO"); len(got) != 1 || got[0] != a1 {
		t.Errorf("UPN form: got %v", got)
	}
	if got := sp.FindMatches("host:445", "OTHER\\alice"); len(got) != 0 {
		t.Errorf("wrong domain: got %d matches, want 0", len(got))
	}
	if got := sp.FindMatches("host:445", "nobody"); len(got) != 0 {
		t.Errorf("unknown user: got %d matches, want 0", len(got))
	}
}

// TestPoolFirstAvailable picks the first non-dead candidate.
func TestPoolFirstAvailable(t *testing.T) {
	sel := PoolFirstAvailable()
	a := &pooledSession{Target: "x"}
	b := &pooledSession{Target: "x"}
	if got := sel([]*pooledSession{a, b}, nil); got != a {
		t.Errorf("expected first candidate, got %v", got)
	}
	a.MarkDead()
	if got := sel([]*pooledSession{a, b}, nil); got != b {
		t.Errorf("dead first: expected b, got %v", got)
	}
	b.MarkDead()
	if got := sel([]*pooledSession{a, b}, nil); got != nil {
		t.Errorf("all dead: expected nil")
	}
}

// TestPoolSessionRoundRobin distributes selections across candidates and
// skips dead. Named to disambiguate from the target-selector RoundRobin test.
func TestPoolSessionRoundRobin(t *testing.T) {
	sel := PoolRoundRobin()
	a := &pooledSession{Target: "x"}
	b := &pooledSession{Target: "x"}
	picks := map[*pooledSession]int{}
	for i := 0; i < 6; i++ {
		picks[sel([]*pooledSession{a, b}, nil)]++
	}
	if picks[a] == 0 || picks[b] == 0 {
		t.Errorf("round-robin failed to spread: a=%d b=%d", picks[a], picks[b])
	}
	a.MarkDead()
	for i := 0; i < 4; i++ {
		if p := sel([]*pooledSession{a, b}, nil); p != b {
			t.Errorf("a dead: expected b, got %v", p)
		}
	}
}

// TestPoolMostRecent picks the candidate with the newest Established time.
func TestPoolMostRecent(t *testing.T) {
	sel := PoolMostRecent()
	now := time.Now()
	old := &pooledSession{Target: "x", Established: now.Add(-time.Hour)}
	mid := &pooledSession{Target: "x", Established: now.Add(-time.Minute)}
	newest := &pooledSession{Target: "x", Established: now}
	if got := sel([]*pooledSession{old, mid, newest}, nil); got != newest {
		t.Errorf("most-recent: got %v want newest", got)
	}
	newest.MarkDead()
	if got := sel([]*pooledSession{old, mid, newest}, nil); got != mid {
		t.Errorf("newest dead: expected mid, got %v", got)
	}
}

// TestResolveUpstreamSkipsDeadOnHealthCheck verifies the
// HealthCheckOnSelect path: if the first chosen pool entry is dead, the
// resolver retries against the remaining candidates. We don't run the actual
// SMB Echo here — we pre-mark the first candidate dead, which simulates a
// health-check failure outcome on the next iteration.
func TestResolveUpstreamSkipsDeadOnHealthCheck(t *testing.T) {
	rs := &RelayServer{
		Config: ServerConfig{
			SelectPoolEntry:     PoolFirstAvailable(),
			HealthCheckOnSelect: false, // health check off; rely on dead flag
		},
	}
	rs.pool = newSessionPool(0, 0)

	a := &pooledSession{Target: "x:1", Cred: &Credential{Username: "u", Domain: "D"}, Established: time.Now()}
	b := &pooledSession{Target: "x:1", Cred: &Credential{Username: "u", Domain: "D"}, Established: time.Now()}
	rs.pool.Add(a)
	rs.pool.Add(b)

	resolver := rs.resolveUpstream(nil)
	if got := resolver("x:1", "D", "u"); got != a {
		t.Fatalf("initial pick: got %v want a", got)
	}
	a.MarkDead()
	if got := resolver("x:1", "D", "u"); got != b {
		t.Fatalf("after a marked dead: got %v want b", got)
	}
	b.MarkDead()
	if got := resolver("x:1", "D", "u"); got != nil {
		t.Fatalf("all dead: expected nil, got %v", got)
	}
}

// TestPoolStickyByRemote ensures the same remote always lands on the same
// target.
func TestPoolStickyByRemote(t *testing.T) {
	s := StickyByRemote()
	targets := []Target{
		{Protocol: ProtoSMB, Host: "a:1"},
		{Protocol: ProtoSMB, Host: "b:2"},
		{Protocol: ProtoSMB, Host: "c:3"},
	}
	addrA := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1234}
	addrB := &net.TCPAddr{IP: net.ParseIP("10.0.0.2"), Port: 5678}
	a1 := s(targets, addrA, nil)
	a2 := s(targets, addrA, nil)
	if a1 != a2 {
		t.Errorf("sticky returned different targets for same remote: %v vs %v", a1, a2)
	}
	b1 := s(targets, addrB, nil)
	if a1 == b1 {
		t.Logf("warning: different remotes hashed to same target %v (acceptable)", a1)
	}
}
