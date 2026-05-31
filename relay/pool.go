// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package relay

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// pooledSession holds a single live, authenticated upstream connection
// captured by RelayServer. Exactly one of Conn (SMB), HTTP, or LDAP is
// non-nil. The mutex is held by SOCKS-side passthrough while a request /
// response is in flight on the upstream so multiple concurrent SOCKS clients
// don't interleave traffic on the same upstream socket.
type pooledSession struct {
	Target      string
	Conn        *smb.Connection // SMB upstream; nil otherwise
	HTTP        *httpUpstream   // HTTP upstream; nil otherwise
	LDAP        *ldapUpstream   // LDAP upstream; nil otherwise
	Cred        *Credential
	Established time.Time
	lastUsed    atomic.Int64 // unix nano
	dead        atomic.Bool

	mu sync.Mutex // serializes outbound requests on the upstream
}

// IsHTTP reports whether this pooled session is an HTTP upstream.
func (p *pooledSession) IsHTTP() bool { return p.HTTP != nil }

// IsLDAP reports whether this pooled session is an LDAP upstream.
func (p *pooledSession) IsLDAP() bool { return p.LDAP != nil }

// MarkDead flags ps as unusable. Subsequent FindMatches calls and selector
// invocations skip it; the next pruneExpired sweep evicts it.
func (p *pooledSession) MarkDead() { p.dead.Store(true) }

// IsDead reports whether ps has been flagged dead.
func (p *pooledSession) IsDead() bool { return p.dead.Load() }

// SessionInfo is a snapshot of a pooled session — exposed for telemetry /
// tests, decoupled from the live mutex-guarded state.
type SessionInfo struct {
	Target      string
	Username    string
	Domain      string
	RemoteAddr  net.Addr
	Established time.Time
	LastUsed    time.Time
}

func (p *pooledSession) snapshot() SessionInfo {
	si := SessionInfo{
		Target:      p.Target,
		Established: p.Established,
		LastUsed:    time.Unix(0, p.lastUsed.Load()),
	}
	if p.Cred != nil {
		si.Username = p.Cred.Username
		si.Domain = p.Cred.Domain
		si.RemoteAddr = p.Cred.RemoteAddr
	}
	return si
}

// Touch updates the last-used timestamp. Called by SOCKS passthrough each
// time a request is forwarded so the TTL ticker can age out idle sessions.
func (p *pooledSession) Touch() {
	p.lastUsed.Store(time.Now().UnixNano())
}

// sessionPool is a FIFO-evicting collection of pooledSessions keyed by
// insertion order. Lookups by target return any matching live session;
// concurrent SOCKS clients can pin different targets simultaneously.
type sessionPool struct {
	mu       sync.Mutex
	max      int
	ttl      time.Duration
	sessions []*pooledSession
}

// newSessionPool returns an empty pool. max <= 0 disables the cap. ttl <= 0
// disables age-based eviction.
func newSessionPool(max int, ttl time.Duration) *sessionPool {
	return &sessionPool{max: max, ttl: ttl}
}

// Add inserts ps into the pool. If MaxPoolSize is reached, the oldest entry
// is evicted (its connection closed). Evictions are collected under the lock
// and closed synchronously after — close-time is dominated by a few socket
// shutdowns, well below the cost of pinning the pool mu, and an in-flight
// background goroutine would otherwise outlive Shutdown.
func (sp *sessionPool) Add(ps *pooledSession) {
	ps.lastUsed.Store(ps.Established.UnixNano())
	sp.mu.Lock()
	sp.sessions = append(sp.sessions, ps)
	var evicted []*pooledSession
	for sp.max > 0 && len(sp.sessions) > sp.max {
		evicted = append(evicted, sp.sessions[0])
		sp.sessions = sp.sessions[1:]
	}
	sp.mu.Unlock()
	for _, p := range evicted {
		closePooled(p)
	}
}

// Remove drops a specific entry (used when a SOCKS dispatcher detects that
// the upstream conn is dead). Closes the *smb.Connection.
func (sp *sessionPool) Remove(target *pooledSession) {
	sp.mu.Lock()
	for i, p := range sp.sessions {
		if p == target {
			sp.sessions = append(sp.sessions[:i], sp.sessions[i+1:]...)
			break
		}
	}
	sp.mu.Unlock()
	closePooled(target)
}

// FindByTarget returns the first live pooled session matching the supplied
// "host:port" target string, or nil. Dead entries are skipped. Retained for
// callers that don't care about user-based filtering; new code should prefer
// FindMatches.
func (sp *sessionPool) FindByTarget(target string) *pooledSession {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	for _, p := range sp.sessions {
		if p.Target == target && !p.IsDead() {
			return p
		}
	}
	return nil
}

// FindMatches returns every live pooled session whose Target equals target
// and whose captured Credential matches user (case-insensitive). The user
// argument accepts:
//   - "" — no user filter, target match only
//   - "name" — Credential.Username == name
//   - "domain\\name", "domain/name" — both domain and name must match
//   - "name@domain" — same as above (UPN form)
//
// Dead entries are excluded.
func (sp *sessionPool) FindMatches(target, user string) []*pooledSession {
	wantDomain, wantName := parseAuthUser(user)
	sp.mu.Lock()
	defer sp.mu.Unlock()
	var out []*pooledSession
	for _, p := range sp.sessions {
		if p.Target != target || p.IsDead() {
			continue
		}
		if user != "" && !credMatches(p.Cred, wantDomain, wantName) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// parseAuthUser splits a user spec into (domain, name). See FindMatches.
func parseAuthUser(s string) (domain, name string) {
	if s == "" {
		return "", ""
	}
	if i := strings.IndexAny(s, "\\/"); i >= 0 {
		return s[:i], s[i+1:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[i+1:], s[:i]
	}
	return "", s
}

// credMatches compares a captured credential against a parsed (domain, name)
// filter. domain is optional; empty domain matches any Credential.Domain.
func credMatches(cred *Credential, domain, name string) bool {
	if cred == nil {
		return false
	}
	if !strings.EqualFold(cred.Username, name) {
		return false
	}
	if domain != "" && !strings.EqualFold(cred.Domain, domain) {
		return false
	}
	return true
}

// Snapshot returns a stable copy of every live entry's metadata.
func (sp *sessionPool) Snapshot() []SessionInfo {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	out := make([]SessionInfo, 0, len(sp.sessions))
	for _, p := range sp.sessions {
		out = append(out, p.snapshot())
	}
	return out
}

// Len reports the number of live entries.
func (sp *sessionPool) Len() int {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return len(sp.sessions)
}

// CloseAll tears down every pooled connection and empties the pool.
func (sp *sessionPool) CloseAll() {
	sp.mu.Lock()
	old := sp.sessions
	sp.sessions = nil
	sp.mu.Unlock()
	for _, p := range old {
		closePooled(p)
	}
}

// pruneExpired evicts entries whose lastUsed is older than ttl, plus any
// entry flagged dead. Called by the background ticker.
func (sp *sessionPool) pruneExpired(now time.Time) []*pooledSession {
	checkTTL := sp.ttl > 0
	cutoff := int64(0)
	if checkTTL {
		cutoff = now.Add(-sp.ttl).UnixNano()
	}
	sp.mu.Lock()
	keep := sp.sessions[:0]
	var evicted []*pooledSession
	for _, p := range sp.sessions {
		if p.IsDead() || (checkTTL && p.lastUsed.Load() < cutoff) {
			evicted = append(evicted, p)
			continue
		}
		keep = append(keep, p)
	}
	sp.sessions = keep
	sp.mu.Unlock()
	for _, p := range evicted {
		closePooled(p)
	}
	if n := len(evicted); n > 0 {
		log.Debugf("pool: pruned %d expired session(s)", n)
	}
	return evicted
}

func closePooled(p *pooledSession) {
	if p == nil {
		return
	}
	if p.Conn != nil {
		p.Conn.Close()
	}
	if p.HTTP != nil {
		_ = p.HTTP.Close()
	}
	if p.LDAP != nil {
		_ = p.LDAP.Close()
	}
}

// SelectTargetFunc is the strategy signature used by RelayServer to decide
// which target to relay an inbound auth toward. lastUsed maps Target.Host ->
// timestamp of the most recent successful relay onto it (updated by the
// caller). The function must be safe for concurrent calls. Returning the
// zero Target signals "no candidate".
type SelectTargetFunc func(targets []Target, remote net.Addr, lastUsed map[string]time.Time) Target

// RoundRobin returns a target-selector that cycles through the configured
// targets in order. Safe for concurrent use.
func RoundRobin() SelectTargetFunc {
	var i atomic.Uint64
	return func(targets []Target, _ net.Addr, _ map[string]time.Time) Target {
		if len(targets) == 0 {
			return Target{}
		}
		idx := i.Add(1) - 1
		return targets[int(idx%uint64(len(targets)))]
	}
}

// StickyByRemote returns a target-selector that hashes the relayed client's
// remote address (host:port stripped to host) onto the target list. Two
// auths from the same client always land on the same upstream — useful for
// post-auth actions that depend on per-client state.
func StickyByRemote() SelectTargetFunc {
	return func(targets []Target, remote net.Addr, _ map[string]time.Time) Target {
		if len(targets) == 0 {
			return Target{}
		}
		host := ""
		if remote != nil {
			host = remote.String()
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
		}
		var h uint64 = 1469598103934665603 // FNV-1a 64
		for i := 0; i < len(host); i++ {
			h ^= uint64(host[i])
			h *= 1099511628211
		}
		return targets[int(h%uint64(len(targets)))]
	}
}

// SessionMatcher picks one pooled session from candidates already filtered by
// target and user. remote is the SOCKS client's address. Return nil if no
// candidate is usable. Implementations MUST skip dead candidates.
type SessionMatcher func(candidates []*pooledSession, remote net.Addr) *pooledSession

// PoolFirstAvailable returns a matcher that picks the first live candidate.
// Combined with [pooledSession.MarkDead] this gives the "first with fallback
// to next" behavior: a dead pick is skipped on the next SOCKS connection.
func PoolFirstAvailable() SessionMatcher {
	return func(candidates []*pooledSession, _ net.Addr) *pooledSession {
		for _, p := range candidates {
			if !p.IsDead() {
				return p
			}
		}
		return nil
	}
}

// PoolRoundRobin returns a matcher that cycles through candidates via an
// atomic counter shared across the matcher's lifetime. Dead candidates are
// skipped (the counter still advances so subsequent picks rotate).
func PoolRoundRobin() SessionMatcher {
	var i atomic.Uint64
	return func(candidates []*pooledSession, _ net.Addr) *pooledSession {
		n := len(candidates)
		if n == 0 {
			return nil
		}
		for tries := 0; tries < n; tries++ {
			idx := i.Add(1) - 1
			p := candidates[int(idx%uint64(n))]
			if !p.IsDead() {
				return p
			}
		}
		return nil
	}
}

// PoolMostRecent returns a matcher that picks the live candidate with the
// highest Established timestamp.
func PoolMostRecent() SessionMatcher {
	return func(candidates []*pooledSession, _ net.Addr) *pooledSession {
		var best *pooledSession
		for _, p := range candidates {
			if p.IsDead() {
				continue
			}
			if best == nil || p.Established.After(best.Established) {
				best = p
			}
		}
		return best
	}
}
