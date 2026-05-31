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
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Protocol identifies the upstream wire protocol carried by a Target.
type Protocol string

const (
	ProtoSMB   Protocol = "smb"
	ProtoHTTP  Protocol = "http"
	ProtoHTTPS Protocol = "https"
	ProtoLDAP  Protocol = "ldap"
	ProtoLDAPS Protocol = "ldaps"
)

// Target is a parsed upstream destination. Targets are configured via
// scheme-prefixed strings (smb://, http://, https://) and dispatched to one of
// the inbound listeners based on Protocol.
type Target struct {
	Raw      string
	Protocol Protocol
	Host     string // canonical "host:port" — also the pool key
	TLS      bool   // https only
	Path     string // http/https only; defaults to "/"
}

// Key returns the pool key for this target — the canonical "host:port" string.
// SMB and HTTP entries sharing a host:port share a pool key; IsHTTP() on
// pooledSession discriminates retrieval.
func (t Target) Key() string { return t.Host }

// IsHTTP reports whether the target speaks HTTP/HTTPS.
func (t Target) IsHTTP() bool { return t.Protocol == ProtoHTTP || t.Protocol == ProtoHTTPS }

// IsLDAP reports whether the target speaks LDAP/LDAPS.
func (t Target) IsLDAP() bool { return t.Protocol == ProtoLDAP || t.Protocol == ProtoLDAPS }

// String renders the target back to its canonical scheme-prefixed form.
func (t Target) String() string {
	switch t.Protocol {
	case ProtoSMB:
		return "smb://" + t.Host
	case ProtoHTTP:
		return "http://" + t.Host + t.Path
	case ProtoHTTPS:
		return "https://" + t.Host + t.Path
	case ProtoLDAP:
		return "ldap://" + t.Host
	case ProtoLDAPS:
		return "ldaps://" + t.Host
	}
	return t.Raw
}

// ParseTarget normalizes a configured target string into a Target. Accepted
// forms:
//   - "smb://host[:port]"          (port defaults to 445)
//   - "http://host[:port][/path]"  (port defaults to 80, path defaults to "/")
//   - "https://host[:port][/path]" (port defaults to 443, path defaults to "/")
//   - "ldap://host[:port]"         (port defaults to 389)
//   - "ldaps://host[:port]"        (port defaults to 636, TLS)
//
// Bare "host:port" (no scheme) is rejected with a descriptive error pointing
// callers at the scheme requirement.
func ParseTarget(s string) (Target, error) {
	if s == "" {
		return Target{}, fmt.Errorf("empty target")
	}
	if !strings.Contains(s, "://") {
		return Target{}, fmt.Errorf("target %q requires scheme prefix (smb://, http://, or https://)", s)
	}
	u, err := url.Parse(s)
	if err != nil {
		return Target{}, fmt.Errorf("parse target %q: %w", s, err)
	}
	t := Target{Raw: s}
	switch strings.ToLower(u.Scheme) {
	case "smb":
		t.Protocol = ProtoSMB
	case "http":
		t.Protocol = ProtoHTTP
	case "https":
		t.Protocol = ProtoHTTPS
		t.TLS = true
	case "ldap":
		t.Protocol = ProtoLDAP
	case "ldaps":
		t.Protocol = ProtoLDAPS
		t.TLS = true
	default:
		return Target{}, fmt.Errorf("parse target %q: unsupported scheme %q", s, u.Scheme)
	}
	host := u.Host
	if host == "" {
		return Target{}, fmt.Errorf("parse target %q: empty host", s)
	}
	if _, portStr, err := net.SplitHostPort(host); err != nil {
		// No port — apply scheme default.
		switch t.Protocol {
		case ProtoSMB:
			host += ":445"
		case ProtoHTTP:
			host += ":80"
		case ProtoHTTPS:
			host += ":443"
		case ProtoLDAP:
			host += ":389"
		case ProtoLDAPS:
			host += ":636"
		}
	} else {
		// Reject 0 and out-of-range ports up front so a typo doesn't
		// surface as a confusing "connection refused" later.
		p, perr := strconv.Atoi(portStr)
		if perr != nil || p < 1 || p > 65535 {
			return Target{}, fmt.Errorf("parse target %q: invalid port %q (want 1-65535)", s, portStr)
		}
	}
	t.Host = host
	if t.IsHTTP() {
		t.Path = u.Path
		if t.Path == "" {
			t.Path = "/"
		}
	}
	return t, nil
}

// ParseTargets parses every entry in raw, returning the slice on success or
// the first parse error.
func ParseTargets(raw []string) ([]Target, error) {
	out := make([]Target, 0, len(raw))
	for _, s := range raw {
		t, err := ParseTarget(s)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// filterTargets returns a new slice containing only the entries that pass
// keep. Used by the listener wiring helpers to feed each listener's selector
// only protocol-compatible candidates.
func filterTargets(in []Target, keep func(Target) bool) []Target {
	out := make([]Target, 0, len(in))
	for _, t := range in {
		if keep(t) {
			out = append(out, t)
		}
	}
	return out
}

// smbAnyTargets returns the SMB-protocol targets parsed from cfg.
func smbAnyTargets(parsed []Target) []Target {
	return filterTargets(parsed, func(t Target) bool { return t.Protocol == ProtoSMB })
}

// httpTargets returns the HTTP/HTTPS targets parsed from cfg.
func httpTargets(parsed []Target) []Target {
	return filterTargets(parsed, Target.IsHTTP)
}

// ldapTargets returns the LDAP/LDAPS targets parsed from cfg.
func ldapTargets(parsed []Target) []Target {
	return filterTargets(parsed, Target.IsLDAP)
}
