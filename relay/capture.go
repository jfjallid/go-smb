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
	"time"
)

// CapturedAuth is a finalized record of one inbound NTLM authentication.
// It is what tooling integrators want to consume: timestamps, captured
// hash material, what we did with it, and the upstream we tried.
type CapturedAuth struct {
	Time        time.Time // capture timestamp
	Format      string    // "NetNTLMv1" / "NetNTLMv2"
	Domain      string
	Username    string
	Workstation string
	RemoteAddr  string // victim's address
	Target      string // upstream we relayed to (canonical "host:port" or full URL)
	Status      string // "captured" while in-flight; finalized to "relayed", "upstream_rejected", or "relay_failed"
	Hashcat     string // hashcat-format hash line, ready for -m 5500/5600
}

// CaptureStatus values surfaced on CapturedAuth.Status.
const (
	CaptureStatusInFlight        = "captured"
	CaptureStatusRelayed         = "relayed"
	CaptureStatusUpstreamRejected = "upstream_rejected"
	CaptureStatusRelayFailed     = "relay_failed"
)

// defaultCaptureBufferSize is the default ring-buffer capacity for
// RelayServer.captured when ServerConfig.CaptureBufferSize is unset.
const defaultCaptureBufferSize = 1024

// captureSlot is a handle returned from RelayServer.captureRecord. The
// caller mutates Status via finalize() when the relay outcome is known.
// Buffer eviction may detach the entry from the buffer; finalize still
// fires OnCapture in that case so file writers see every record.
type captureSlot struct {
	rs  *RelayServer
	rec *CapturedAuth
}

// captureRecord appends a new in-flight CapturedAuth to the ring buffer
// and returns a slot for later finalization. If the buffer is at capacity
// the oldest entry is dropped. cred must be non-nil; pre-cred failures
// should not call this. target may be empty if the relay never picked
// one (shouldn't happen on the post-cred path).
func (rs *RelayServer) captureRecord(cred *Credential, target string) *captureSlot {
	if cred == nil {
		return nil
	}
	rec := &CapturedAuth{
		Time:        time.Now(),
		Format:      cred.Format,
		Domain:      cred.Domain,
		Username:    cred.Username,
		Workstation: cred.Workstation,
		Target:      target,
		Status:      CaptureStatusInFlight,
		Hashcat:     cred.Hashcat,
	}
	if cred.RemoteAddr != nil {
		rec.RemoteAddr = cred.RemoteAddr.String()
	}
	rs.captureMu.Lock()
	cap := rs.captureCap
	if cap >= 0 {
		rs.captured = append(rs.captured, rec)
		if cap > 0 && len(rs.captured) > cap {
			// FIFO evict the oldest; the entry continues to live via slot
			// references but won't be reported by CapturedCredentials().
			rs.captured = rs.captured[len(rs.captured)-cap:]
		}
	}
	rs.captureMu.Unlock()
	return &captureSlot{rs: rs, rec: rec}
}

// finalize stamps the slot's Status and fires the OnCapture hook (if any).
// Safe to call on a nil slot — pre-cred failure paths use this to keep call
// sites uniform.
func (s *captureSlot) finalize(status string) {
	if s == nil || s.rec == nil {
		return
	}
	s.rs.captureMu.Lock()
	s.rec.Status = status
	final := *s.rec // copy under lock for the hook
	s.rs.captureMu.Unlock()
	if cb := s.rs.Config.OnCapture; cb != nil {
		cb(final)
	}
}

// CapturedCredentials returns a snapshot of every captured authentication
// still in the ring buffer, oldest first. Entries with Status =
// CaptureStatusInFlight are auths whose upstream outcome isn't decided yet.
func (rs *RelayServer) CapturedCredentials() []CapturedAuth {
	rs.captureMu.Lock()
	defer rs.captureMu.Unlock()
	out := make([]CapturedAuth, len(rs.captured))
	for i, r := range rs.captured {
		out[i] = *r
	}
	return out
}

// captureMu / captured / captureCap live on RelayServer (defined in
// server.go alongside the rest of the runtime state). They're declared
// there so the struct layout stays in one place; this file just owns the
// behavior.
