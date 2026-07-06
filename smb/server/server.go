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

// Package server provides a minimal but extensible SMB2/3 server intended for
// hosting a file server, capturing NetNTLM credentials from coerced
// authentication, and (later) relaying authentication to a third-party target.
//
// Most behavior is customizable via function-field hooks on ServerConfig,
// modeled on net/http.Server.
package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfjallid/golog"

	"github.com/jfjallid/go-smb/smb"
)

// SessionSetupStage identifies which leg of the SessionSetup exchange has
// arrived. The default acceptor parses the security blob and dispatches by
// leading byte (0x60 = NegTokenInit -> stage Negotiate; 0xa1 = NegTokenResp
// -> stage Authenticate).
type SessionSetupStage int

const (
	SessionSetupStageNegotiate    SessionSetupStage = 1
	SessionSetupStageAuthenticate SessionSetupStage = 3
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/server").SetDisplayName("smb/server")

// ErrServerClosed is returned by Serve and ListenAndServe after a call to
// Shutdown or Close.
var ErrServerClosed = fmt.Errorf("server closed")

// Logger is the small subset of golog used by the server. Override
// ServerConfig.Logger to integrate with custom logging (e.g. SIEM forwarders).
type Logger interface {
	Errorf(format string, v ...any)
	Errorln(v ...any)
	Noticef(format string, v ...any)
	Noticeln(v ...any)
	Infof(format string, v ...any)
	Infoln(v ...any)
	Debugf(format string, v ...any)
	Debugln(v ...any)
}

// Status is returned by hooks to short-circuit the default handler with a
// custom NT status code. Body, when non-nil, replaces the default response
// body bytes (header is built by the server). When the response struct is
// already populated and only the status code differs, leave Body nil.
//
// SecurityBlob, when non-nil, is used by SessionSetup hooks (and only those)
// to inject a SPNEGO-wrapped security blob into the outbound
// SessionSetupRes. Useful for relay flows where the upstream's CHALLENGE
// (leg 1) or accept-completed token (leg 2) needs to be forwarded to the
// inbound client.
type Status struct {
	Code         uint32
	Body         []byte
	SecurityBlob []byte
}

// ServerConfig holds the tunable knobs for a Server. Function-field hooks
// allow callers to observe or override every protocol step. Hooks are called
// synchronously from the per-connection goroutine.
//
// Hook return convention:
//   - return (nil, nil): default handler runs.
//   - return (&Status{Code: ntstatus, Body: optional}, nil): server replies
//     with the supplied status (and body, if set), default handler is skipped.
//   - return (nil, err): the connection is aborted.
type ServerConfig struct {
	// ServerGUID is advertised in NegotiateRes. A random value is generated
	// if zero.
	ServerGUID [16]byte

	// NetBIOS / DNS identity advertised in the NTLMSSP TargetInfo AVPairs.
	// Defaults to "GO-SMB" / empty if unset.
	NetBIOSName     string
	NetBIOSDomain   string
	DnsComputerName string
	DnsDomainName   string
	NtlmTargetName  string // NTLMSSP TargetName; defaults to NetBIOSName

	// MinDialect / MaxDialect bound the SMB2 dialects the server will accept
	// during Negotiate. Default: smb.DialectSmb_2_1 .. smb.DialectSmb_3_1_1.
	MinDialect uint16
	MaxDialect uint16

	// SigningRequired advertises SecurityModeSigningRequired and rejects
	// unsigned requests once a session is established.
	SigningRequired bool

	// EncryptionSupported advertises GlobalCapEncryption and gates SMB 3.x
	// transport encryption.
	EncryptionSupported bool

	// RequireEncryption forces every authenticated session into the SMB 3.x
	// transport-encryption regime: the server sets SessionFlagEncryptData
	// at SessionSetup time, expects every inbound PDU to arrive inside a
	// TransformHeader, and wraps every outbound reply. Implies
	// EncryptionSupported. Clients without GlobalCapEncryption in their
	// NegotiateReq capability set will fail SessionSetup with
	// STATUS_ACCESS_DENIED.
	RequireEncryption bool

	// Maximum sizes advertised in NegotiateRes. Defaults: 65536 each.
	MaxReadSize     uint32
	MaxWriteSize    uint32
	MaxTransactSize uint32

	// Shares maps the wire-visible share name (case-insensitive) to the
	// share definition. Use (*Server).RegisterShare to populate this without
	// allocating the map yourself. IPC$ is auto-provided as a Pipe share if
	// not explicitly registered.
	Shares map[string]Share

	// PipeOpener routes named-pipe opens (Create on a Pipe-typed share, e.g.
	// IPC$) to per-open backends. When nil, all pipe opens fail with
	// STATUS_OBJECT_NAME_NOT_FOUND. The default IPC$ share auto-provided by
	// lookupShare is a Pipe share, so installing a non-nil PipeOpener is the
	// minimum needed to answer share-enumeration RPCs.
	PipeOpener PipeOpener

	// Authenticator verifies parsed NTLMSSP AUTHENTICATE messages. Default:
	// AlwaysFailAuthenticator (capture mode — every login fails after the
	// hash is captured via OnCredentialCaptured).
	Authenticator Authenticator

	// AllowAnonymous lets clients with empty NT/LM responses obtain a null
	// session (sessionFlags |= SessionFlagIsNull). Default false. Useful for
	// hosting payload shares to clients that don't authenticate.
	AllowAnonymous bool

	// AllowGuest grants a guest session (sessionFlags |= SessionFlagIsGuest)
	// when authentication fails but the user/password were non-empty.
	// Default false.
	AllowGuest bool

	// Hooks. Any nil hook means "use default behavior".

	// OnConnect fires after a TCP accept, before any framing has been read.
	// Returning a non-nil error closes the connection without a reply.
	OnConnect func(c *Conn) error
	// OnDisconnect fires after the connection has been torn down (best
	// effort; not invoked if the process is killed).
	OnDisconnect func(c *Conn)

	// OnNegotiate fires after the server has parsed a NegotiateReq and
	// populated a default NegotiateRes. The hook can mutate either side.
	// Returning a non-nil error aborts the connection.
	OnNegotiate func(c *Conn, req *smb.NegotiateReq, res *smb.NegotiateRes) error

	// OnSessionSetup fires for each leg of the SessionSetup exchange after
	// the inbound blob has been peeled out of the SMB2 envelope. The Conn,
	// Session (allocated on the first leg), the SecurityBlob bytes, and the
	// stage are passed in. Returning a non-nil *Status replaces the default
	// SMB-level reply status (e.g. force StatusAccessDenied without
	// processing the NTLMSSP). Status.SecurityBlob, when non-nil, is sent
	// verbatim as the outbound SessionSetupRes.SecurityBlob — relay flows
	// inject the upstream's wrapped NTLMSSP CHALLENGE here on leg 1 and the
	// upstream's accept-completed token on leg 2.
	//
	// Hooks that return a non-nil *Status own the session lifetime: the
	// server does NOT auto-evict the session, so the hook must call
	// (*Conn).RemoveSession explicitly when it wants the session destroyed
	// (e.g. capture-and-drop relay leg 2 — the hook discards the inbound
	// session and keeps a separate upstream Connection alive in its pool).
	//
	// Returning (nil, err) aborts the connection.
	OnSessionSetup func(c *Conn, s *Session, securityBlob []byte, stage SessionSetupStage) (*Status, error)

	// OnCredentialCaptured fires once per AUTHENTICATE message, regardless of
	// the verify outcome. Useful for honeypot logging / SIEM forwarding.
	OnCredentialCaptured func(c *Conn, cred *Credential)

	// OnLogoff fires when the client cleanly tears down a session.
	OnLogoff func(c *Conn, s *Session)

	// OnTreeConnect fires after the server has parsed a TreeConnectReq and
	// looked up the requested share. The hook receives the resolved share
	// name (without the "\\host\" prefix) and the default-populated res
	// struct. Returning a non-nil *Status replaces the default reply status.
	OnTreeConnect func(c *Conn, s *Session, share string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*Status, error)

	// OnTreeDisconnect fires after a successful TreeDisconnect, before any
	// open handles are forcibly closed.
	OnTreeDisconnect func(c *Conn, s *Session, t *Tree)

	// OnEcho fires for each inbound SMB2 Echo (keepalive) request before the
	// default StatusOk reply is written. Useful for liveness logging or to
	// short-circuit the connection (returning a non-nil error aborts).
	OnEcho func(c *Conn) error

	// OnRawRequest fires for every inbound PDU (post-NetBIOS-framing,
	// pre-dispatch) and provides a hook for relay/instrumentation. Returning
	// (true, nil) means "I wrote a reply myself, do not dispatch."
	OnRawRequest func(c *Conn, raw []byte) (handled bool, err error)
	// OnRawResponse fires after the default handler builds a reply but before
	// signing/encryption/wire-write. Mutation of the returned slice is allowed.
	OnRawResponse func(c *Conn, raw []byte) ([]byte, error)

	// OnUnknownCommand fires for any SMB2 command not handled by the current
	// build. Default: respond with STATUS_NOT_SUPPORTED.
	OnUnknownCommand func(c *Conn, h *smb.Header, body []byte) (*Status, error)

	// Logger overrides the default golog logger.
	Logger Logger
}

// authenticator returns the configured Authenticator or the default
// AlwaysFailAuthenticator.
func (cfg *ServerConfig) authenticator() Authenticator {
	if cfg != nil && cfg.Authenticator != nil {
		return cfg.Authenticator
	}
	return AlwaysFailAuthenticator{}
}

// netbiosName returns NetBIOSName or a sensible default.
func (cfg *ServerConfig) netbiosName() string {
	if cfg != nil && cfg.NetBIOSName != "" {
		return cfg.NetBIOSName
	}
	return "GO-SMB"
}

// ntlmTargetName returns NtlmTargetName or falls back to netbiosName.
func (cfg *ServerConfig) ntlmTargetName() string {
	if cfg != nil && cfg.NtlmTargetName != "" {
		return cfg.NtlmTargetName
	}
	return cfg.netbiosName()
}

// encryptionSupported reports whether the server should advertise / accept
// SMB 3.x encryption. Either EncryptionSupported or RequireEncryption
// implies the capability bit is set in NegotiateRes.
func (cfg *ServerConfig) encryptionSupported() bool {
	return cfg != nil && (cfg.EncryptionSupported || cfg.RequireEncryption)
}

// dialectsAllowed returns the SMB2 dialects between Min and Max inclusive in
// preference order (highest first).
func (cfg *ServerConfig) dialectsAllowed() []uint16 {
	min := cfg.MinDialect
	if min == 0 {
		min = smb.DialectSmb_2_1
	}
	max := cfg.MaxDialect
	if max == 0 {
		max = smb.DialectSmb_3_1_1
	}
	all := []uint16{
		smb.DialectSmb_3_1_1,
		smb.DialectSmb_3_0_2,
		smb.DialectSmb_3_0,
		smb.DialectSmb_2_1,
		smb.DialectSmb_2_0_2,
	}
	out := make([]uint16, 0, len(all))
	for _, d := range all {
		if d >= min && d <= max {
			out = append(out, d)
		}
	}
	return out
}

// logger returns the configured Logger, falling back to the package logger.
func (cfg *ServerConfig) logger() Logger {
	if cfg != nil && cfg.Logger != nil {
		return cfg.Logger
	}
	return log
}

// Server hosts an SMB2/3 service. The zero value is not usable; create one
// with a non-nil Config.
type Server struct {
	Config *ServerConfig

	mu         sync.Mutex
	listeners  map[net.Listener]struct{}
	conns      map[*Conn]struct{}
	inShutdown atomic.Bool
	doneCh     chan struct{}

	// Lazily-initialized random ServerGUID when Config.ServerGUID is zero.
	serverGUIDOnce sync.Once
	serverGUID     [16]byte
}

// resolvedServerGUID returns the configured ServerGUID, or a process-stable
// random GUID if the configured value is zero.
func (s *Server) resolvedServerGUID() [16]byte {
	s.serverGUIDOnce.Do(func() {
		if s.Config != nil && s.Config.ServerGUID != ([16]byte{}) {
			s.serverGUID = s.Config.ServerGUID
			return
		}
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			s.Config.logger().Errorln("ServerGUID rand failure:", err)
		}
		s.serverGUID = b
	})
	return s.serverGUID
}

// trackListener adds/removes a listener from the active set. Returns false if
// the server is shutting down and the listener should not be served.
func (s *Server) trackListener(l net.Listener, add bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners == nil {
		s.listeners = make(map[net.Listener]struct{})
	}
	if add {
		if s.inShutdown.Load() {
			return false
		}
		s.listeners[l] = struct{}{}
	} else {
		delete(s.listeners, l)
	}
	return true
}

func (s *Server) trackConn(c *Conn, add bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = make(map[*Conn]struct{})
	}
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
}

// ListenAndServe listens on the given TCP address (":445" if empty) and
// serves SMB connections until Shutdown or Close is called.
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = ":445"
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts incoming connections on l and spawns one goroutine per
// connection. Serve always returns a non-nil error; after Shutdown or Close
// the returned error is ErrServerClosed.
func (s *Server) Serve(l net.Listener) error {
	if s.Config == nil {
		s.Config = &ServerConfig{}
	}
	if !s.trackListener(l, true) {
		return ErrServerClosed
	}
	defer s.trackListener(l, false)
	defer l.Close()

	logger := s.Config.logger()
	logger.Noticef("accepting on %s", l.Addr())

	for {
		nc, err := l.Accept()
		if err != nil {
			if s.inShutdown.Load() {
				return ErrServerClosed
			}
			return err
		}

		c := newConn(s, nc)
		s.trackConn(c, true)
		go func() {
			// Defense in depth: c.serve recovers its own panics, but guard the
			// goroutine body too so a panic outside serve's recover scope can
			// never tear down the accept loop / process.
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("recovered from panic in connection goroutine: %v", r)
				}
			}()
			defer s.trackConn(c, false)
			c.serve()
		}()
	}
}

// Shutdown stops accepting new connections, then waits for active connections
// to drain (or until ctx is done).
func (s *Server) Shutdown(ctx context.Context) error {
	s.inShutdown.Store(true)

	s.mu.Lock()
	for l := range s.listeners {
		l.Close()
	}
	s.mu.Unlock()

	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// evictPreviousSession evicts any session matching prevID owned by the
// same (case-insensitively compared) user@domain across every Conn the
// Server currently tracks, except for the newly-installed session
// identified by (newConn, newID). MS-SMB2 §3.3.5.5.3 step 6: the eviction
// happens once the new SessionSetup has succeeded with an authenticated
// principal, so we can match by username (a no-op SessionID match without
// the user guard would let an attacker stomp another user's session).
//
// Eviction closes any open trees on the victim and removes it from its
// Conn's session table. The Conn itself stays alive — a real client may
// reuse the underlying TCP connection for other sessions.
func (s *Server) evictPreviousSession(prevID uint64, user, domain string, newConn *Conn, newID uint64, logger Logger) {
	s.mu.Lock()
	conns := make([]*Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	matchUser := strings.ToLower(user)
	matchDomain := strings.ToLower(domain)
	for _, c := range conns {
		victim := c.session(prevID)
		if victim == nil {
			continue
		}
		if c == newConn && victim.ID == newID {
			continue
		}
		if strings.ToLower(victim.Username) != matchUser || strings.ToLower(victim.Domain) != matchDomain {
			continue
		}
		if logger != nil {
			logger.Debugf("evicting previous session %d for user %s\\%s on %s", prevID, domain, user, c.RemoteAddr)
		}
		// Close any tree handles before removing the session from the
		// table so VFS implementations see Close before the session
		// disappears.
		c.cleanupSession(victim)
		c.removeSession(prevID)
	}
}

// Close immediately tears down all listeners and active connections.
func (s *Server) Close() error {
	s.inShutdown.Store(true)
	s.mu.Lock()
	defer s.mu.Unlock()
	for l := range s.listeners {
		l.Close()
	}
	for c := range s.conns {
		c.close()
	}
	return nil
}

// formatErr is a small helper used in places that need a wrapped error string.
func formatErr(prefix string, err error) error {
	return fmt.Errorf("%s: %w", prefix, err)
}
