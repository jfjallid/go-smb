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

package server

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// TestNegotiate spins up the server on an ephemeral TCP port, drives it
// from this repo's own smb.NewConnection in ManualLogin mode (so SessionSetup
// is skipped), and verifies that the SMB1->SMB2 multi-protocol handshake plus
// the subsequent SMB2 NegotiateReq are answered correctly.
func TestNegotiate(t *testing.T) {
	cases := []struct {
		name              string
		forceSMB2         bool // client flag: only offer SMB 2.1
		disableSigning    bool
		disableEncryption bool
	}{
		// SMB 2.1 with everything off — exercises the simple non-3.1.1 path.
		{name: "smb_2_1_only", forceSMB2: true, disableSigning: true, disableEncryption: true},
		// SMB 3.1.1 with encryption off but signing left enabled — the
		// client refuses 3.1.1 with both off, so we allow signing here.
		{name: "smb_3_1_1", forceSMB2: false, disableSigning: false, disableEncryption: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runNegotiateTest(t, tc.forceSMB2, tc.disableSigning, tc.disableEncryption)
		})
	}
}

func runNegotiateTest(t *testing.T, forceSMB2, disableSigning, disableEncryption bool) {
	t.Helper()

	var negotiateHookFired atomic.Bool
	srv := &Server{
		Config: &ServerConfig{
			OnNegotiate: func(c *Conn, req *smb.NegotiateReq, res *smb.NegotiateRes) error {
				negotiateHookFired.Store(true)
				return nil
			},
		},
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()

	addr := l.Addr().(*net.TCPAddr)

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		ManualLogin:       true,
		DisableSigning:    disableSigning,
		DisableEncryption: disableEncryption,
		ForceSMB2:         forceSMB2,
		DialTimeout:       2 * time.Second,
	}

	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("smb.NewConnection: %v", err)
	}
	c.Close()

	if !negotiateHookFired.Load() {
		t.Errorf("OnNegotiate hook never fired")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-serveErr; err != nil && err != ErrServerClosed {
		t.Errorf("Serve returned: %v", err)
	}
}
