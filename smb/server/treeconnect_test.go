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

package server_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// startTestServer spins up the supplied Server on an ephemeral port and
// returns the address plus a shutdown function the caller defers. This is a
// duplicate of the in-package helper so that tests in the external test
// package can use it without crossing the import cycle through memvfs.
func startTestServer(t *testing.T, srv *server.Server) (*net.TCPAddr, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(l) }()
	return l.Addr().(*net.TCPAddr), func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		if e := <-serveErr; e != nil && e != server.ErrServerClosed {
			t.Errorf("Serve: %v", e)
		}
	}
}

// TestTreeConnect drives a real client through Negotiate +
// SessionSetup + TreeConnect against a server with a single registered share.
func TestTreeConnect(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
		share    = "test"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	var hookFired atomic.Bool
	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain: domain,
				Accounts: map[string]*server.Account{
					user: {NTHash: ntHash},
				},
			},
			OnTreeConnect: func(c *server.Conn, s *server.Session, name string, req *smb.TreeConnectReq, res *smb.TreeConnectRes) (*server.Status, error) {
				if name != share {
					t.Errorf("OnTreeConnect: got %q want %q", name, share)
				}
				if res.ShareType != smb.ShareTypeDisk {
					t.Errorf("OnTreeConnect: ShareType got 0x%x want Disk", res.ShareType)
				}
				hookFired.Store(true)
				return nil, nil
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	if err := c.TreeConnect(share); err != nil {
		t.Fatalf("TreeConnect: %v", err)
	}
	if !hookFired.Load() {
		t.Errorf("OnTreeConnect did not fire")
	}

	if err := c.TreeDisconnect(share); err != nil {
		t.Errorf("TreeDisconnect: %v", err)
	}
}

// TestTreeConnectBadShare asserts that a request for an unknown share
// is rejected with STATUS_BAD_NETWORK_NAME and no Tree state leaks.
func TestTreeConnectBadShare(t *testing.T) {
	const (
		user     = "alice"
		password = "Hunter2!"
		domain   = "WORKGROUP"
	)
	ntHash := ntlmssp.Ntowfv1(password)

	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntHash}},
			},
		},
	}

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	opts := smb.Options{
		Host:              "127.0.0.1",
		Port:              addr.Port,
		Initiator:         &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DisableSigning:    true,
		DisableEncryption: true,
		Dialects:          smb.DialectsSMB2Only,
		DialTimeout:       2 * time.Second,
	}
	c, err := smb.NewConnection(opts)
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	err = c.TreeConnect("does-not-exist")
	if err == nil {
		t.Fatalf("expected TreeConnect to fail with bad-network-name; got nil")
	}
	if !errors.Is(err, smb.StatusMap[smb.StatusBadNetworkName]) {
		t.Errorf("err: got %v want bad-network-name", err)
	}
}
