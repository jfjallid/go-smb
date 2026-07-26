// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid

package server_test

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/smb/server"
	"github.com/jfjallid/go-smb/smb/server/memvfs"
	"github.com/jfjallid/go-smb/spnego"
)

// notifyVFS wraps a memvfs with a ChangeNotifier that returns a canned change
// after a short delay, so the async path can be exercised end to end.
type notifyVFS struct {
	server.VFS
	delay   time.Duration
	changes []server.FileNotifyChange
}

func (n *notifyVFS) WatchChanges(ctx context.Context, h server.Handle, filter uint32, watchTree bool) ([]server.FileNotifyChange, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(n.delay):
		return n.changes, nil
	}
}

// buildChangeNotifyPDU hand-builds an SMB2 CHANGE_NOTIFY request (MS-SMB2
// §2.2.35) for the given handle. The client has no ChangeNotify API, so the PDU
// is assembled here and pushed through SendRawPDU.
func buildChangeNotifyPDU(t *testing.T, sessionID uint64, treeID uint32, fileID []byte, outLen uint32, watchTree bool) []byte {
	t.Helper()
	pdu := make([]byte, 96)
	copy(pdu[0:4], []byte(smb.ProtocolSmb2))
	binary.LittleEndian.PutUint16(pdu[4:6], 64) // header StructureSize
	binary.LittleEndian.PutUint16(pdu[6:8], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(pdu[12:14], smb.CommandChangeNotify)
	binary.LittleEndian.PutUint16(pdu[14:16], 1) // Credits
	binary.LittleEndian.PutUint32(pdu[36:40], treeID)
	binary.LittleEndian.PutUint64(pdu[40:48], sessionID)

	b := pdu[64:]
	binary.LittleEndian.PutUint16(b[0:2], 32) // body StructureSize
	if watchTree {
		binary.LittleEndian.PutUint16(b[2:4], 0x0001)
	}
	binary.LittleEndian.PutUint32(b[4:8], outLen)
	copy(b[8:24], fileID)
	binary.LittleEndian.PutUint32(b[24:28], server.FileNotifyChangeFileName|server.FileNotifyChangeLastWrite)
	return pdu
}

// openDirHandle connects the share and opens its root directory, returning the
// live FileId plus the session and tree ids needed to address it.
func openDirHandle(t *testing.T, c *smb.Connection, share string) (fileID []byte, treeID uint32) {
	t.Helper()
	opts := smb.NewCreateReqOpts()
	opts.CreateOpts = smb.FileDirectoryFile
	opts.DesiredAccess = smb.DAccMaskFileListDirectory | smb.DAccMaskFileReadAttributes
	opts.FileAttr = smb.FileAttrDirectory

	f, err := c.OpenFileExt(share, "", opts)
	if err != nil {
		t.Fatalf("open directory handle: %v", err)
	}
	t.Cleanup(func() { _ = f.CloseFile() })
	return f.FileID(), c.TreeID(share)
}

// TestChangeNotifyWithoutNotifier is the default path: a VFS with no
// ChangeNotifier must answer STATUS_NOT_SUPPORTED promptly. Answering at all is
// the point — a server that stays silent leaves Windows Explorer reissuing the
// request forever.
func TestChangeNotifyWithoutNotifier(t *testing.T) {
	const (
		user, password, domain, share = "alice", "Hunter2!", "WORKGROUP", "files"
	)
	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntlmssp.Ntowfv1(password)}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{Type: smb.ShareTypeDisk, VFS: memvfs.New(memvfs.Options{})})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	fileID, treeID := openDirHandle(t, c, share)
	pdu := buildChangeNotifyPDU(t, c.SessionID(), treeID, fileID, 4096, false)

	resp, err := c.SendRawPDU(pdu)
	if err != nil {
		t.Fatalf("SendRawPDU: %v", err)
	}
	status := binary.LittleEndian.Uint32(resp[8:12])
	if status != smb.StatusNotSupported {
		t.Errorf("status = 0x%08x, want STATUS_NOT_SUPPORTED (0x%08x)", status, smb.StatusNotSupported)
	}
}

// TestChangeNotifyAsyncDelivery drives the full asynchronous path: the server
// must send an interim STATUS_PENDING (which the client's receiver absorbs)
// and then the real response once the notifier fires.
func TestChangeNotifyAsyncDelivery(t *testing.T) {
	const (
		user, password, domain, share = "alice", "Hunter2!", "WORKGROUP", "files"
	)
	srv := &server.Server{
		Config: &server.ServerConfig{
			Authenticator: &server.MapAuthenticator{
				Domain:   domain,
				Accounts: map[string]*server.Account{user: {NTHash: ntlmssp.Ntowfv1(password)}},
			},
		},
	}
	srv.RegisterShare(share, server.Share{
		Type: smb.ShareTypeDisk,
		VFS: &notifyVFS{
			VFS:   memvfs.New(memvfs.Options{}),
			delay: 150 * time.Millisecond,
			changes: []server.FileNotifyChange{
				{Action: server.FileActionAdded, Name: "created.txt"},
			},
		},
	})

	addr, shutdown := startTestServer(t, srv)
	defer shutdown()

	c, err := smb.NewConnection(smb.Options{
		Host:        "127.0.0.1",
		Port:        addr.Port,
		Initiator:   &spnego.NTLMInitiator{User: user, Password: password, Domain: domain},
		DialTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewConnection: %v", err)
	}
	defer c.Close()

	fileID, treeID := openDirHandle(t, c, share)
	pdu := buildChangeNotifyPDU(t, c.SessionID(), treeID, fileID, 4096, true)

	done := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := c.SendRawPDU(pdu)
		if err != nil {
			errCh <- err
			return
		}
		done <- resp
	}()

	select {
	case err := <-errCh:
		t.Fatalf("SendRawPDU: %v", err)
	case resp := <-done:
		status := binary.LittleEndian.Uint32(resp[8:12])
		if status != smb.StatusOk {
			t.Fatalf("status = 0x%08x, want STATUS_SUCCESS", status)
		}
		// The reply must be flagged async and carry a non-zero AsyncId, which
		// is what correlates it back to the interim response.
		flags := binary.LittleEndian.Uint32(resp[16:20])
		if flags&smb.SMB2_FLAGS_ASYNC_COMMAND == 0 {
			t.Error("final response is not flagged SMB2_FLAGS_ASYNC_COMMAND")
		}
		asyncID := uint64(binary.LittleEndian.Uint32(resp[32:36])) |
			uint64(binary.LittleEndian.Uint32(resp[36:40]))<<32
		if asyncID == 0 {
			t.Error("final response carries AsyncId 0")
		}

		// Body: StructureSize(2) OutputBufferOffset(2) OutputBufferLength(4).
		off := binary.LittleEndian.Uint16(resp[66:68])
		length := binary.LittleEndian.Uint32(resp[68:72])
		if length == 0 {
			t.Fatal("response carried no FILE_NOTIFY_INFORMATION")
		}
		if int(off)+int(length) > len(resp) {
			t.Fatalf("output buffer [%d:%d] exceeds the %d-byte response", off, uint32(off)+length, len(resp))
		}
		notify := resp[off : uint32(off)+length]
		if action := binary.LittleEndian.Uint32(notify[4:8]); action != server.FileActionAdded {
			t.Errorf("Action = %d, want FILE_ACTION_ADDED (%d)", action, server.FileActionAdded)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the asynchronous CHANGE_NOTIFY response")
	}
}
