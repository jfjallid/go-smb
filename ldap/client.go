// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

// Package ldap implements a wrapper around the github.com/jfjallid/ldap/v3 package
// to facilitate for clients to use a shared authentication method between ldap and
// DCERPC packages.
package ldap

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/spnego"
	goldap "github.com/jfjallid/ldap/v3"
	"github.com/jfjallid/ldap/v3/gssapi"
)

// SASLMode controls SASL signing/sealing negotiated after a successful bind.
// It aliases the underlying ldap type so callers don't need to import old-ldap.
type SASLMode = goldap.SASLSecurityMode

const (
	SASLNone SASLMode = goldap.SASLSecurityNone
	SASLSign SASLMode = goldap.SASLSecuritySign
	SASLSeal SASLMode = goldap.SASLSecuritySeal
)

// ClientOptions controls transport-level behavior (TCP dial, TLS).
// Credentials do not live here; they are carried by the gss.Mechanism
// passed to Bind.
type ClientOptions struct {
	UseTLS             bool
	UseStartTLS        bool
	InsecureSkipVerify bool
	// Dialer, when non-nil, is used to establish the TCP connection (e.g.
	// a SOCKS5 proxy.Dialer). When nil, net.Dialer with DialTimeout is used.
	Dialer      proxy.Dialer
	DialTimeout time.Duration
}

// Client is a minimal LDAP client layered over jfjallid/ldap/v3. Its bind
// surface is designed around the go-smb spnego initiators so tools can use
// a single credential source for both LDAP and DCERPC.
type Client struct {
	conn   *goldap.Conn
	target string
	opts   ClientOptions
}

func NewClient(opts ClientOptions) *Client {
	return &Client{opts: opts}
}

// Connect dials the LDAP server. For Kerberos authentication, host must be a
// hostname (not an IP) that matches the SPN the ticket was issued for.
// If port is 0, it defaults to 636 for LDAPS or 389 otherwise.
func (c *Client) Connect(host string, port int) error {
	if port == 0 {
		if c.opts.UseTLS {
			port = 636
		} else {
			port = 389
		}
	}
	c.target = host
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	var rawConn net.Conn
	var err error
	if c.opts.Dialer != nil {
		rawConn, err = c.opts.Dialer.Dial("tcp", addr)
	} else {
		d := net.Dialer{Timeout: c.opts.DialTimeout}
		rawConn, err = d.Dial("tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("ldap: dial %s: %w", addr, err)
	}

	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: c.opts.InsecureSkipVerify}
	if c.opts.UseTLS {
		tlsConn := tls.Client(rawConn, tlsConf)
		if err := tlsConn.Handshake(); err != nil {
			rawConn.Close()
			return fmt.Errorf("ldap: TLS handshake: %w", err)
		}
		c.conn = goldap.NewConn(tlsConn, true)
		c.conn.Start()
		return nil
	}

	c.conn = goldap.NewConn(rawConn, false)
	c.conn.Start()
	if c.opts.UseStartTLS {
		if err := c.conn.StartTLS(tlsConf); err != nil {
			c.conn.Close()
			return fmt.Errorf("ldap: StartTLS: %w", err)
		}
	}
	return nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// BindOptions is the per-bind surface. All credentials live on the
// gss.Mechanism; only protocol-level knobs live here.
type BindOptions struct {
	// SPN is the service principal for the LDAP server (Kerberos only).
	// When empty, defaults to "host/<target>".
	SPN string
	// SASLMode controls post-bind SASL signing/sealing. Automatically
	// collapsed to SASLNone when TLS is in use (AD rejects SASL sign/seal
	// over TLS).
	SASLMode SASLMode
	// ChannelBinding enables RFC 5929 tls-server-end-point channel binding.
	// Only meaningful when the connection uses TLS/StartTLS.
	ChannelBinding bool
	// AuthZID is passed through to the SASL GSSAPI handshake.
	AuthZID string
}

// Bind authenticates the connection using the provided GSS mechanism.
// The same initiator instance can be passed to dcerpc.BindAuth to share
// credentials and — for Kerberos — the TGT/TGS ticket cache.
//
// Supported concrete types: *spnego.KRB5Initiator, *spnego.NTLMInitiator.
// NTLM is not routed through a GSS mechanism because AD's LDAP NTLM bind
// is the sicily extension (raw NTLMSSP tokens), not SASL/SPNEGO; see the
// design notes in the package commit message.
//
// On a server-side rejection Bind returns a *BindError; callers can
// errors.As it to inspect Kind and retry with adjusted BindOptions /
// ClientOptions. Setup failures (e.g. Kerberos client init, channel binding
// configuration) are returned as plain wrapped errors and will not match
// *BindError.
func (c *Client) Bind(mech gss.Mechanism, opts BindOptions) error {
	if c.conn == nil {
		return fmt.Errorf("ldap: not connected")
	}

	saslMode := opts.SASLMode
	if c.opts.UseTLS || c.opts.UseStartTLS {
		saslMode = SASLNone
	}

	var err error
	switch m := mech.(type) {
	case *spnego.KRB5Initiator:
		err = c.kerberosBind(m, opts, saslMode)
	case *spnego.NTLMInitiator:
		err = c.ntlmBind(m, opts, saslMode)
	default:
		return fmt.Errorf("ldap: unsupported mechanism %T", mech)
	}
	if err == nil {
		return nil
	}
	overTLS := c.opts.UseTLS || c.opts.UseStartTLS
	fail := goldap.ClassifyBindError(err, overTLS)
	return &BindError{
		Kind:        fail.Kind,
		SubStatus:   fail.SubStatus,
		Description: fail.Description,
		OverTLS:     overTLS,
		Err:         err,
	}
}

func (c *Client) kerberosBind(mech *spnego.KRB5Initiator, opts BindOptions, saslMode SASLMode) error {
	krbClient, err := mech.Client()
	if err != nil {
		return fmt.Errorf("ldap: kerberos init: %w", err)
	}

	// gssapi.Client wraps the gokrb5 client.Client embedded in krb5ssp.Client.
	// Do NOT call gssClient.Close(): that would Destroy the shared gokrb5
	// client and tear down the TGS cache the initiator is still using.
	// GSSAPIBindRequest calls DeleteSecContext internally to clear the
	// per-bind session keys, which is the cleanup we actually want.
	gssClient, err := gssapi.NewClient(krbClient.Client)
	if err != nil {
		return fmt.Errorf("ldap: gssapi client: %w", err)
	}
	gssClient.SASLSecurity = int(saslMode)

	if opts.ChannelBinding && (c.opts.UseTLS || c.opts.UseStartTLS) {
		tlsState, ok := c.conn.TLSConnectionState()
		if ok && len(tlsState.PeerCertificates) > 0 {
			if err := gssClient.SetChannelBinding(tlsState.PeerCertificates[0]); err != nil {
				return fmt.Errorf("ldap: channel binding: %w", err)
			}
		}
	}

	spn := opts.SPN
	if spn == "" {
		spn = "host/" + c.target
	}

	return c.conn.GSSAPIBindRequest(gssClient, &goldap.GSSAPIBindRequest{
		ServicePrincipalName: spn,
		AuthZID:              opts.AuthZID,
		SASLSecurity:         saslMode,
	})
}

func (c *Client) ntlmBind(mech *spnego.NTLMInitiator, opts BindOptions, saslMode SASLMode) error {
	var hashStr string
	if len(mech.Hash) > 0 {
		hashStr = hex.EncodeToString(mech.Hash)
	}
	_, err := c.conn.NTLMChallengeBind(&goldap.NTLMBindRequest{
		Domain:         mech.Domain,
		Username:       mech.User,
		Password:       mech.Password,
		Hash:           hashStr,
		SASLSecurity:   saslMode,
		ChannelBinding: opts.ChannelBinding,
	})
	if err != nil {
		return fmt.Errorf("ldap: ntlm bind: %w", err)
	}
	return nil
}

// Search performs a paged subtree search at baseDN.
func (c *Client) Search(baseDN, filter string, attributes []string, pageSize uint32) (*goldap.SearchResult, error) {
	var err error
	if c.conn == nil {
		return nil, fmt.Errorf("ldap: not connected")
	}
	if baseDN == "" {
		baseDN, err = c.detectBaseDN("defaultNamingContext")
		if err != nil {
			return nil, fmt.Errorf("failed to lookup baseDN: %v", err)
		}
	}
	req := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)
	if pageSize == 0 {
		pageSize = 1000
	}
	res, err := c.conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	return res, nil
}

func (c *Client) detectBaseDN(attr string) (string, error) {
	result, err := c.conn.Search(goldap.NewSearchRequest(
		"", goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{attr},
		nil,
	))
	if err != nil {
		return "", fmt.Errorf("RootDSE query failed: %w", err)
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no RootDSE entry returned")
	}
	dn := result.Entries[0].GetAttributeValue(attr)
	if strings.TrimSpace(dn) == "" {
		return "", fmt.Errorf("%s is empty", attr)
	}
	return dn, nil
}

func ValidateFilter(filter string) error {
	_, err := goldap.CompileFilter(filter)
	return err
}

// TimeToFileTime converts a time.Time object to a Windows FileTime (int64).
// It returns 0 if the input time is zero (representing "never").
func TimeToFileTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}

	// Windows FileTime is the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	// Unix time is seconds since January 1, 1970 (UTC).
	// The difference between epochs is 11644473600 seconds.
	const epochDiff = 11644473600

	// Get Unix seconds
	unixSecs := t.Unix()

	// Calculate seconds since 1601
	fileTimeSecs := unixSecs + epochDiff

	// Convert to 100-nanosecond intervals (multiply by 10,000,000)
	fileTime := fileTimeSecs * 10000000

	return fileTime
}

func ParseFiletime(s string) (int64, error) {
	s = strings.TrimSpace(s)

	// Handle special cases
	if s == "(never)" || s == "(never expires)" {
		return 0, nil
	}

	// Try to parse as plain integer first (if already in FileTime format)
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v, nil
	}

	// Extract datetime part if there's a suffix like " (123456789012345678)"
	datetimePart := s
	if idx := strings.Index(s, " ("); idx != -1 {
		datetimePart = s[:idx]
	}
	datetimePart = strings.TrimSpace(datetimePart)

	// Parse the datetime string (format: "2006-01-02 15:04:05 UTC")
	layout := "2006-01-02 15:04:05 UTC"
	t, err := time.Parse(layout, datetimePart)
	if err != nil {
		return 0, err
	}

	// Convert to Windows FileTime
	// Unix timestamp is seconds since 1970-01-01
	// FileTime is 100-nanosecond intervals since 1601-01-01
	const epochDiff = 11644473600 // seconds between 1601 and 1970
	unixSecs := t.Unix()
	fileTimeSecs := unixSecs + epochDiff
	fileTime := fileTimeSecs * 10000000 // convert to 100-nanosecond intervals

	return fileTime, nil
}
