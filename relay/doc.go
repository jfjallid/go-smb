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

// Package relay provides NTLMSSP relay functionality on top of the
// smb/server SMB listener and the smb/client. It currently exposes:
//
//   - RelayClient: a one-shot listener that accepts a single inbound auth,
//     forwards it to a configured target, and returns the resulting
//     authenticated *smb.Connection. Replacement for the legacy
//     smb.NewRelayConnection.
//   - RelayServer: a long-running multi-target listener with a pooled
//     session cache, optional SOCKS5 proxy that exposes the pool to local
//     tools, and post-auth actions. Inbound SMB and HTTP listeners share one
//     unified ServerConfig.Targets list (scheme-prefixed: smb://, http://,
//     https://, ldap://, ldaps://) — any inbound listener can route to any
//     upstream protocol, so HTTP-to-SMB and SMB-to-HTTP relay both work
//     out of the box.
//   - SMBPassthrough / HTTPPassthrough / LDAPPassthrough: SOCKS-fronted
//     raw-PDU forwarders for pooled upstreams.
//
// # Configuration knobs
//
// Most of ServerConfig is read once at Start(). Three behaviors are
// mutable on a running server:
//
//   - StripMechListMIC — toggle via [RelayServer.SetStripMechListMIC]
//   - HealthCheckOnSelect — toggle via [RelayServer.SetHealthCheckOnSelect]
//   - SelectTarget — replace via [RelayServer.SetSelectTarget]
//
// Other fields take their Start()-time value.
//
// # Captured credentials
//
// Each successful inbound auth produces a [CapturedAuth] record with the
// upstream relay status (CaptureStatusRelayed, CaptureStatusUpstreamRejected,
// CaptureStatusRelayFailed). Records flow through two channels:
//
//   - [ServerConfig.OnCapture] fires once per finalized record — ideal for
//     streaming captures to a file or external system.
//   - [RelayServer.CapturedCredentials] returns a snapshot of an in-memory
//     FIFO ring buffer (sized via ServerConfig.CaptureBufferSize, default
//     1024) for ad-hoc inspection.
//
// # Cross-protocol caveat
//
// When relaying TYPE_2 (CHALLENGE) from one transport to a victim on
// another, the TargetName/TargetInfo AV pairs reflect the upstream
// service. EPA-strict clients may abort. Strip-mic (via
// ServerConfig.StripMechListMIC) opts out of MechListMIC pass-through for
// upstreams that re-derive the MIC themselves.
package relay

import "github.com/jfjallid/golog"

var log = golog.Get("github.com/jfjallid/go-smb/relay").SetDisplayName("relay")
