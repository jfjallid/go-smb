# Changelog

All notable future changes to this project are documented here as well as
the most recent history of changes. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/). The **[Unreleased]**
section collects changes that have landed but not yet been tagged;
at release time it is renamed to the new version and a fresh
**[Unreleased]** is started above it.

## [Unreleased]

Headline items this cycle are a batch of SMB 2.1–3.1.1 client protocol
conformance work (SMB 3.0/3.0.2 dialects, credit-based flow control with the
Windows request/grow/split strategy, per-share encryption, and oplock-break /
CANCEL handling), an explicit NTLM authentication mode, reliable detection of
accepted guest/null sessions, and the removal of the long-unused credential
fields on `smb.Options`.

### SMB2/3 client protocol conformance

A batch of MS-SMB2 client-side improvements:

- **SMB 3.0 / 3.0.2 dialects are now offered.** Previously the client jumped
  straight from 3.1.1 to 2.1, so any server capped at 3.0/3.0.2 silently
  downgraded to 2.1 and lost SMB3 signing and encryption. The negotiate offer
  now includes `0x0302`/`0x0300`, with the matching key-derivation path
  (fixed AES-128-CMAC signing, AES-128-CCM encryption, and the SMB 3.0 KDF
  label/context pairs per MS-SMB2 §3.1.4.2).
- **Custom dialect offer via `Options.Dialects`.** A caller can now override the
  set of SMB2 dialects advertised in NEGOTIATE (e.g. to require 3.1.1 only or
  exclude 2.0.2). Entries are validated against the known revisions; the
  3.1.1-only negotiate contexts are emitted only when 3.1.1 is offered, and
  setting the field takes the direct SMB2 negotiate path (the SMB1
  multi-protocol probe cannot honor a custom list). Leaving it nil keeps the
  default offer.
- **`Options.ForceSMB2` removed (breaking).** The flag was equivalent to
  offering only SMB 2.1, which `Options.Dialects` now expresses directly. Set
  `Dialects: smb.DialectsSMB2Only` (a new convenience value for
  `[]uint16{smb.DialectSmb_2_1}`) to pin the legacy 2.1 path. Unlike the old
  flag, this also skips the SMB1 multi-protocol probe and goes straight to the
  SMB2 negotiate.
- **Per-share encryption is honored (MS-SMB2 §3.2.5.5).** TreeConnect now
  captures `ShareFlags`, `Capabilities` and `MaximalAccess` (exposed via
  `Session.TreeConnectInfo`). A share flagged `SMB2_SHAREFLAG_ENCRYPT_DATA`
  gets its traffic encrypted; if the connection cannot encrypt end-to-end the
  tree connect fails with the new `smb.ErrShareRequiresEncryption` instead of
  sending traffic the server rejects.
- **Credit-based flow control (MS-SMB2 §3.2.4.1.2).** The client now maintains
  a real credit balance: it consumes `CreditCharge` credits per request
  (blocking when short) and replenishes from each response's granted credits.
  The server side was correspondingly fixed to grant credits commensurate with
  the request (it previously granted a flat 1, which starves a compliant
  client on multi-credit operations). The client now also follows the Windows
  credit strategy end-to-end:
    - **Ask for more.** Every credit-managed request advertises a
      `CreditRequest` that covers its charge and grows the granted balance
      toward a target (default 512 credits ≈ a 32 MiB window), so the window
      climbs and holds instead of draining. Configurable via the new
      `Options.CreditTarget`.
    - **Never exceed / split.** Large `ReadFile`/`WriteFile` calls are split
      into requests whose `CreditCharge` fits the current window (and the
      server-advertised `MaxReadSize`/`MaxWriteSize`), so a single transfer can
      never require more credits than the server will grant.
    - **Deadlock-free by construction.** Credit reservation happens off the
      send mutex, connection teardown wakes any waiter, and a bounded wait
      (default 60 s, configurable via the new `Options.CreditReserveTimeout`;
      negative waits forever) turns a starved window into an error rather than
      a hang.
    - `calcCreditCharge` now uses the integer formula from MS-SMB2 §3.1.5.2;
      it previously over-charged by one credit at exact 64 KiB multiples.
- **`ReadFile`/`WriteFile` transfer semantics.** As a consequence of credit
  splitting, `File.ReadFile` is now `io.Reader`-style: it may return
  `n < len(b)` for a single call even when more data is available, and callers
  should loop on the returned offset (`RetrieveFile` already does).
  `File.WriteFile` now always writes the *entire* buffer, looping internally as
  needed — this also fixes a latent bug where, against a server without
  multi-credit support, only the first 64 KiB of a larger buffer was written.
- **Unsolicited oplock break handling + CANCEL (MS-SMB2 §2.2.23/24, §2.2.30).**
  Server break notifications (reserved MessageId `0xFFFF…`) are routed to an
  optional handler (`Session.SetOplockBreakHandler`) and acknowledged instead
  of being dropped. `Connection.SendCancel` issues an SMB2 CANCEL; the server
  now exempts CANCEL from duplicate-MessageId detection as the spec requires.
- **New client commands: `Connection.Echo` (keepalive, §2.2.28) and
  `File.Flush` (§2.2.17).**

### Breaking changes

**1. `smb.Options` credential fields removed.**

The `User`, `Password`, `Hash`, and `Domain` fields have been removed from
`smb.Options`. They were never read by the library — authentication has always
been driven exclusively by `Options.Initiator` — so setting them had no effect.

```go
// Before (User/Password/Hash/Domain were ignored)
opts := smb.Options{
    Host:     host,
    User:     user,
    Password: pass,
    Domain:   domain,
    Initiator: &spnego.NTLMInitiator{User: user, Password: pass, Domain: domain},
}
// After — supply credentials only through the Initiator
opts := smb.Options{
    Host:      host,
    Initiator: &spnego.NTLMInitiator{User: user, Password: pass, Domain: domain},
}
```

Code that set these fields will no longer compile; move the values into the
`Initiator`. Code that relied on them for authentication was already silently
broken and must do the same.

**2. Guest authentication no longer sets `NTLMSSP_NEGOTIATE_ANONYMOUS`.**

An NTLM guest attempt (empty username, real NTLMv2 response) previously set the
`NTLMSSP_NEGOTIATE_ANONYMOUS` flag in the AUTHENTICATE message, which is
inconsistent with MS-NLMP — that flag denotes a credential-less session. The
flag is now set only for a true anonymous/null session. This changes the bytes
on the wire for the guest path but not the Go API.

### New features

- **Explicit NTLM auth mode.** `ntlmssp.Client` and `spnego.NTLMInitiator` gain
  an `AuthMode` field of type `NTLMAuthMode` with values `NTLMAuthCredentials`,
  `NTLMAuthAnonymous`, and `NTLMAuthGuest`, re-exported from `spnego` for
  convenience. This makes the auth intent explicit rather than inferring it from
  an empty username. The zero value preserves the previous behaviour: the
  deprecated `NullSession bool` still selects anonymous, and an empty `User`
  still selects guest.
- **Reliable session-type detection.** `smb.Session` gains `AuthResult()`,
  returning a `SessionAuthResult` (`AuthResultUser` / `AuthResultGuest` /
  `AuthResultAnonymous`), so a caller can fingerprint how a server treated an
  authentication attempt (run a probe with normal creds, `NTLMAuthAnonymous`,
  or `NTLMAuthGuest` and read the result). `IsNullSession()` now reports an
  accepted anonymous/null session — the client sent
  `NTLMSSP_NEGOTIATE_ANONYMOUS` and SessionSetup succeeded — rather than merely
  echoing the server's `SMB2_SESSION_FLAG_IS_NULL`, which some servers omit even
  when they accept a null session. `IsGuestSession()` continues to reflect the
  server's `SMB2_SESSION_FLAG_IS_GUEST`, the only signal for guest since the
  client cannot infer it. (Note that "null session" and "anonymous" are the same
  NTLM mechanism.)
- **Raw (non-SPNEGO) NTLMSSP.** Both sides now speak bare NTLMSSP — the framing
  the Linux kernel CIFS client (`mount.cifs`) uses, where the SessionSetup blob
  is an NTLMSSP token with no SPNEGO wrapper. The server auto-detects it by the
  `NTLMSSP\0` signature and routes each leg through the existing acceptor, so
  Linux clients can now mount a go-smb share; Windows and SPNEGO clients are
  unaffected. The client can opt into offering it via the new
  `Options.RawNTLMSSP` (NTLM only; requires a `*spnego.NTLMInitiator`).

### Server interoperability fixes

Three defects made a default-configured go-smb server unreachable by real
Windows clients (WinPE `net use` failed before authentication, with nothing
logged); each moved the connection reset one step later on the wire:

- **Empty `SMB2_COMPRESSION_CAPABILITIES` context is no longer emitted.** The
  3.1.1 Negotiate Response echoed a compression context with
  `CompressionAlgorithmCount == 0`, which MS-SMB2 §2.2.3.1.3 forbids (the count
  MUST be > 0); Windows reset the connection on reading it. A server with no
  compression now omits the context entirely.
- **CHALLENGE no longer inherits `NTLMSSP_NEGOTIATE_LM_KEY`.** LM_KEY and
  `EXTENDED_SESSIONSECURITY` are mutually exclusive (MS-NLMP §2.2.2.5) and the
  server always asserts the latter, so inheriting LM_KEY from a client that
  requested both produced a spec-violating CHALLENGE.
- **CHALLENGE TargetInfo defaults from `NetBIOSName`.** When the domain/DNS
  fields are unset the server now fills the `MsvAv*` domain/DNS pairs from
  `NetBIOSName` instead of omitting them; Windows rejects a CHALLENGE that
  lacks them. A minimally-configured server is now usable by Windows.

Also: a NEGOTIATE with no mutually-supported dialect now returns
`STATUS_NOT_SUPPORTED` (MS-SMB2 §3.3.5.4) instead of silently dropping the
connection, and the client surfaces that status instead of a misleading parse
error. Dialect revisions are logged as friendly version strings.

### Client encryption

- **`Options.RequireEncryption`.** Opts the whole session into encrypt-all:
  every request is wrapped in a TransformHeader regardless of the server's or
  share's flags. Mutually exclusive with `DisableEncryption` (which wins).
- **The server's encryption verdict is now honored (MS-SMB2 §3.2.5.3.1).**
  Previously the client forced session-wide encryption whenever it merely
  *supported* it. It now only encrypts session-wide when the server sets
  `SMB2_SESSION_FLAG_ENCRYPT_DATA` (including when the server asserts it only on
  the final SessionSetup response) or the caller set `RequireEncryption`;
  otherwise per-tree enforcement encrypts individual `ENCRYPT_DATA` shares while
  plaintext shares stay unwrapped.
- **Encrypted responses are no longer wrongly rejected by the signing check.**
  On a signing-required session negotiating a pre-3.1.1 dialect with encryption,
  the reader ran the plaintext signature check on encrypted PDUs (which carry
  their own AEAD integrity and never set `SMB2_FLAGS_SIGNED`) and tore the
  connection down. The check is now skipped for encrypted PDUs.

## [0.11.0] — 2026-07-06

Headline items this cycle are a logging and error-handling overhaul, a pass
of untrusted-input hardening, completion of the NDR response-side migration,
and new WMI query and server-VFS query support.

**Logging and error-handling overhaul.**

This release reworks how errors are logged and returned across the library.
Previously an error was frequently both logged in place **and** returned, so a
single failure produced several identical log lines as it propagated up the
call chain, and none of them named the operation that failed. The new model is:

> **An error is either logged or returned, never both.** Context travels with
> the error via `fmt.Errorf("<operation>: %w", err)` wrapping; a single log line
> at the boundary (a background goroutine, the SMB/DCERPC servers, the relay)
> tells the whole story.

### Breaking changes

**1. RPC and SMB status errors are now typed wrappers.**

Non-zero DCERPC return codes are returned as `*dcerpc.StatusError`, and
non-success SMB NTSTATUS values as `*smb.NTStatusError`. Both preserve the raw
code and wrap the mapped sentinel from the relevant status map:

```go
type StatusError struct {       // package dcerpc
    Op   string // RPC operation, e.g. "SamrConnect5"
    Code uint32 // raw return code, preserved even when unmapped
    Err  error  // mapped sentinel from the service's response-code map, or nil
}

type NTStatusError struct {     // package smb
    Op     string
    Status uint32
    Err    error  // mapped sentinel from smb.StatusMap, or nil
}
```

Because these wrap the map sentinel, **identity comparisons no longer match.**
Downstream code that did:

```go
if err == smb.StatusMap[smb.StatusAccessDenied] { ... }
if err == mssamr.ResponseCodeMap[mssamr.StatusNoSuchGroup] { ... }
```

must switch to `errors.Is`:

```go
if errors.Is(err, smb.StatusMap[smb.StatusAccessDenied]) { ... }
if errors.Is(err, mssamr.ResponseCodeMap[mssamr.StatusNoSuchGroup]) { ... }
```

The raw code is also newly available for inspection:

```go
var se *dcerpc.StatusError
if errors.As(err, &se) {
    log.Printf("op %s failed with code 0x%08x", se.Op, se.Code)
}
```

A DCERPC **Fault** PDU is likewise now returned as `*dcerpc.FaultError`
(previously a plain `fmt.Errorf("DCERPC Fault PDU received with status: ...")`).
It preserves the raw fault status in `Code` and wraps a sentinel for the
recognised codes, so faults can be matched with `errors.Is`:

```go
if errors.Is(err, dcerpc.ErrAccessDenied) { ... }
if errors.Is(err, dcerpc.ErrContextMismatch) { ... }
```

**2. Error message text now carries an operation prefix.**

Error strings are now of the form `"<operation>: <message>"`, e.g.
`SamrOpenGroup: The group does not exist`. Code that matched on the bare
message text (`strings.Contains(err.Error(), ...)`) may need updating. The
human-readable status-map texts themselves are unchanged.

**3. Error strings start lowercase and no longer end in `\n`.**

Per Go convention, constructed error messages (`fmt.Errorf` / `errors.New`) now
begin lowercase and omit trailing newlines, so they compose cleanly when
wrapped. The descriptive text in `smb.StatusMap` and the service response-code
maps is unchanged.

### Logging behaviour

- The library no longer emits duplicate `[Error]` lines for a single failure.
  Error-level logging now happens only where an error cannot be returned:
  the connection receiver/sender goroutines, the SMB and DCERPC servers, and
  the relay.
- A few `Debug`-level breadcrumbs sit at layer seams (`dcerpc.Bind`,
  `dcerpc.BindAuth`, `ServiceBind.MakeRequest`, `smb` `sendrecv` /
  `NegotiateProtocol` / `SessionSetup`) so a propagating error can still be
  traced at `LevelDebug` without per-call-site noise.
- The SMB server now tags every log line with the client's remote address
  (e.g. `smb/server [192.0.2.7:49832] [Error] ...`) via golog child loggers.

### Security / robustness

Malformed or hostile input from an untrusted peer (a rogue server, a relay
peer, or crafted wire data) now returns an error instead of panicking on an
out-of-range slice or over-allocating from an attacker-controlled size:

- **dcerpc:** reject `Bind` responses shorter than the 16-byte common header
  and `BindNak` responses shorter than 18 bytes; reject a `Response` PDU with
  `FragLength < 24` (the `FragLength - 24` subtraction otherwise underflows);
  cap reassembled response stub data at 64 MiB and bound the fragment count.
- **smb/encoder:** variable-length field reads are validated with `uint64`
  bounds math so a crafted wire offset/count cannot wrap past the guard.
- **ntlmssp:** `AvPair` windows are computed in `uint64` against the parent
  buffer so a crafted length cannot underflow the loop.
- **smb:** the receive path guards against short packets before reading the
  NetBIOS/SMB2/transform headers, and a final `SessionSetup` response too short
  to hold a signature is rejected.
- **smb/server:** the per-connection `MessageId` dedup set is capped (two
  generations) so a long-lived connection cannot grow it unbounded.
- **relay:** short `Negotiate`/`SessionSetup` PDUs are rejected.
- Service decoders (`msdcom`, `msdrsr`, `msrrp`, `mssamr`, `mslsad`, `msscmr`)
  validate server-reported counts against the returned arrays and guard
  OID/string decodes before indexing.
- The CCM tag and SMB signatures are now compared in constant time.

### Added

- **msdcom/WMI:** `WMIClient.Query` for running WQL queries, plus
  `ParseCIMInstanceAllValues` and heap-array decoding for reading CIM instances
  out of the object heap.
- **smb/server:** `QueryFileInfo` / `QueryFSInfo` on the `filevfs` and `memvfs`
  backends.

### Changed

- **NDR migration:** the remaining response decoders were moved onto the `ndr`
  library — union discriminator `SwitchFunc` methods were added across
  `msdrsr`, `mslsad`, `mssamr`, `msrprn`, `msscmr`, `mssrvs`, and `mswkst`.
- Static-analysis cleanup: `staticcheck ./...` goes from 181 findings to 1.
  Unused package-level vars and dead symbols were removed, and `ST1005`
  (capitalized error strings) is suppressed via `staticcheck.conf` — the
  project deliberately keeps the capitalized status-map texts.

### Dependency

- Requires **golog v0.4.0** (adds `MyLogger.With` for per-connection child
  loggers).
- Bumped **gokrb5/v9** to v9.1.0 and **ldap/v3** to v3.102.0.

## [0.10.1] — 2026-06-08

### Added

- Support for initializing a Kerberos client from a keytab file.

## [0.10.0] — 2026-06-06

### Added

- **mssrvs:** `NetShareEnumAllExt` (info levels 501/502 in addition to 1),
  `NetShareGetInfo[Ext]` (levels 0/1/2/501/502), `NetShareSetInfo` with
  `…Comment`/`…Flags`/`…SecurityDescriptor` setters, and `NetServerDiskEnum`.
  Level 502 surfaces the parsed share `SecurityDescriptor`, path and use counts.
- **msscmr:** `GetServiceSecurity[Bytes]`/`SetServiceSecurity[Bytes]` and
  `GetSCManagerSecurity[Bytes]` to read/write service and SCM-database security
  descriptors.
- **smb:** `QueryInfoSecurityRaw` returns the full parsed `SecurityDescriptor`
  (with a buffer-overflow retry); `OpenFileReadAttributes` opens a handle with
  `READ_CONTROL` only.

### Changed

- **msscmr:** SCM/service handles are now opened with least privilege — only the
  access rights each operation requires.
- **krb5ssp, ldap:** migrated to `gokrb5/v9` and adapted to the decoupled
  `ldap/v3`.

## [0.9.0] — 2026-05-31

### Added

- **smb/server:** SMB2/3 server implementation (negotiate, signing and encoding
  groundwork; server-side authentication acceptor in `spnego`/`ntlmssp`).
- **dcerpc:** server-side PDU marshalling and RPC service servers.
- **relay:** multi-target NTLM relay package — `RelayServer` (long-running
  multi-target listener with a session pool, post-auth actions and optional
  fake-server handoff) and `RelayClient` (one-shot, returns a single
  authenticated `*smb.Connection`), replacing the retired
  `smb.NewRelayConnection`. Adds the `MarkAuthenticated` and `SendRawPDU`
  connection hooks the relay drives.
- **msdtyp:** `ACCESS_*_OBJECT_ACE` support and GUID helpers.

### Changed

- **dcerpc:** non-zero RPC return codes are now surfaced as errors.
- **ntlmssp:** client `Negotiate` sets `NEGOTIATE_ALWAYS_SIGN`.
- **krb5ssp:** KDC traffic now defaults to TCP.
- **msdrsr:** added AES-SHA2 Kerberos etypes.
- **msscmr:** optional `ChangeServiceConfig` strings are now passed as pointers.
- Package loggers use `golog` `SetDisplayName` for short, readable tags
  (e.g. `epm`, `msdcom`, `spnego`); dependencies upgraded.

## [0.8.2] — 2026-05-01

### Changed

- Updated the gokrb5 library version.

## [0.8.1] — 2026-05-01

### Added

- `ldap` client — a convenience wrapper around `github.com/jfjallid/ldap/v3`
  exposing limited search functionality.

## [0.8.0] — 2026-04-25

### Added

- New DCERPC service clients: **MS-DCOM** (Distributed COM, with WMI support),
  **MS-TSCH** (Task Scheduler), **MS-DRSR** (DRS Replication / DCSync — replicate
  AD secrets via `DRSGetNCChanges` with DES/AES/RC4 and PEK decryption), plus
  minimal **MS-EVEN** and **MS-RPRN** for authentication coercion.
- **dcerpc:** PktIntegrity authentication level; `AlterContext`, `ObjectUUID`
  and `BindNakError` (DCOM support).
- **krb5ssp:** RFC 4757 RC4 Wrap/MIC tokens (RC4 and AES for DCERPC); a
  configurable cifs→host SPN alias map (`SPNAliases`); CCACHE creation accepting
  both DNS and NetBIOS domain names; a lazily-initialising `KRB5Initiator.Client()`
  accessor.
- **msscmr:** query/modify many more service settings (failure actions, SID type,
  dependencies, description, delayed autostart, required privileges, preshutdown
  info, preferred NUMA node).
- **ldap:** channel-binding support.

### Changed

- Migrated structs from hand-rolled marshalling to the NDR encoder, and moved
  shared structs to the `github.com/jfjallid/mstypes` package.
- Bumped gokrb5 to v8.6.1 (and crypto/net); moved function-entry debug logging
  to `LevelTrace` (golog v0.3.5).

## [0.7.0] — 2026-02-26

DCERPC was decoupled from SMB: the RPC layer is now transport-agnostic and can
run over either SMB named pipes or raw TCP.

### Breaking changes

**1. Package paths moved — all DCERPC packages relocated.**

All DCERPC packages moved from `smb/dcerpc/...` to `dcerpc/...`:

| Old import path | New import path |
|---|---|
| `github.com/jfjallid/go-smb/smb/dcerpc` | `github.com/jfjallid/go-smb/dcerpc` |
| `github.com/jfjallid/go-smb/smb/dcerpc/mssrvs` | `github.com/jfjallid/go-smb/dcerpc/mssrvs` |
| `github.com/jfjallid/go-smb/smb/dcerpc/msrrp` | `github.com/jfjallid/go-smb/dcerpc/msrrp` |
| `github.com/jfjallid/go-smb/smb/dcerpc/mssamr` | `github.com/jfjallid/go-smb/dcerpc/mssamr` |
| `github.com/jfjallid/go-smb/smb/dcerpc/msscmr` | `github.com/jfjallid/go-smb/dcerpc/msscmr` |
| `github.com/jfjallid/go-smb/smb/dcerpc/mslsad` | `github.com/jfjallid/go-smb/dcerpc/mslsad` |
| `github.com/jfjallid/go-smb/smb/dcerpc/mswkst` | `github.com/jfjallid/go-smb/dcerpc/mswkst` |

The old `smb/dcerpc` package no longer exists.

**2. `dcerpc.Bind()` signature changed.**

```go
// Before
dcerpc.Bind(f *smb.File, interface_uuid string, ...) (*ServiceBind, error)
// After
dcerpc.Bind(transport DCERPCTransport, interfaceUUID string, ...) (*ServiceBind, error)
```

The function now accepts a `DCERPCTransport` interface rather than a raw
`*smb.File`. Callers must wrap their file/connection in a transport first:

- **SMB named pipes:** `smbtransport.NewSMBTransport(file)` — import
  `github.com/jfjallid/go-smb/dcerpc/smbtransport`
- **Raw TCP:** `dcerpc.NewTCPTransport(conn)`

**3. `ServiceBind.MakeIoCtlRequest()` renamed to `MakeRequest()`.**

`sb.MakeIoCtlRequest(opcode, buf)` becomes `sb.MakeRequest(opcode, buf)`. This
affects any code calling RPC methods directly through `ServiceBind`.

**4. `krb5ssp.Client.GetAPReq()` signature changed.**

`GetAPReq(spn string)` becomes `GetAPReq(spn string, dceStyle bool)`. The new
`dceStyle bool` parameter supports DCE-style 3-leg Kerberos authentication; pass
`false` to preserve previous behaviour.

### New features

- **`DCERPCTransport` interface** — DCERPC is now transport-agnostic; supports
  both SMB named pipes and raw TCP connections.
- **`BindAuth()`** — authenticated DCERPC binding with NTLM or Kerberos,
  supporting `RpcAuthnLevelConnect`, `RpcAuthnLevelPktIntegrity`, and
  `RpcAuthnLevelPktPrivacy` (per-PDU signing/sealing).
- **`dcerpc/smbtransport`** — bridge package wrapping `smb.File` as a
  `DCERPCTransport`.
- **`dcerpc/tcptransport`** — `TCPTransport` for DCERPC over raw TCP (no SMB).
- **`dcerpc/epm`** — Endpoint Mapper (EPM) package for resolving the TCP
  port/address of a given RPC service UUID.
- **Kerberos DCERPC authentication** — full Kerberos support over both SMB and
  TCP transports, including PktPrivacy (encryption).
- **NTLM DCERPC encryption over TCP** — PktPrivacy support for NTLM over raw TCP.
