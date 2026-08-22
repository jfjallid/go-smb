# Changelog

All notable future changes to this project are documented here as well as
the most recent history of changes. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/). The **[Unreleased]**
section collects changes that have landed but not yet been tagged;
at release time it is renamed to the new version and a fresh
**[Unreleased]** is started above it.

## [Unreleased]

_Nothing yet._

## [0.12.0] — 2026-08-22

Headline items this cycle are a batch of SMB 2.1–3.1.1 client protocol
conformance work (SMB 3.0/3.0.2 dialects, credit-based flow control with the
Windows request/grow/split strategy, a four-state client encryption policy, and
oplock-break / CANCEL handling), SMB2/3 compression on both sides of the
connection,
`context.Context` variants for the blocking client calls, and server-side
durable handles and CHANGE_NOTIFY served on a new asynchronous request path.
On the RPC side this cycle adds `dcerpc/msicpr`, a client for Active Directory
Certificate Services covering certificate enrollment (MS-ICPR over the named
pipe or TCP, MS-WCCE over DCOM) and CA administration (MS-CSRA).
Authentication gains an explicit NTLM mode, reliable detection of accepted
guest/null sessions, and raw (non-SPNEGO) NTLMSSP so the Linux kernel CIFS
client can mount a go-smb share. This cycle also retires the reflection-based
`smb/encoder` engine in favour of hand-written `MarshalBinary` /
`UnmarshalBinary` methods, which changes the marshalling API without changing
the bytes on the wire, and removes the long-unused credential fields on
`smb.Options`.

Everything added this cycle was driven against a live Windows Server 2022
domain controller rather than only against the in-repo server, which is what
surfaced several of the correctness fixes listed below.

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
    - **Headroom.** `creditWindowBytes` holds back one credit, so a read
      bounded by the credit window cannot consume the whole balance. A client
      at zero credits with a request outstanding violates §3.2.4.1.2 and
      Windows closes the connection. `RetrieveFile` also sizes its read buffer
      to the file rather than to `MaxReadSize`, since `ReadFile` requests
      `len(buf)` bytes and a small file would otherwise issue a full-size READ.
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
  An unsolicited break is exempt from the client's "must be signed" check: it
  answers no request, so MS-SMB2 §3.3.4.1 does not oblige the server to sign it
  and Windows Server sends it unsigned. A signature that *is* present is still
  verified.
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

**3. `smb/encoder` is gone; the UTF-16 helpers now live in `smb/unicode`.**

The reflection-based `smb:"..."` tag engine has been retired (see *Wire
marshalling* below), so `encoder.Marshal`, `encoder.Unmarshal`,
`encoder.Metadata` and `encoder.BinaryMarshallable` no longer exist. With only
the UTF-16LE conversion helpers left, the package was renamed to match what it
actually contains:

```go
// Before
import "github.com/jfjallid/go-smb/smb/encoder"
name := encoder.ToUnicode("share")
// After
import "github.com/jfjallid/go-smb/smb/unicode"
name := unicode.ToUnicode("share")
```

The helpers themselves — `ToUnicode`, `FromUnicodeString`, `FromUnicode`,
`Utf16ToUtf8`, `Utf8ToUtf16` — are unchanged in both signature and behaviour,
so this is an import-line edit. Note that a file importing both this package
and stdlib `unicode` will need an alias; no file in this repo does.

The package stays a leaf deliberately: `ntlmssp` depends on it and `smb`
depends on `ntlmssp`, so folding these helpers into `smb` would introduce an
import cycle.

For the marshalling API itself:

```go
// Before
buf, err := encoder.Marshal(req)          // req or &req, both accepted
err = encoder.Unmarshal(buf, &res)

// After — methods on the structure itself
buf, err := req.MarshalBinary()           // pointer receiver: use &req
err = res.UnmarshalBinary(buf)
```

Types that implemented `encoder.BinaryMarshallable` must drop the
`*encoder.Metadata` argument. There is no successor interface requiring both
directions — a type now implements only the direction it is actually used in:

```go
// Before
func (s *T) MarshalBinary(meta *encoder.Metadata) ([]byte, error)
func (s *T) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error
// After
func (s *T) MarshalBinary() ([]byte, error)
func (s *T) UnmarshalBinary(buf []byte) error
```

`Connection.send`, `Connection.sendrecv` and the server reply helpers now take
the exported `smb.Marshaller` (`MarshalBinary() ([]byte, error)`) instead of
`any`. Passing a struct value where a pointer is required is a compile error
rather than a silently wrong encoding.

`NegContext.Padd` has been removed; inter-context alignment is now derived
during marshalling and must no longer be supplied by the caller.

**4. `Options.ForceSMB2` removed.**

The flag was equivalent to offering only SMB 2.1, which `Options.Dialects` now
expresses directly. Set `Dialects: smb.DialectsSMB2Only` to pin the legacy 2.1
path — see *SMB2/3 client protocol conformance* above for the difference in
negotiate behaviour.

**5. `Options.DisableEncryption` and `Options.RequireEncryption` removed.**

Both booleans are gone, replaced by the single `Options.Encryption` field of
type `smb.EncryptionPolicy`. Two booleans could express states that contradict
each other, and the old resolution — `DisableEncryption` silently wins — is
exactly the class of quiet downgrade this release set out to remove.

```go
// Before
opts := smb.Options{Host: host, Initiator: init, RequireEncryption: true}
opts := smb.Options{Host: host, Initiator: init, DisableEncryption: true}

// After
opts := smb.Options{Host: host, Initiator: init, Encryption: smb.EncryptionRequired}
opts := smb.Options{Host: host, Initiator: init, Encryption: smb.EncryptionDisabled}
```

Code setting either field no longer compiles. The mapping is mechanical:
`RequireEncryption: true` → `Encryption: smb.EncryptionRequired`,
`DisableEncryption: true` → `Encryption: smb.EncryptionDisabled`, and leaving
both false → leave `Encryption` unset, **but note that the default's meaning
changed** (see the next item and "Client encryption" below). Code that wants
the pre-0.12.0 default behaviour back must say so explicitly with
`Encryption: smb.EncryptionServerDirected`.

**6. Behavioural changes that can break working code.**

None of these alter a signature, so they compile silently:

- **`File.ReadFile` may return `n < len(b)`** even when more data is available.
  Credit-window splitting makes it `io.Reader`-style, so a caller that assumed a
  full read must now loop on the returned offset. `File.WriteFile` moved the
  other way and always writes the entire buffer.
- **`TreeConnect` can now fail where it previously succeeded**, with
  `smb.ErrShareRequiresEncryption`, when a share sets
  `SMB2_SHAREFLAG_ENCRYPT_DATA` and the connection cannot encrypt end to end.
  Previously the traffic was sent unencrypted and the server rejected it later.
- **Awaiting a response on a connection being torn down returns an error**
  rather than `(nil, nil)`. Callers that special-cased the nil/nil pair can drop
  that branch; callers that ignored it now get a real error.
- **`NewConnection` can now fail where it previously succeeded**, with
  `smb.ErrEncryptionNotNegotiated`, when `Options.Encryption` is
  `EncryptionRequired` and the server negotiates no encryption or establishes a
  guest/anonymous session. Callers that demanded encryption against a pre-3.0 or
  non-encrypting server were getting a plaintext connection and no diagnostic;
  they now get an error and must either relax the policy or fix the server.
  `EncryptionRequired` with an `Options.Dialects` list offering no SMB 3.x
  dialect is rejected before dialing.
- **The default now encrypts more traffic than before.** A connection that
  negotiates a cipher encrypts session-wide even when neither the server nor the
  target share asked for it. Bulk transfers to unflagged shares pay AEAD cost
  they did not previously. Set `Encryption: smb.EncryptionServerDirected` for
  the previous behaviour, which encrypts only what the server and its shares
  ask for.

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
- **Negotiated-state accessors.** `smb.Connection` gains read-only accessors for
  state that was previously only observable through debug logging: `Dialect()`
  (with `DialectString` to render it), `Cipher()`, `Capabilities()`,
  `CompressionInfo()` (agreed algorithms, chained wire form, and whether
  compression is active at all), `MaxReadSize()`, `MaxWriteSize()` and
  `SupportsMultiCredit()`. These exist so a caller — or a test — can assert on
  what was actually negotiated rather than on what was offered, which is the
  only way to catch a silent dialect downgrade or a compression context the
  server declined.

### New DCERPC service client: AD CS (`dcerpc/msicpr`)

A new client for the three protocols an Active Directory Certificate Services
CA exposes, covering certificate enrollment and CA administration. The package
is named for the first of them, the only one that needs no DCOM:

- **MS-ICPR (`ICertPassage`)** — enrollment over the `\pipe\cert` named pipe or
  a dynamic TCP endpoint via `epm`. `RPCCon.CertServerRequest` submits a PKCS#10
  or CMC request and retrieves an issued or pending certificate, returning a
  decoded `CertResponse` (request id, `CR_DISP_*` disposition, the CA's status
  message, the DER leaf and the PKCS#7 chain).
- **MS-WCCE (`ICertRequestD`)** — the same enrollment call over DCOM/ORPC
  (opnum 3), for hosts where the named pipe is filtered but DCOM is reachable.
  It takes an object activated through `msdcom.DCOMConnection.CreateInstance`
  and returns the same `CertResponse`, so the two transports are drop-in
  alternatives behind one interface.
- **MS-CSRA (`ICertAdminD` / `ICertAdminD2`)** — CA administration over DCOM:
  `ResubmitRequest` and `DenyRequest` to approve or reject a pending request,
  `GetCAProperty`/`SetCAProperty` (with `GetTemplateList`/`SetTemplateList`
  over `CR_PROP_TEMPLATES`) to read and write the CA's enabled-template list,
  and `GetCASecurity`/`SetCASecurity` to read and write the CA security
  descriptor carrying the ManageCA and ManageCertificates roles.
  `AddTemplate`/`RemoveTemplate` edit the template list by name and OID: the
  raw list ends with the terminator the CA keeps after the final newline, so
  appending to what `GetTemplateList` returns writes entries the CA will not
  read back.

A refused call keeps the CA's own account of why. `ResponseCodeMap` maps the
`CERTSRV_E_*` range and the generic access/argument failures — in both their
Win32 (ICPR) and HRESULT (DCOM) spellings — to sentinels matchable with
`errors.Is`, and a failing enrollment returns the decoded `CertResponse`
alongside the error, because the CA's reason ("Denied by Policy Module
0x80094800, The request was for a certificate template that is not supported")
arrives in the disposition message rather than in the status word. That message
is appended to the error text as well.

Two implementation notes worth knowing when using it:

- **Per-parameter NDR deferral.** Every pointer parameter is tagged `toplevel`,
  so its referents are emitted inside its own deferral scope rather than being
  deferred to the end of the stub. This is the layout Windows' MIDL-generated
  server stubs expect; without it the CA rejects the call with DCERPC fault
  `0x000006f7` (`nca_s_fault_ndr`). Each stub has a byte-exact layout test.
- **`ICertAdmin` activates its two interfaces lazily, one per call.** Opnums
  3–30 dispatch on `ICertAdminD` and 31+ on `ICertAdminD2`, so each has its own
  IPID and is activated separately — but only on first use. Activating both up
  front works over NTLM yet makes a Kerberos-authenticated session fail its
  second `RemoteCreateInstance` with `RPC_S_SEC_PKG_ERROR` (`0x721`). The
  activation cache is mutex-guarded, and `Close` releases every interface taken.

The package was validated end to end against a live Windows CA over both NTLM
and Kerberos, across all three transports.

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

Client encryption is now a single four-state policy, `Options.Encryption`,
replacing two booleans that could contradict each other and, in one direction,
did nothing at all. The old `RequireEncryption` was a no-op whenever it
mattered most: it was consulted in exactly one place, in a branch that also
required encryption to have been negotiated already, so a connection that could
*not* encrypt fell through it silently and ran in plaintext — no error, no
warning. That covers a 2.0.2/2.1 dialect (which has no encryption at all), a
3.0/3.0.2 server that did not answer with `SMB2_GLOBAL_CAP_ENCRYPTION`, and a
3.1.1 server that answered the `EncryptionCapabilities` context with
`SMB2_ENCRYPTION_NONE` because it shared no cipher with the client's offer.

```go
opts := smb.Options{
    Host:       host,
    Initiator:  initiator,
    Encryption: smb.EncryptionServerDirected,
}
```

The four policies, in ascending order of insistence:

- **`EncryptionDisabled`** removes encryption from the negotiation entirely.
  The old `DisableEncryption` suppressed `SMB2_GLOBAL_CAP_ENCRYPTION` but
  still sent an `EncryptionCapabilities` context, so a cipher was selected and
  keys derived on both sides for a session that would never use them. The
  context is now omitted along with the capability, so no cipher is negotiated
  at all. The mandatory preauth-integrity and signing contexts are unaffected. A
  share flagged `ENCRYPT_DATA` fails its TreeConnect with
  `ErrShareRequiresEncryption`, because this policy cannot reach it.
- **`EncryptionServerDirected`** encrypts only what the peer asks for: a session
  the server flagged `SMB2_SESSION_FLAG_ENCRYPT_DATA` (MS-SMB2 §3.2.5.3.1) and
  shares flagged `SMB2_SHAREFLAG_ENCRYPT_DATA` (§3.2.5.5). Everything else
  travels as signed plaintext. This is how a Windows client behaves, which makes
  it the choice when the traffic should look ordinary, or when a plaintext
  capture is wanted without losing access to encrypt-only shares — a cipher is
  still negotiated, so unlike `EncryptionDisabled` those shares stay reachable.
  It is also the closest match to the pre-0.12.0 default.
- **`EncryptionPreferred`** (the default, and the zero value) encrypts every
  request whenever a cipher was negotiated end-to-end, and falls back to signed
  plaintext when none was. Note that this encrypts more than the peer asks for:
  per-share enforcement is subsumed on any connection that *can* encrypt, so
  traffic to unflagged shares is encrypted too, which costs throughput on bulk
  transfers. Choose `EncryptionServerDirected` to get the old behaviour back.
- **`EncryptionRequired`** encrypts everything and refuses any connection that
  cannot. `NewConnection` returns the new `smb.ErrEncryptionNotNegotiated`,
  naming the negotiated dialect, instead of handing back a working plaintext
  connection. The check runs at the end of NEGOTIATE, before authenticating:
  encryption is not retrofittable onto an established session, so there is
  nothing to gain by continuing. `SessionSetup` fails the same way if the server
  establishes a guest or anonymous session, which has no key to encrypt with —
  matching the rule already applied to signing. A policy that cannot be
  satisfied by the dialect offer at all (`EncryptionRequired` with an
  `Options.Dialects` list containing no SMB 3.x dialect) is rejected by
  `validateOptions` before a socket is opened.

The two booleans this replaces, `Options.DisableEncryption` and
`Options.RequireEncryption`, are **removed** rather than deprecated — see
breaking change 5 above for the migration.

A server demand the client cannot satisfy is now an error too. When the server
sets `SMB2_SESSION_FLAG_ENCRYPT_DATA` but no cipher was negotiated, the client
used to clear the flag and carry on in plaintext; the server requires every
subsequent request to be encrypted (MS-SMB2 §3.3.5.2.9) and rejects them, so
that only deferred the failure to a point where the cause was no longer visible.

Two defects surfaced while implementing the above, each masked by the old
behaviour:

- **The client no longer trusts `SMB2_GLOBAL_CAP_ENCRYPTION` on SMB 3.1.1.**
  MS-SMB2 §3.2.5.2 establishes `Connection.SupportsEncryption` from that
  capability bit only for dialects 3.0 and 3.0.2; 3.1.1 negotiates encryption
  solely through the `EncryptionCapabilities` context. A 3.1.1 server that set
  the bit anyway marked the connection encryption-capable with no cipher ever
  selected, and key derivation then failed the session outright with "cipher
  algorithm (0) not implemented". Previously unreachable only because the client
  always sent a cipher context, so a cipher always came back.
- **A server with `ServerConfig.RequireEncryption` could be talked out of it.**
  In `smb/server`, the "no cipher selected" early return in
  `deriveEncryptionKeys` ran *before* the requirement check, so a client that simply
  omitted the `EncryptionCapabilities` context got an unencrypted session out of
  a server configured to require encryption. The requirement is now checked
  first and covers all three ways a client can be unencryptable: a pre-3.0
  dialect, no capability bit, or no cipher.

Also in this area:

- **Encrypted responses are no longer wrongly rejected by the signing check.**
  On a signing-required session negotiating a pre-3.1.1 dialect with encryption,
  the reader ran the plaintext signature check on encrypted PDUs (which carry
  their own AEAD integrity and never set `SMB2_FLAGS_SIGNED`) and tore the
  connection down. The check is now skipped for encrypted PDUs.

### Security

- **The client stopped verifying signatures after the first encrypted PDU.**
  The flag that suppresses the plaintext signature check for an encrypted PDU
  was scoped to the whole receive loop rather than to a single packet, so once
  any encrypted PDU arrived, every subsequent *plaintext* PDU on that
  connection skipped both the `SMB2_FLAGS_SIGNED` check and signature
  verification — for the life of the connection. This was reachable in ordinary
  use: on a share flagged `SMB2_SHAREFLAG_ENCRYPT_DATA`, encrypted and
  plaintext PDUs interleave normally, so an on-path attacker could inject
  unsigned responses after observing one encrypted exchange. The flag is now
  per-PDU.

### SMB2/3 compression

- **Compression is implemented for both client and server** (MS-SMB2 §2.2.42,
  MS-XCA): LZ77 (Plain), LZ77+Huffman, and Pattern_V1 in the new
  `smb/compress` package, with both the chained and unchained transform wire
  forms. Opt in with `smb.Options.Compression` on the client and
  `server.ServerConfig.Compression` on the server; `CompressionAlgorithms`
  overrides the offered set on either side. The option covers both directions:
  outbound PDUs are compressed when that pays off, and READ requests carry
  `SMB2_READFLAG_REQUEST_COMPRESSED` (MS-SMB2 §2.2.19) so the server compresses
  what it sends back. There is no per-direction switch. A peer stays free to
  answer uncompressed — Windows gates its side per-share on `-CompressData`.
- Compression is applied before encryption and after signing, per MS-SMB2
  §3.1.4.1. Inbound frames are rejected outright until compression has actually
  been negotiated, so an unnegotiated peer cannot drive the decompressor, and a
  frame's declared original size is bounded (16 MiB) so a small frame cannot
  force a large allocation.
- Because a single-payload chained frame may legally leave
  `SMB2_COMPRESSION_FLAG_CHAINED` clear, the two wire forms cannot be told
  apart by inspection; the decoder parses with the negotiated form and retries
  the other on failure. Both forms verify the reconstructed length against the
  size the sender declared, so a wrong guess errors rather than yielding wrong
  bytes.
- **`Connection.CompressionStats()` reports compression-transform frames sent
  and received.** A compressed transfer is byte-identical to an uncompressed
  one, so a counter is the only way to tell a connection that merely negotiated
  compression from one that is actually using it.
- **LZXPRESS Plain reproduces Windows' `RtlCompressBuffer` byte for byte.**
  MS-XCA §2.4 ends decompression on a match bit with no input remaining, so a
  conforming encoder leaves the final flag group's unused bits set: groups start
  all-ones and literals clear their bit. The decompressor implements the same
  end-of-stream rule rather than reporting a truncated match.
- **Exercised against Windows Server 2022**, which negotiates LZ77+Huffman and
  Pattern_V1 but not plain LZ77 — so LZ77+Huffman carries every compressed PDU,
  including bulk WRITEs at `MaxWriteSize` of 1 MiB and up.

### Client correctness and robustness

- **`NewConnection` leaked a socket and two goroutines on every error return.**
  It starts its sender and receiver goroutines before NEGOTIATE and hands back a
  half-built `*Connection` alongside the error, which no caller can be expected
  to `Close`. Failed connections now unwind themselves — which matters for
  anything that sweeps many hosts, and became easy to hit once
  `EncryptionRequired` could refuse a connection outright.
- **`ParseAccessMask` never reported `GENERIC_WRITE`.** The lookup table's key
  was `0x4000000` — one zero short of `0x40000000` — so the bit was never
  matched, and the reserved bit `0x04000000` was reported as `GENERIC_WRITE`
  instead. This affected every DACL surfaced through `QueryInfoSecurity`.
- **A "no common cipher" negotiate response no longer fails the connection.**
  A server that shares no cipher with our offer answers with
  `Ciphers[0] = 0x0000` (MS-SMB2 §3.3.5.4); this was treated as an unknown
  algorithm and aborted `NegotiateProtocol` instead of continuing unencrypted.
  Exposed as the new `smb.CipherNone`.
- **`Connection.Close` is now idempotent.** A second call panicked on a closed
  channel, which the common `defer c.Close()` plus an explicit close on an
  error path was enough to trigger.
- **`QueryDirectory` no longer panics on a malformed reply.** The
  server-controlled `NextEntryOffset` was unbounded and the buffer end was
  never clamped; entry boundaries are now validated and must move strictly
  forward. This runs on the caller's goroutine, where the receive loop's
  `recover` does not apply.
- **`ReadFile` no longer misreads on a small `DataOffset`.** The offset was
  computed in `byte` arithmetic and wrapped modulo 256 for any value below 80
  (0 became 176), silently reading from the wrong place.
- **An oversized NetBIOS length no longer desynchronizes the stream.** The
  client skipped the frame without consuming its payload and kept reading,
  turning every subsequent frame into garbage; it now fails the connection.
- Response header parsing is centralized behind one length-guarded helper, so a
  reply too short to contain a header is an error rather than a panic on the
  caller's goroutine. A truncated response no longer reaches `sign`/`verify`
  either.

### `context.Context` support (client)

- **New `XxxContext` variants** on the blocking calls: `ReadFileContext`,
  `WriteFileContext`, `RetrieveFileContext`, `PutFileContext`, `EchoContext`,
  `FlushContext` and `QueryDirectoryContext`. The existing methods are
  unchanged and now delegate with `context.Background()`, so this is not a
  breaking change.
- Cancellation reaches all three places a call can block: the credit reserve,
  the handoff to the sender, and the wait for the response. The credit wait is
  built on a `sync.Cond`, which only wakes on a Broadcast, so a cancelled
  context is translated into one — previously a caller blocked on a starved
  credit window ignored cancellation entirely and hung for the full reserve
  timeout (60s by default).
- When a cancelled request has already gone out, an **SMB2 CANCEL** is sent for
  it (MS-SMB2 §3.2.4.24) rather than leaving the server working for a caller
  that has walked away. Long transfers also check the context between chunks,
  so they stop at the next boundary instead of running to completion.
- Awaiting a response on a connection that is being torn down now reports an
  error instead of returning `(nil, nil)`, which every caller previously had to
  special-case before parsing a response that did not exist.
- New accessors `File.FileID`, `Connection.SessionID` and `Connection.TreeID`
  expose what is needed to address an open handle in a hand-built PDU via
  `Connection.SendRawPDU`.

### Server resource limits

- **Connection resources are now bounded.** New `ServerConfig.IdleTimeout`,
  `WriteTimeout` and `MaxConnections` (defaults 5min / 30s / 512; a negative
  value disables each). Previously a peer that connected and then went quiet —
  or dribbled a PDU a byte at a time — held a goroutine and its buffers
  indefinitely, and nothing capped how many such connections could accumulate.
  The read deadline is armed around the read only and cleared while a request
  is being handled, so a slow VFS or hook is never mistaken for an idle client.
- **The accept loop no longer dies on a transient error.** `Serve` returned on
  any accept failure, so a momentary resource shortage (e.g. running out of
  file descriptors) permanently took the listener down. Temporary errors are
  now retried with exponential backoff up to one second.

### Server: CHANGE_NOTIFY and asynchronous requests

- **CHANGE_NOTIFY (MS-SMB2 §2.2.35) is now served.** Windows Explorer issues one
  per displayed directory and reissues it as soon as it completes, so a server
  that never answers leaves the client retrying indefinitely.
- A VFS opts in by implementing the new `ChangeNotifier` interface; the server
  then holds the request open and answers when a change arrives. A VFS that
  does not implement it gets `STATUS_NOT_SUPPORTED`, which — unlike silence —
  clients accept as "this server does not do notifications".
- This adds a general **asynchronous request path** (MS-SMB2 §3.3.4.2): an
  interim `STATUS_PENDING` response carrying a server-assigned AsyncId releases
  the client immediately, and the final response reuses the same MessageId and
  AsyncId when the operation completes. A CANCEL aborts an outstanding
  operation, and connection teardown cancels every one still in flight so no
  watcher goroutine outlives its connection. Concurrent async operations are
  capped per connection; beyond the cap the request is refused rather than
  allowed to accumulate goroutines.
- `Session.signPDU` / `verifyPDU` are now serialized. The HMAC-SHA256 and
  AES-CMAC paths share a stateful hash across messages, which was safe only
  while dispatch was strictly single-goroutine per connection; asynchronous
  replies sign from their own goroutine and would otherwise interleave into a
  corrupt MAC.

### Server: durable handles

- **Durable handles (MS-SMB2 §3.3.5.9.6) are now supported**, opt-in via
  `ServerConfig.DurableHandles`. A handle whose CREATE carried a durable
  request survives the loss of its connection and can be reclaimed on a later
  one, so a transient network blip no longer aborts an in-progress transfer.
  The lifecycle is: grant on CREATE, park on connection loss with a deadline,
  reclaim on a CREATE carrying the matching reconnect context, and close
  through the VFS once the deadline passes.
- `DurableHandleTimeout` and `MaxDurableHandleTimeout` bound how long a parked
  handle is retained (defaults 60s and 10min). A client-requested timeout is
  clamped rather than honored blindly — a handle parked indefinitely is a
  resource leak any client could trigger by connecting and disappearing.
- A parked handle is only ever returned to the same user and domain, on the
  same share. Without that check any authenticated user could take over
  another's handle by presenting a guessed FileId.
- This also adds SMB2 **CREATE-context parsing and emission** (MS-SMB2
  §2.2.13.2), which the server did not have at all: `DHnQ`, `DH2Q`, `DHnC` and
  `DH2C`. A malformed context list is rejected with STATUS_INVALID_PARAMETER
  rather than partially parsed, since contexts drive handle semantics.
- A v2 reconnect is keyed on the **CreateGuid alone**, per MS-SMB2 §3.3.5.9.12 —
  that is what the GUID is for, and Windows sends an all-zero FileId in the DH2C
  context. v1 (`DHnC`), which carries no GUID, keys on FileId instead.
- Persistent handles are **not** granted: surviving a server restart requires
  durable storage for the handle table. The durable part of a v2 request is
  granted and the persistent flag left clear, which is a valid response.

### Wire marshalling

The reflection-based encoder that drove SMB2 and NTLMSSP serialization from
`smb:"..."` struct tags has been replaced by hand-written methods on each
structure. See *Breaking changes* above for the API migration.

- **`smb/encoder/encoder.go` is deleted** (809 lines, plus its tests), and the
  surviving UTF-16LE helpers move to `smb/unicode` (see *Breaking changes*
  above). Marshalling now lives in `smb/marshal.go` (every SMB2 PDU, negotiate
  context, `TransformHeader` and `SMB1Header`), the pre-existing
  `smb/marshal_server.go`, and the new `ntlmssp/marshal.go`.
- **The wire format is unchanged and pinned by tests.** Goldens were captured
  from the reflection engine before any change and asserted against the new
  output: 35 SMB structures plus 9 NTLMSSP structures, byte-identical. Two
  deliberate deviations, both unreachable from callers in this repo:
  `ReadRes.DataOffset` is now derived rather than caller-supplied (it was
  always set to 80), and fixed-width fields — GUIDs, FileIds, signatures — are
  padded or truncated to their spec length instead of being emitted at whatever
  length the caller passed, which can only change output that was already an
  invalid PDU.
- **Bounds checking is now uniform.** Every decoder runs through a single
  `reader` cursor that records the first error and no-ops afterwards, so
  peer-controlled offset/length pairs are widened to `uint64` and range-checked
  in one place. Previously only two paths were guarded and the rest could panic
  on hostile input.
- **Negotiate-context padding is fixed, not just moved.** Alignment is derived
  per context position in `marshalNegContextList` and emitted *between*
  contexts per MS-SMB2 §3.3.5.4, replacing `NegContext.Padd`, eight duplicated
  `make([]byte, (8-len(x)%8)%8)` computations, the server's `padTo8` helper and
  the trailing-context workaround that stopped stray zeros being emitted after
  the final context. Output is byte-identical;
  `TestNegContextListAlignment` pins it.
- **Known encoder defects go with it:** offsets computed by re-marshalling
  every preceding field (O(n²), and derived from marshalled lengths rather than
  the spec's fixed offsets, so the two could silently disagree); a zero-length
  `[]struct` emitting four zero bytes from a DCERPC null-pointer hack; the
  disabled alignment logic and its `//TODO Should this be x2?` comments; and
  stringly-typed errors with no field path.
- One asymmetry was found and **deliberately preserved**: an empty `[]byte`
  payload gets offset 0, but a non-nil-but-empty NTLMSSP `TargetInfo` gets a
  real offset, because the old emptiness test checked pointer-nil rather than
  length. Peers accept it, and changing it was out of scope for a
  wire-preserving migration.

### Authentication robustness

Two panics on the Kerberos SessionSetup path, both reached when the server
accepts the AP-REQ outright and authentication completes in a single leg:

- `spnego.Client` now records the optimistic mechanism as selected when it
  builds the initial `NegTokenInit`. `selectedMech` was assigned only in the
  second-leg branch, so an exchange the server accepted outright left it nil
  and the subsequent `SessionKey()` call panicked with a nil-pointer
  dereference. A server naming a mechanism that was never offered is now
  rejected with an error instead of dereferencing nil.
- `Connection.SessionSetup` validates the mechanism's session key before
  slicing it to 16 bytes. A mechanism that completed without establishing a
  key caused a slice-bounds panic; it now returns "authentication completed
  without a usable session key".

### Correctness fixes

- **`DSNAME.SetName` counts UTF-16 code units, not UTF-8 bytes.** `NameLen` is a
  WCHAR count but was set from `len(name)`, the Go string's byte length. The two
  agree only for ASCII; for any other character `NameLen` came out too large, so
  the `[size_is(NameLen+1)]` conformant array declared more code units than
  `StringName` actually held. A `DRSGetNCChanges` request built from such a
  DSNAME is rejected by the DC with a DCERPC fault carrying
  `RPC_X_BAD_STUB_DATA` (0x6f7), so no object whose DN contained a non-ASCII
  character could be replicated. The count is now derived from the encoded
  `StringName`. Note that `len([]rune(name))` would not be correct either: a
  character outside the BMP is one rune but two UTF-16 code units.

- **`NetrServerDiskEnum` (MS-SRVS opnum 23) now decodes.** `DISK_INFO.Disk` is
  declared `WCHAR Disk[3]` but carries the `[string]` attribute, so NDR puts a
  varying array on the wire — offset, actual count, then that many UTF-16 code
  units — not three bare WCHARs. Decoding it as a fixed `[3]uint16` consumed the
  offset/count pair as character data and slid the rest of the stub, so
  `TotalEntries` was read as the return code: every call against a Windows
  server failed with "unknown return code 0x00000001" and no drive was ever
  returned. The struct field is now a Go `string`, which the encoder and decoder
  already treat as varying. The existing round-trip test could not catch this —
  it was symmetric in the same wrong format — so a captured Windows response is
  now pinned as golden bytes.

- **`msdtyp.ParseAccessMask` reports GENERIC_WRITE.** The `msdtyp` copy of the
  access-mask table still had the `0x4000000` typo (one zero short of
  `0x40000000`) that was corrected in `smb`, so `ACE.Permissions()` — every DACL
  and SACL rendered through this package — silently omitted GENERIC_WRITE and
  attributed it to the reserved bit `0x04000000` instead.

- **`msdtyp.ParseAceFlags` output is deterministic.** It joined flags in map
  iteration order, so the rendered flag list reordered between runs.

### Testing

- **The tree is verified clean under `-race`.** `go test -race ./...` reports
  no data races in any package, which covers the asynchronous request path,
  durable handles and the `context.Context` client work added this cycle. The
  one race the run did find was in a test fixture rather than library code:
  `dcerpc/server`'s `fakeService` recorded the last dispatched opnum and stub
  without synchronisation while `TestPipeHandlerConcurrentTransceive` drove it
  from eight goroutines. The production `PipeHandler` was correct.
- **Validated against live Windows servers.** The protocol options added this
  cycle — dialect selection, per-share encryption, credit flow control,
  compression, context cancellation — are not reachable from the tools built on
  this library, so until now they were only ever exercised against the in-repo
  server, which shares its own assumptions with the client. Testing against a
  Windows Server 2022 domain controller is what surfaced the LZXPRESS Plain
  framing, the oplock-break signing rule, and the credit-headroom behaviour
  described above.

### Dependency

- **`github.com/jfjallid/ndr` v0.1.1 → v0.2.0.** Brings bounds on wire-driven
  element counts before allocation, strict `ndr:"..."` tag validation,
  `ErrMalformed` wrapping, and a fix to the header-mode alignment origin.
  The wire-visible change is that the encoder **no longer emits trailing
  padding after string or array data**. NDR aligns each primitive before
  writing it and has no concept of a trailing pad, so padding a message out to
  a 4/8-byte boundary is the DCERPC stub's concern, one layer up — go-smb
  already does it where the spec requires, when aligning `sec_trailer`. The old
  behaviour also desynchronised the decoder for any string followed by a field
  of alignment < 4. Two request vectors in `dcerpc/mssamr` and `dcerpc/msscmr`
  are updated to match; a Windows Server 2019 DC accepts the unpadded stubs in
  both plain and sealed (PktPrivacy) DCERPC.

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
