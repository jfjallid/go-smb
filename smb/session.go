// MIT License
//
// Copyright (c) 2017 stacktitan
// Copyright (c) 2023 Jimmy Fjällid for extensions beyond login for SMB 2.1
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
package smb

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/msdtyp"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/compress"
	"github.com/jfjallid/go-smb/smb/crypto/ccm"
	"github.com/jfjallid/go-smb/smb/crypto/cmac"
	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/go-smb/spnego"
	"golang.org/x/net/proxy"
)

type File struct {
	*Connection
	FileMetadata
	shareid  uint32
	fd       []byte
	share    string
	filename string
}

type FileMetadata struct {
	CreateAction   uint32
	CreationTime   uint64 //Filetime
	LastAccessTime uint64 //Filetime
	LastWriteTime  uint64 //Filetime
	ChangeTime     uint64 //Filetime
	Attributes     uint32
	EndOfFile      uint64
}

// Information extracted from the SessionSetup handshake
type TargetInfo struct {
	DnsComputerName  string
	DnsDomainName    string
	NBComputerName   string
	NBDomainName     string
	OS               uint64
	GuessedOSVersion string
}

type Session struct {
	isSigningRequired  atomic.Bool
	isSigningDisabled  bool
	isAuthenticated    bool
	supportsEncryption bool
	clientGuid         []byte
	securityMode       uint16
	messageID          uint64
	sessionID          uint64 // Does this need to be atomic?
	creditMgr          *creditManager
	sessionFlags       uint16
	// authedAsNull records that this session was established with an anonymous
	// (null) NTLM logon that the server accepted — i.e. the client sent
	// NTLMSSP_NEGOTIATE_ANONYMOUS with empty responses and authentication
	// succeeded. This is the reliable null-session signal, independent of the
	// server's SMB2_SESSION_FLAG_IS_NULL (which some servers omit). See
	// IsNullSession / AuthResult.
	authedAsNull        bool
	supportsMultiCredit bool
	//SequenceWindow            uint64
	maxReadSize               uint32
	maxWriteSize              uint32
	maxTransactSize           uint32
	preauthIntegrityHashValue [64]byte // Session preauthIntegrityHashValue
	exportedSessionKey        []byte   // From SPNego Auth
	// Used in SMB 3.1.1 instead of sessionKey for higher level applications
	// such as to encrypt a password parameter
	applicationKey []byte // SMB 3.X only
	signer         smbSigner
	verifier       smbVerifier
	encrypter      cipher.AEAD
	decrypter      cipher.AEAD
	dialect        uint16
	options        Options
	trees          map[string]*treeConnect
	treeLock       sync.RWMutex
	lock           sync.RWMutex
	authUsername   string // Combined domain and username as sent in SessionSetup2 request
	targetInfo     *TargetInfo
	// oplockBreakHandler, when set, is consulted on an unsolicited server
	// oplock break notification and returns the oplock level to acknowledge.
	// nil means "acknowledge down to None".
	oplockBreakHandler OplockBreakHandler
}

// treeConnect records the per-share state returned by an SMB2 TREE_CONNECT
// response (MS-SMB2 §2.2.10). Beyond the TreeId it captures the ShareFlags,
// Capabilities and MaximalAccess so callers and the send path can honor
// per-share requirements — most importantly SMB2_SHAREFLAG_ENCRYPT_DATA, which
// obliges the client to encrypt every request on that tree even when the
// session default is cleartext (MS-SMB2 §3.2.5.5).
type treeConnect struct {
	treeId        uint32
	shareFlags    uint32
	capabilities  uint32
	maximalAccess uint32
	encryptData   bool
}

type Options struct {
	Host                  string
	Port                  int
	Workstation           string
	DisableSigning        bool
	RequireMessageSigning bool
	DisableEncryption     bool
	// RequireEncryption opts the whole session into encrypt-all: every request
	// is wrapped in a TransformHeader regardless of whether the server flagged
	// the session or the target share with ENCRYPT_DATA. Leaving it false makes
	// the client honor the server's verdict (MS-SMB2 §3.2.5.3.1) — the session
	// encrypts only when the server set SMB2_SESSION_FLAG_ENCRYPT_DATA, while
	// individual shares flagged SMB2_SHAREFLAG_ENCRYPT_DATA are still encrypted
	// per-tree. Mutually exclusive with DisableEncryption; the latter wins.
	RequireEncryption bool
	// SMB2Only skips the SMB1 multi-protocol negotiate and sends an SMB2
	// NEGOTIATE directly. Useful against servers with SMB1 disabled.
	SMB2Only bool
	// Dialects, when non-empty, overrides the set of SMB2 dialects offered in
	// the NEGOTIATE request. Entries must be known dialect revisions
	// (DialectSmb_2_0_2, _2_1, _3_0, _3_0_2, _3_1_1); the server still selects
	// the highest it supports, so order is not significant. Setting it forces
	// the direct SMB2 negotiate (the SMB1 multi-protocol probe cannot honor a
	// custom list). Leaving it nil keeps the default offer
	// (3.1.1, 3.0.2, 3.0, 2.1, 2.0.2). To pin the legacy SMB 2.1 path, set
	// DialectsSMB2Only.
	Dialects    []uint16
	Initiator   gss.Mechanism
	DialTimeout time.Duration
	ProxyDialer proxy.Dialer
	ManualLogin bool
	// RawNTLMSSP offers bare NTLMSSP tokens in SessionSetup instead of
	// SPNEGO-wrapped ones (the framing the Linux kernel CIFS client uses).
	// NTLM only: it requires a *spnego.NTLMInitiator and is rejected with a
	// Kerberos initiator. Leave it false (the default) for the standard
	// SPNEGO path, which every mainstream server accepts.
	RawNTLMSSP bool
	// Ciphers, when non-nil, overrides the SMB 3.1.1 EncryptionCapabilities
	// offer in the Negotiate request. The slice order is the client's
	// preference — the server picks the first entry it recognizes. Leaving
	// it nil keeps the default offer (AES-128-CCM, AES-128-GCM, AES-256-CCM,
	// AES-256-GCM). Useful for tests that need to pin which cipher gets
	// negotiated.
	Ciphers []uint16
	// CreditReserveTimeout bounds how long a request will block waiting for the
	// server to grant enough credits before failing with an error instead of
	// hanging. Zero selects defaultCreditReserveTimeout; a negative value waits
	// indefinitely (the old behavior, unblocked only by connection teardown).
	CreditReserveTimeout time.Duration
	// CreditTarget is the credit balance the client tries to keep granted by
	// requesting toward it on every request ("ask for more"). Zero selects
	// defaultCreditTarget. One credit covers 64 KiB of a single READ/WRITE, so
	// the target also bounds the largest un-split transfer (target × 64 KiB).
	CreditTarget uint16
	// Compression opts the SMB 3.1.1 client into offering an
	// SMB2_COMPRESSION_CAPABILITIES context. When the server also supports it,
	// the connection may send and receive compression-transform (0xFCSMB)
	// frames. Once offered, the server may send us compressed frames, so
	// decompression is always active for a negotiated connection.
	Compression bool
	// CompressionAlgorithms, when non-nil, overrides the offered algorithm set
	// (preference order). Leaving it nil offers the default
	// (LZ77+Huffman, LZ77, Pattern_V1).
	CompressionAlgorithms []uint16
}

// defaultCreditReserveTimeout is the ceiling on how long a single request waits
// for credits when Options.CreditReserveTimeout is left unset. A well-behaved
// server grants credits within a round trip, so a wait this long means the
// window is starved and the caller should hear about it rather than hang.
const defaultCreditReserveTimeout = 60 * time.Second

// defaultCreditTarget is the credit balance the client aims to keep when
// Options.CreditTarget is unset. 512 credits ≈ a 32 MiB window: comfortably
// larger than a typical 1–8 MiB MaxReadSize/MaxWriteSize so full-size transfers
// fit without splitting, while staying modest enough not to burden the server.
const defaultCreditTarget uint64 = 512

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return fmt.Errorf("missing required option: Host (use -h for help on usage)")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return fmt.Errorf("invalid or missing value: Port (use -h for help on usage)")
	}
	if opt.Initiator == nil && !opt.ManualLogin {
		return fmt.Errorf("initiator empty")
	}
	if opt.RawNTLMSSP && opt.Initiator != nil {
		if _, ok := opt.Initiator.(*spnego.NTLMInitiator); !ok {
			return fmt.Errorf("RawNTLMSSP requires a *spnego.NTLMInitiator (NTLM only)")
		}
	}
	if len(opt.Dialects) > 0 {
		for _, d := range opt.Dialects {
			switch d {
			case DialectSmb_2_0_2, DialectSmb_2_1, DialectSmb_3_0, DialectSmb_3_0_2, DialectSmb_3_1_1:
			default:
				return fmt.Errorf("invalid options: unknown dialect 0x%04x in Dialects", d)
			}
		}
	}
	return nil
}

type CreateReqOpts struct {
	OpLockLevel        byte
	ImpersonationLevel uint32
	DesiredAccess      uint32
	FileAttr           uint32
	ShareAccess        uint32
	CreateDisp         uint32
	CreateOpts         uint32
}

func NewCreateReqOpts() *CreateReqOpts {
	return &CreateReqOpts{
		OpLockLevel:        OpLockLevelNone,
		ImpersonationLevel: ImpersonationLevelImpersonation,
		DesiredAccess:      FAccMaskFileReadData | FAccMaskFileReadEA | FAccMaskFileReadAttributes | FAccMaskReadControl | FAccMaskSynchronize,
		FileAttr:           0,
		ShareAccess:        FileShareRead | FileShareWrite,
		CreateDisp:         FileOpen,
	}
}

func (s *Session) GetSessionKey() []byte {
	if s.dialect >= DialectSmb_3_0 {
		return s.applicationKey
	}
	return s.exportedSessionKey
}

func (s *Session) IsAuthenticated() bool {
	return s.isAuthenticated
}

func (s *Session) IsSigningRequired() bool {
	return s.isSigningRequired.Load()
}

// negotiateStatus decodes only the SMB2 header from a negotiate response and
// returns a non-nil error when the server signalled a failure status. It must
// run before the full-body NegotiateRes unmarshalling: an error response (for
// example STATUS_NOT_SUPPORTED when no common dialect exists) carries only a
// short 9-byte error body, so unmarshalling it as a full NegotiateRes fails
// with a misleading "unexpected EOF" and masks the real server status.
func negotiateStatus(buf []byte) error {
	_, err := headerStatus("Negotiate", buf)
	return err
}

func (c *Connection) NegotiateProtocol() (err error) {
	// Debug breadcrumb at the layer seam: connection establishment spans
	// multiple round trips before sendrecv-based operations take over.
	defer func() {
		if err != nil {
			log.Debugln(err)
		}
	}()
	var rr *requestResponse
	var negRes NegotiateRes
	var negResBuf []byte

	if c.options.SMB2Only || len(c.options.Dialects) > 0 {
		// Skip SMB1 multi-protocol negotiate and go straight to an SMB2
		// NEGOTIATE request. The dialect list (including 2.0.2) is the
		// authoritative offer. A custom Options.Dialects forces this path too:
		// the SMB1 multi-protocol probe advertises a fixed 2.0.2/2.1 set it
		// cannot restrict, so honoring a custom list requires the direct offer.
		negReq, err := c.NewNegotiateReq()
		if err != nil {
			return err
		}
		c.offeredDialects = append([]uint16(nil), negReq.Dialects...)
		log.Debugln("Sending SMB2-only NegotiateProtocol request")
		rr, err = c.send(&negReq)
		if err != nil {
			log.Debugln(err)
			return err
		}
		negResBuf, err = c.recv(rr)
		if err != nil {
			log.Debugln(err)
			return err
		}
		if len(negResBuf) > 0 && negResBuf[0] == 0xFF {
			err = fmt.Errorf("target %s only accepts SMBv1, but SMBv1 is not implemented", c.conn.RemoteAddr().String())
			return err
		}
		// Surface a server error status (e.g. STATUS_NOT_SUPPORTED when the
		// server shares no dialect with our offer) before attempting to parse
		// the response as a full NegotiateRes.
		if err = negotiateStatus(negResBuf); err != nil {
			return err
		}
		negRes = NewNegotiateRes()
		log.Traceln("Unmarshalling SMB2-only NegotiateProtocol response")
		if err := negRes.UnmarshalBinary(negResBuf); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(negResBuf))
			return err
		}
	} else {
		negReq1, err := c.NewSMB1NegotiateReq()
		if err != nil {
			return err
		}
		log.Debugln("Sending SMB1 NegotiateProtocol request")
		// SMB1 multi-proto advertises [SMB 2.002, SMB 2.100, SMB 2.???].
		// Record the SMB2 equivalents so dialect validation accepts a
		// direct 2.0.2 / 2.1 selection by the server.
		c.offeredDialects = []uint16{DialectSmb_2_0_2, DialectSmb_2_1, DialectSmb2_ALL}
		rr, err = c.send(&negReq1)
		if err != nil {
			log.Debugln(err)
			return err
		}

		negResBuf, err = c.recv(rr)
		if err != nil {
			log.Debugln(err)
			return err
		}

		if len(negResBuf) > 0 && negResBuf[0] == 0xFF {
			// Server does not support or want to use SMB2.
			err = fmt.Errorf("target %s is only accepting SMBv1, but SMBv1 support is not implemented", c.conn.RemoteAddr().String())
			return err
		}
		// Surface a server error status before parsing the SMB2 response body.
		if err = negotiateStatus(negResBuf); err != nil {
			return err
		}

		negRes1 := NewNegotiateRes()
		log.Traceln("Unmarshalling NegotiateProtocol response")
		if err := negRes1.UnmarshalBinary(negResBuf); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(negResBuf))
			return err
		}

		switch {
		case negRes1.DialectRevision == DialectSmb_2_0_2:
			// 2.0.2-only server: take this response as final, no SMB2
			// follow-up negotiate.
			negRes = negRes1
		case negRes1.DialectRevision == DialectSmb2_ALL:
			// Wildcard: send an SMB2 negotiate to pin the dialect.
			negReq, err := c.NewNegotiateReq()
			if err != nil {
				return err
			}
			c.offeredDialects = append([]uint16(nil), negReq.Dialects...)
			log.Debugln("Sending SMB2 NegotiateProtocol request")
			// Reuse rr variable for the second neg protocol req to keep
			// reference for calculation of the pre-auth integrity hash.
			// Address-of so encoder.Marshal sees the pointer-receiver
			// MarshalBinary and emits 8-byte-aligned NegotiateContextOffset.
			rr, err = c.send(&negReq)
			if err != nil {
				log.Debugln(err)
				return err
			}
			negResBuf, err = c.recv(rr)
			if err != nil {
				log.Debugln(err)
				return err
			}
			// Surface a server error status before parsing the response body.
			if err = negotiateStatus(negResBuf); err != nil {
				return err
			}
			negRes = NewNegotiateRes()
			log.Traceln("Unmarshalling second NegotiateProtocol response")
			if err := negRes.UnmarshalBinary(negResBuf); err != nil {
				log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(negResBuf))
				return err
			}
		case negRes1.DialectRevision < DialectSmb2_ALL:
			// Non-2.0.2 / non-wildcard (e.g. 2.1 from a server that does
			// not honor wildcard). Treat as final.
			negRes = negRes1
		default:
			err = fmt.Errorf("server responded to the multi-protocol negotiation with an invalid DialectRevision of 0x%x", negRes1.DialectRevision)
			log.Debugln(err)
			return err
		}
	}

	if err = statusError("Negotiate", negRes.Header.Status); err != nil {
		return err
	}

	oid := negRes.SecurityBlob.OID
	if !oid.Equal(gss.SpnegoOid) {
		err = fmt.Errorf("unknown security type OID: %s", oid)
		return err
	}

	hasNTLMSSP := false
	hasKerberosSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(gss.NtLmSSPMechTypeOid) {
			hasNTLMSSP = true
		} else if mechType.Equal(gss.KerberosSSPMechTypeOid) {
			hasKerberosSSP = true
		}
	}
	if !hasNTLMSSP && !hasKerberosSSP {
		return fmt.Errorf("this library only supports NTLMSSP and KRB5 Kerberos, and the server supports neither")
	}

	c.securityMode = negRes.SecurityMode
	c.dialect = negRes.DialectRevision

	// Validate the server-selected dialect against the dialects we offered
	// (MS-SMB2 §3.2.5.2). Reject anything else to avoid silent downgrade.
	if len(c.offeredDialects) > 0 {
		allowed := slices.Contains(c.offeredDialects, c.dialect)
		if !allowed {
			err = fmt.Errorf("server selected dialect 0x%x which the client did not offer", c.dialect)
			return err
		}
	}

	// Determine whether signing is required
	mode := uint16(c.securityMode)
	if !c.isSigningRequired.Load() {
		if mode&SecurityModeSigningEnabled > 0 {
			if mode&SecurityModeSigningRequired > 0 {
				c.isSigningRequired.Store(true)
			} else {
				c.isSigningRequired.Store(false)
			}
		}
	}

	// Check if server supports multi-credit operations
	if (negRes.Capabilities & GlobalCapLargeMTU) == GlobalCapLargeMTU {
		c.supportsMultiCredit = true
		c.capabilities |= GlobalCapLargeMTU
	}

	// Check if encryption is enabled
	if (negRes.Capabilities & GlobalCapEncryption) == GlobalCapEncryption {
		c.supportsEncryption = true
		c.capabilities |= GlobalCapEncryption
	}

	// Update maxReadSize, maxWriteSize, and maxTransactSize from response
	c.maxReadSize = negRes.MaxReadSize
	c.maxWriteSize = negRes.MaxWriteSize
	c.maxTransactSize = negRes.MaxTransactSize

	if c.dialect != DialectSmb_3_1_1 {
		// SMB 3.0 / 3.0.2 have no negotiate contexts: signing is fixed at
		// AES-128-CMAC and, when encryption was negotiated via the
		// GlobalCapEncryption capability flag above, the cipher is fixed at
		// AES-128-CCM (MS-SMB2 §3.1.4.2, §3.2.5.2). Pin those defaults here so
		// the SessionSetup key-derivation branch has a concrete algorithm.
		if c.dialect >= DialectSmb_3_0 {
			c.signingId = AES_CMAC
			if c.supportsEncryption {
				c.cipherId = AES128CCM
			}
		}
		return nil
	}

	// Handle context for SMB 3.1.1
	foundSigningContext := false
	for _, context := range negRes.ContextList {
		switch context.ContextType {
		case PreauthIntegrityCapabilities:
			pic := PreauthIntegrityContext{}
			err = pic.UnmarshalBinary(context.Data)
			if err != nil {
				return err
			}
			if pic.HashAlgorithmCount != 1 { // Must be 1 selection according to spec
				err = fmt.Errorf("multiple hash algorithms")
				return err
			}
			c.preauthIntegrityHashId = pic.HashAlgorithms[0]
			// MS-SMB2 Section 3.2.5.2 last paragraph.
			switch c.preauthIntegrityHashId {
			case SHA512:
				h := sha512.New()
				h.Write(c.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(c.preauthIntegrityHashValue[:0])

				h.Reset()
				h.Write(c.preauthIntegrityHashValue[:])
				h.Write(negResBuf)
				h.Sum(c.preauthIntegrityHashValue[:0])

			default:
				err = fmt.Errorf("unknown hash algorithm")
				return err
			}
		case EncryptionCapabilities:
			ec := EncryptionContext{}
			err = ec.UnmarshalBinary(context.Data)
			if err != nil {
				return err
			}
			if ec.CipherCount != 1 { // Must be 1 according to spec
				err = fmt.Errorf("multiple cipher algorithms")
				return err
			}
			switch ec.Ciphers[0] {
			case AES128GCM, AES256GCM, AES128CCM, AES256CCM:
				c.cipherId = ec.Ciphers[0]
				c.supportsEncryption = true
			case CipherNone:
				// MS-SMB2 §3.3.5.4: a server that shares no cipher with our
				// offer answers with a single Cipher of 0x0000. That is a
				// well-formed "no encryption available", not an error — the
				// connection continues unencrypted (and signed). Treating it as
				// a fatal unknown-cipher would refuse to talk to such a server
				// at all.
				c.cipherId = CipherNone
				c.supportsEncryption = false
				log.Debugln("Server offered no common cipher; continuing without encryption")
			default:
				err = fmt.Errorf("unknown cipher algorithm (%d)", ec.Ciphers[0])
				return err
			}

		case SigningCapabilities: // Only supported by Windows 11/Window Server 2022 and later
			sc := SigningContext{}
			err = sc.UnmarshalBinary(context.Data)
			if err != nil {
				return err
			}
			if sc.SigningAlgorithmCount != 1 {
				err = fmt.Errorf("multiple signing algorithms")
				return err
			}
			c.signingId = sc.SigningAlgorithms[0]
			switch c.signingId {
			case HMAC_SHA256:
			case AES_CMAC:
			case AES_GMAC:
			default:
				err = fmt.Errorf("unknown signing algorithm (%d)", c.signingId)
				return err
			}

			foundSigningContext = true

		case CompressionCapabilities:
			// Only meaningful if we actually offered compression; a server that
			// volunteers the context unasked does not get to switch it on.
			if !c.options.Compression {
				log.Debugln("Ignoring CompressionCapabilities context: compression was not offered")
				break
			}
			cc := CompressionContext{}
			if err = cc.UnmarshalBinary(context.Data); err != nil {
				return err
			}
			// Keep only algorithms we can actually handle. Pattern_V1 is
			// decode-only for us but valid to accept inside chained frames.
			var negotiated []uint16
			for _, alg := range cc.CompressionAlgorithms {
				switch alg {
				case CompressionLZ77, CompressionLZ77Huffman, CompressionPatternV1:
					negotiated = append(negotiated, alg)
				}
			}
			chained := cc.Flags&CompressionCapabilitiesFlagChained != 0
			c.compression.Configure(negotiated, chained, compress.DefaultMinSize)
			log.Debugf("negotiated compression algorithms %v (chained=%v)\n", negotiated, chained)

		default:
			log.Debugf("Unsupported context type (%d)\n", context.ContextType)
		}
	}

	if !foundSigningContext && c.dialect > DialectSmb_2_1 {
		// Default for SMB 3.x when no SigningContent is received is to use AES_CMAC for signing
		c.signingId = AES_CMAC
	}

	return nil
}

func (c *Connection) SessionSetup() (err error) {
	// Debug breadcrumb at the layer seam, see NegotiateProtocol.
	defer func() {
		if err != nil {
			log.Debugln(err)
		}
	}()
	// Make sure to reset relevant options to allow multiple logins
	c.disableSession()
	c.sessionID = 0
	c.isAuthenticated = false

	// RawNTLMSSP: drive bare NTLMSSP tokens directly through the initiator,
	// bypassing SPNEGO framing. spnegoClient stays nil in that mode; rawInit
	// is the concrete NTLM initiator (validated in validateOptions).
	rawMode := c.options.RawNTLMSSP
	var spnegoClient *spnego.Client
	var rawInit *spnego.NTLMInitiator
	if rawMode {
		var ok bool
		rawInit, ok = c.options.Initiator.(*spnego.NTLMInitiator)
		if !ok {
			return fmt.Errorf("RawNTLMSSP requires a *spnego.NTLMInitiator")
		}
	} else {
		spnegoClient, err = spnego.NewClient([]gss.Mechanism{c.options.Initiator})
		if err != nil {
			return err
		}
	}

	log.Debugln("Sending SessionSetup1 request")
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		log.Debugln(err)
		return err
	}

	// challengeBytes holds the bare NTLMSSP CHALLENGE extracted from the leg-1
	// response — from the SPNEGO ResponseToken or, in raw mode, the whole blob.
	var (
		rr             *requestResponse
		ssresbuf       []byte
		challengeBytes []byte
	)

	if rawMode {
		negToken, nErr := rawInit.InitSecContext(nil) // bare NTLMSSP NEGOTIATE
		if nErr != nil {
			return nErr
		}
		ssreq := c.NewSessionSetupRawReq(negToken)
		ssreq.Header.Credits = 127
		rr, err = c.send(&ssreq)
		if err != nil {
			return err
		}
		ssresbuf, err = c.recv(rr)
		if err != nil {
			return err
		}
		log.Traceln("Unmarshalling raw SessionSetup1 response")
		var rawRes SessionSetupRes
		if err := rawRes.UnmarshalBinary(ssresbuf); err != nil {
			log.Debugln(err)
			return err
		}
		// Populate the header/flags on ssres so the shared flow below keys off
		// the same fields as the SPNEGO path.
		ssres.Header = rawRes.Header
		ssres.Flags = rawRes.Flags
		challengeBytes = rawRes.SecurityBlob
	} else {
		ssreq, sErr := c.NewSessionSetup1Req(spnegoClient)
		if sErr != nil {
			log.Debugln(sErr)
			return sErr
		}
		// Since I'm not currently handling credits I try to request more than I need
		// Turns out that with Kerberos auth I sometimes lack credits due to shorter
		// SessionSetup flow
		ssreq.Header.Credits = 127
		rr, err = c.send(&ssreq)
		if err != nil {
			return err
		}
		ssresbuf, err = c.recv(rr)
		if err != nil {
			return err
		}
		log.Traceln("Unmarshalling SessionSetup1 response")
		if err := ssres.UnmarshalBinary(ssresbuf); err != nil {
			log.Debugln(err)
			return err
		}
		// Extracting target info only works for NTLMSSP and not for Kerberos
		if ssres.SecurityBlob.SupportedMech.Equal(gss.NtLmSSPMechTypeOid) {
			challengeBytes = ssres.SecurityBlob.ResponseToken
		}
	}

	// Extract target info from the bare NTLMSSP CHALLENGE (NTLM only — empty
	// for Kerberos).
	if len(challengeBytes) > 0 {
		challenge := ntlmssp.NewChallenge()
		if err := challenge.UnmarshalBinary(challengeBytes); err != nil {
			log.Debugln(err)
			return err
		}

		// Extract target info from server Challange
		versionBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(versionBuf, challenge.Version)
		buildNumber := binary.LittleEndian.Uint16(versionBuf[2:4])
		c.targetInfo = &TargetInfo{
			OS:               challenge.Version,
			GuessedOSVersion: fmt.Sprintf("Windows NT %d.%d Build %d", versionBuf[0], versionBuf[1], buildNumber),
		}
		for _, av := range *challenge.TargetInfo {
			switch av.AvID {
			case ntlmssp.MsvAvDnsDomainName:
				c.targetInfo.DnsDomainName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					// Informational fields only, not a reason to fail the session setup.
					log.Warningf("Failed to decode DNS Domain Name from AV Pair with error: %s\n", err)
					err = nil
				}
			case ntlmssp.MsvAvDnsComputerName:
				c.targetInfo.DnsComputerName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Warningf("Failed to decode DNS Computer Name from AV Pair with error: %s\n", err)
					err = nil
				}
			case ntlmssp.MsvAvNbDomainName:
				c.targetInfo.NBDomainName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Warningf("Failed to decode NB Domain Name from AV Pair with error: %s\n", err)
					err = nil
				}
			case ntlmssp.MsvAvNbComputerName:
				c.targetInfo.NBComputerName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Warningf("Failed to decode NB Computer Name from AV Pair with error: %s\n", err)
					err = nil
				}
			default:
			}
		}
	}

	if err = statusError("SessionSetup1", ssres.Header.Status, StatusMoreProcessingRequired); err != nil {
		return err
	}

	c.sessionID = ssres.Header.SessionID

	if c.isSigningRequired.Load() {
		if ssres.Flags&SessionFlagIsGuest != 0 {
			err = fmt.Errorf("guest account doesn't support signing")
			return err
		} else if ssres.Flags&SessionFlagIsNull != 0 {
			err = fmt.Errorf("anonymous account doesn't support signing")
			return err
		}
	}

	//TODO Validate Challenge security options?
	// Adopt the server's session flags, including its SMB2_SESSION_FLAG_ENCRYPT_DATA
	// verdict (MS-SMB2 §3.2.5.3.1). Only force session-wide encryption when the
	// caller explicitly opted in via RequireEncryption; otherwise per-tree
	// enforcement (treeIdEncrypts) handles ENCRYPT_DATA shares individually.
	c.sessionFlags = ssres.Flags
	if c.Session.options.DisableEncryption {
		c.sessionFlags &= ^SessionFlagEncryptData
	} else if c.Session.options.RequireEncryption && c.supportsEncryption {
		c.sessionFlags |= SessionFlagEncryptData
	}

	switch c.dialect {
	case DialectSmb_3_1_1:
		c.Session.preauthIntegrityHashValue = c.preauthIntegrityHashValue
		switch c.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(c.Session.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(c.Session.preauthIntegrityHashValue[:0])

			if ssres.Header.Status == StatusMoreProcessingRequired {
				h.Reset()
				h.Write(c.Session.preauthIntegrityHashValue[:])
				h.Write(ssresbuf)
				h.Sum(c.Session.preauthIntegrityHashValue[:0])
			}
		}
	}

	if c.options.Initiator.IsNullSession() {
		// Anonymous auth. Record the intent: combined with a successful
		// SessionSetup this is what makes the session a null session, whether or
		// not the server sets SMB2_SESSION_FLAG_IS_NULL. The sessionFlags bit is
		// kept as well because the signing/encryption gating below keys off it.
		c.authedAsNull = true
		c.sessionFlags |= SessionFlagIsNull
		c.sessionFlags &= ^SessionFlagEncryptData
	}

	// finalSSResbuf holds the raw bytes of the last SESSION_SETUP response in
	// the exchange. Its signature is verified once the signing key is derived
	// (see below) — MS-SMB2 §3.2.5.3.1. In the common multi-leg flow this is
	// the SessionSetup2 response; in a single-leg flow it is the first one.
	finalSSResbuf := ssresbuf

	// Retrieve the full username used in the authentication attempt
	// <domain\username> or just <username> if domain component is empty
	c.Session.authUsername = c.options.Initiator.GetUsername()

	if ssres.Status == StatusMoreProcessingRequired {
		log.Debugln("Sending SessionSetup2 request")
		var ss2resbuf []byte
		if rawMode {
			authToken, aErr := rawInit.InitSecContext(challengeBytes) // bare NTLMSSP AUTHENTICATE
			if aErr != nil {
				return aErr
			}
			ss2req := c.NewSessionSetupRawReq(authToken)
			ss2req.Header.Credits = 127
			rr, err = c.send(&ss2req)
			if err != nil {
				return err
			}
			ss2resbuf, err = c.recv(rr)
			if err != nil {
				return err
			}
		} else {
			securityBlob, sErr := ssres.SecurityBlob.MarshalBinary()
			if sErr != nil {
				return sErr
			}
			sc, sErr := spnegoClient.InitSecContext(securityBlob)
			if sErr != nil {
				return sErr
			}
			ss2req, sErr := c.NewSessionSetup2Req(sc, &ssres)
			if sErr != nil {
				log.Debugln(sErr)
				return sErr
			}
			ss2req.Header.Credits = 127
			rr, err = c.send(&ss2req)
			if err != nil {
				return err
			}
			ss2resbuf, err = c.recv(rr)
			if err != nil {
				return err
			}
		}
		finalSSResbuf = ss2resbuf
		log.Traceln("Unmarshalling SessionSetup2 response header")

		var authResp Header
		if err := authResp.UnmarshalBinary(ss2resbuf); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(ss2resbuf))
			return err
		}
		if err = statusError("SessionSetup2", authResp.Status); err != nil {
			return err
		}

		log.Traceln("Unmarshalling SessionSetup2 response")
		ssres2, err := NewSessionSetup2Res()
		if err != nil {
			log.Debugln(err)
			return err
		}
		if err := ssres2.UnmarshalBinary(ss2resbuf); err != nil {
			log.Debugln(err)
			return err
		}

		// When relaying through a proxy, if we don't have a sessionID yet,
		// take it from the SessionSetup2Res message
		if c.useProxy {
			c.sessionID = ssres2.SessionID
		}

		//TODO Unmarshal the Security Blob as well?

		if ssres2.Header.Status == StatusOk {
			// Fold the server's guest/null verdict into sessionFlags; the
			// signing/encryption gating below keys off these bits.
			if ssres2.Flags&SessionFlagIsGuest == SessionFlagIsGuest {
				c.Session.sessionFlags |= SessionFlagIsGuest
			}
			if ssres2.Flags&SessionFlagIsNull == SessionFlagIsNull {
				c.Session.sessionFlags |= SessionFlagIsNull
			}
			// MS-SMB2 §3.2.5.3.1: honor the server's session-wide encryption
			// directive. A server that requires encryption only sets
			// SMB2_SESSION_FLAG_ENCRYPT_DATA on the final SessionSetup response
			// (after deriving keys), so it is not visible on the first-response
			// flags copied above. Unless the caller opted out via
			// DisableEncryption, adopt it so every PDU is wrapped in a
			// TransformHeader. This is the server-driven counterpart to the
			// client-side RequireEncryption opt-in handled off the first response.
			if ssres2.Flags&SessionFlagEncryptData == SessionFlagEncryptData &&
				!c.Session.options.DisableEncryption {
				c.Session.sessionFlags |= SessionFlagEncryptData
			}
		}
	}

	// Check if we authenticated as guest or with a null session. If so, disable signing and encryption
	if ((c.sessionFlags & SessionFlagIsGuest) == SessionFlagIsGuest) || ((c.sessionFlags & SessionFlagIsNull) == SessionFlagIsNull) {
		c.isSigningRequired.Store(false)
		c.options.DisableEncryption = true
		//c.sessionFlags = ssres2.Flags             //NOTE Replace all sessionFlags here?
		c.sessionFlags &= ^SessionFlagEncryptData // Make sure encryption is disabled
		if c.IsGuestSession() {
			c.authUsername += " (GUEST)"
		}
	}

	c.isAuthenticated = true

	// Handle signing and encryption options
	if c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
		var sessionKey []byte
		if rawMode {
			sessionKey = rawInit.SessionKey()[:16]
		} else {
			sessionKey = spnegoClient.SessionKey()[:16]
		}
		c.exportedSessionKey = sessionKey

		switch c.dialect {
		case DialectSmb_2_0_2, DialectSmb_2_1:
			if !c.isSigningDisabled {
				c.Session.signer = newHashSigner(hmac.New(sha256.New, sessionKey))
				c.Session.verifier = newHashVerifier(hmac.New(sha256.New, sessionKey))
			}
		case DialectSmb_3_0, DialectSmb_3_0_2:
			// SMB 3.0 / 3.0.2 key derivation (MS-SMB2 §3.1.4.2). Unlike 3.1.1
			// these dialects have no negotiate contexts: signing is always
			// AES-128-CMAC and encryption, when negotiated, is always
			// AES-128-CCM. The KDF context is a fixed string rather than the
			// preauth-integrity hash (which only exists in 3.1.1).
			signingKey := kdf(sessionKey, smb30LabelSigning, smb30ContextSigning, 128)
			cs, errS := cmac.New(signingKey)
			if errS != nil {
				return fmt.Errorf("init AES-CMAC signer: %w", errS)
			}
			cv, errV := cmac.New(signingKey)
			if errV != nil {
				return fmt.Errorf("init AES-CMAC verifier: %w", errV)
			}
			c.Session.signer = newHashSigner(cs)
			c.Session.verifier = newHashVerifier(cv)

			if c.supportsEncryption {
				// c.cipherId was pinned to AES128CCM during NegotiateProtocol.
				encryptionKey := kdf(sessionKey, smb30LabelCipher, smb30ContextC2S, 128)
				decryptionKey := kdf(sessionKey, smb30LabelCipher, smb30ContextS2C, 128)

				ciph, errC := aes.NewCipher(encryptionKey)
				if errC != nil {
					return errC
				}
				c.Session.encrypter, errC = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if errC != nil {
					return errC
				}
				ciph, errC = aes.NewCipher(decryptionKey)
				if errC != nil {
					return errC
				}
				c.Session.decrypter, errC = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				if errC != nil {
					return errC
				}
				log.Debugln("Initialized encrypter and decrypter with CCM (SMB 3.0/3.0.2)")
			}

			c.applicationKey = kdf(sessionKey, smb30LabelApp, smb30ContextApp, 128)
		case DialectSmb_3_1_1:
			switch c.preauthIntegrityHashId {
			case SHA512:
				if ssres.Header.Status == StatusMoreProcessingRequired {
					// Calculate the preauthIntegrityHashValue over the second SessionSetup req sent
					// Make sure to only perform the below steps for Kerberos if MoreProcessing was required
					h := sha512.New()
					h.Write(c.Session.preauthIntegrityHashValue[:])
					h.Write(rr.pkt)
					h.Sum(c.Session.preauthIntegrityHashValue[:0])
				}
			}

			// SMB 3.1.1 requires either signing or encryption of requests, so can't disable signing.
			// Signingkey is always 128bit
			signingKey := kdf(sessionKey, smb311LabelSigning, c.Session.preauthIntegrityHashValue[:], 128)

			switch c.signingId {
			case AES_CMAC:
				cs, errS := cmac.New(signingKey)
				if errS != nil {
					return fmt.Errorf("init AES-CMAC signer: %w", errS)
				}
				cv, errV := cmac.New(signingKey)
				if errV != nil {
					return fmt.Errorf("init AES-CMAC verifier: %w", errV)
				}
				c.Session.signer = newHashSigner(cs)
				c.Session.verifier = newHashVerifier(cv)
			case HMAC_SHA256:
				c.Session.signer = newHashSigner(hmac.New(sha256.New, signingKey))
				c.Session.verifier = newHashVerifier(hmac.New(sha256.New, signingKey))
			case AES_GMAC:
				gcm, errG := newAESGMAC(signingKey)
				if errG != nil {
					return fmt.Errorf("init AES-GMAC signer: %w", errG)
				}
				c.Session.signer = newGmacSigner(gcm)
				c.Session.verifier = newGmacVerifier(gcm)
			default:
				err = fmt.Errorf("unknown signing algorithm (%d) not implemented", c.signingId)
				return err
			}

			if c.supportsEncryption {
				// Determine size of L variable for the KDF
				var l uint32
				switch c.cipherId {
				case AES128GCM:
					l = 128
				case AES128CCM:
					l = 128
				case AES256CCM:
					l = 256
				case AES256GCM:
					l = 256
				default:
					err = fmt.Errorf("cipher algorithm (%d) not implemented", c.cipherId)
					return err
				}

				encryptionKey := kdf(sessionKey, smb311LabelC2S, c.Session.preauthIntegrityHashValue[:], l)
				decryptionKey := kdf(sessionKey, smb311LabelS2C, c.Session.preauthIntegrityHashValue[:], l)

				switch c.cipherId {
				case AES128GCM, AES256GCM:
					ciph, err := aes.NewCipher(encryptionKey)
					if err != nil {
						return err
					}
					c.Session.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
					if err != nil {
						return err
					}

					ciph, err = aes.NewCipher(decryptionKey)
					if err != nil {
						return err
					}
					c.Session.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
					if err != nil {
						return err
					}
					log.Debugln("Initialized encrypter and decrypter with GCM")
				case AES128CCM, AES256CCM:
					ciph, err := aes.NewCipher(encryptionKey)
					if err != nil {
						return err
					}
					c.Session.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
					if err != nil {
						return err
					}
					ciph, err = aes.NewCipher(decryptionKey)
					if err != nil {
						return err
					}
					c.Session.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
					if err != nil {
						return err
					}
					log.Debugln("Initialized encrypter and decrypter with CCM")
				default:
					err = fmt.Errorf("cipher algorithm (%d) not implemented", c.cipherId)
					return err
				}
			}

			// Handle ApplicationKey
			c.applicationKey = kdf(sessionKey, smb311LabelApp, c.Session.preauthIntegrityHashValue[:], 128)
		}
	}

	// MS-SMB2 §3.2.5.3.1: when signing is negotiated the client MUST verify
	// the signature on the final SESSION_SETUP response. It authenticates the
	// server and detects tampering or a downgrade by an active attacker. This
	// response is consumed before the signing key exists and the normal
	// receive-path verify gate skips the SessionSetup command, so it is checked
	// here, once the verifier has been derived. The gate mirrors the receive
	// path (connection.go): for 3.1.1 always (the preauth-integrity hash also
	// backstops it); for 2.0.2/2.1/3.0/3.0.2, only when signing is required —
	// those dialects have no preauth-hash backstop, so this is the sole check.
	// Guest/null sessions disable signing and are excluded. Fail closed.
	if c.verifyFinalSessionSetupSignature() {
		if len(finalSSResbuf) < 64 {
			return fmt.Errorf("final SessionSetup response is too short (%d bytes) to verify its signature", len(finalSSResbuf))
		}
		var fh Header
		if err := fh.UnmarshalBinary(finalSSResbuf[:64]); err != nil {
			return fmt.Errorf("decode final SessionSetup response header: %w", err)
		}
		if fh.Flags&SMB2_FLAGS_SIGNED != SMB2_FLAGS_SIGNED {
			return fmt.Errorf("final SessionSetup response is not signed but signing is required; aborting")
		}
		if !c.verify(finalSSResbuf) {
			return fmt.Errorf("final SessionSetup response has an invalid signature; aborting")
		}
		log.Debugln("Verified signature on final SessionSetup response")
	}

	log.Debugln("Completed NegotiateProtocol and SessionSetup")

	c.enableSession()

	return nil
}

// verifyFinalSessionSetupSignature reports whether the final SESSION_SETUP
// response signature must be verified (MS-SMB2 §3.2.5.3.1). It mirrors the
// inbound verify gate in runReceiver: SMB 3.1.1 always verifies (guest/null
// excluded), older dialects verify only when signing is required. A nil
// verifier (signing disabled) means there is nothing to check.
func (c *Connection) verifyFinalSessionSetupSignature() bool {
	if c.Session.verifier == nil {
		return false
	}
	if c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) != 0 {
		return false
	}
	if c.dialect == DialectSmb_3_1_1 {
		return true
	}
	return c.isSigningRequired.Load()
}

func (c *Connection) Logoff() error {
	for _, k := range c.treeNames() {
		c.TreeDisconnect(k)
	}

	req := c.NewLogoffReq()
	buf, err := c.sendrecv(&req)
	if err != nil {
		return err
	}

	res := NewLogoffRes()
	log.Traceln("Unmarshalling Logoff response")
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugln(err)
		return err
	}

	if err = statusError("Logoff", res.Status); err != nil {
		return err
	}
	c.disableSession()
	c.sessionID = 0
	c.options.Initiator.Logoff()
	c.isAuthenticated = false

	return nil
}

func (s *Session) sign(buf []byte) ([]byte, error) {
	hdr, err := parseHeader("sign", buf)
	if err != nil {
		return nil, err
	}
	hdr.Flags |= SMB2_FLAGS_SIGNED
	hdr.Signature = make([]byte, 16)
	hdrBuf, err := hdr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(buf[:64], hdrBuf[:64])
	sig := s.signer.Sign(buf)
	copy(buf[48:64], sig)

	return buf, nil
}

func (s *Session) verify(buf []byte) (ok bool) {
	if len(buf) < headerSize {
		return false
	}
	signature := make([]byte, 16)
	copy(signature, buf[48:64])
	// Zero the signature field for the MAC computation, then restore it
	// regardless of outcome so callers see the original packet bytes.
	copy(buf[48:64], make([]byte, 16))
	defer copy(buf[48:64], signature)
	return s.verifier.Verify(buf, signature)
}

func (s *Session) encrypt(buf []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	tHdr := NewTransformHeader()
	copy(tHdr.Nonce, nonce)
	tHdr.OriginalMessageSize = uint32(len(buf))
	tHdr.SessionId = s.sessionID
	tHdrBytes, err := tHdr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	ciphertext := s.encrypter.Seal(nil, nonce, buf, tHdrBytes[20:52])
	copy(tHdrBytes[4:20], ciphertext[len(ciphertext)-16:])
	return append(tHdrBytes, ciphertext[:len(ciphertext)-16]...), nil
}

func (s *Session) decrypt(buf []byte) ([]byte, error) {
	tHdr := NewTransformHeader()
	err := tHdr.UnmarshalBinary(buf[:52])
	if err != nil {
		return nil, err
	}
	ciphertext := append(buf[52:], tHdr.Signature...)
	// Not sure where it is specified that part of the transform header is used as AdditionalData
	return s.decrypter.Open(ciphertext[:0], tHdr.Nonce[:s.decrypter.NonceSize()], ciphertext, buf[20:52])
}

func (c *Connection) GetAuthUsername() string {
	return c.authUsername
}

func (c *Connection) GetTargetInfo() *TargetInfo {
	return c.targetInfo
}

// treeId returns the TreeConnect id for a share name, or 0 if the share is not
// currently connected. TreeId 0 is never a valid connected tree, so it doubles
// as a "not found" sentinel.
func (s *Session) treeId(name string) uint32 {
	s.treeLock.RLock()
	defer s.treeLock.RUnlock()
	if t, ok := s.trees[name]; ok {
		return t.treeId
	}
	return 0
}

// hasTree reports whether the named share is currently tree-connected.
func (s *Session) hasTree(name string) bool {
	s.treeLock.RLock()
	defer s.treeLock.RUnlock()
	_, ok := s.trees[name]
	return ok
}

// treeNames returns a snapshot of the connected share names. Callers that
// mutate the tree map (e.g. disconnecting every tree) must iterate this
// snapshot rather than ranging the live map.
func (s *Session) treeNames() []string {
	s.treeLock.RLock()
	defer s.treeLock.RUnlock()
	names := make([]string, 0, len(s.trees))
	for k := range s.trees {
		names = append(names, k)
	}
	return names
}

// canEncrypt reports whether the connection can encrypt PDUs such that the
// server will be able to decrypt them: encryption was negotiated, the client
// offered the capability (it did not opt out via DisableEncryption), and an
// encrypter is initialized. A server derives its decrypter only when the client
// advertised GlobalCapEncryption, so having offered the capability is required —
// the EncryptionCapabilities negotiate context alone is not sufficient.
func (s *Session) canEncrypt() bool {
	return s.supportsEncryption && !s.options.DisableEncryption && s.encrypter != nil
}

// treeIdEncrypts reports whether the share behind the given TreeConnect id was
// flagged by the server with SMB2_SHAREFLAG_ENCRYPT_DATA, meaning every request
// on that tree must be encrypted (MS-SMB2 §3.2.5.5).
func (s *Session) treeIdEncrypts(id uint32) bool {
	if id == 0 {
		return false
	}
	s.treeLock.RLock()
	defer s.treeLock.RUnlock()
	for _, t := range s.trees {
		if t.treeId == id {
			return t.encryptData
		}
	}
	return false
}

// TreeConnectInfo returns the ShareFlags, Capabilities and MaximalAccess the
// server reported for an already-connected share. ok is false if the share is
// not connected.
func (s *Session) TreeConnectInfo(name string) (shareFlags, capabilities, maximalAccess uint32, ok bool) {
	s.treeLock.RLock()
	defer s.treeLock.RUnlock()
	t, ok := s.trees[name]
	if !ok {
		return 0, 0, 0, false
	}
	return t.shareFlags, t.capabilities, t.maximalAccess, true
}

func (c *Connection) TreeConnect(name string) error {
	// Check if already connected
	if c.hasTree(name) {
		return nil
	}

	log.Debugf("Sending TreeConnect request [%s]\n", name)
	req, err := c.NewTreeConnectReq(name)
	if err != nil {
		log.Debugln(err)
		return err
	}
	buf, err := c.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return err
	}

	log.Tracef("Unmarshalling TreeConnect response Header [%s]\n", name)
	if _, err := headerStatus("TreeConnect", buf); err != nil {
		return err
	}

	var res TreeConnectRes

	log.Tracef("Unmarshalling TreeConnect response [%s]\n", name)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return err
	}

	if err = statusError("TreeConnect", res.Header.Status); err != nil {
		return err
	}

	encryptData := res.ShareFlags&ShareFlagEncryptData != 0
	// MS-SMB2 §3.2.5.5: if the share requires encryption but the connection
	// cannot encrypt end-to-end, the client MUST fail the tree connect rather
	// than send traffic the server is unable to decrypt (or plaintext it will
	// reject with STATUS_ACCESS_DENIED).
	if encryptData && !c.canEncrypt() {
		return fmt.Errorf("share [%s]: %w", name, ErrShareRequiresEncryption)
	}

	c.treeLock.Lock()
	c.trees[name] = &treeConnect{
		treeId:        res.Header.TreeID,
		shareFlags:    res.ShareFlags,
		capabilities:  res.Capabilities,
		maximalAccess: res.MaximalAccess,
		encryptData:   encryptData,
	}
	c.treeLock.Unlock()
	// Granted credits are accounted centrally in the receive loop.

	log.Debugf("Completed TreeConnect [%s]\n", name)
	return nil
}

func (c *Connection) TreeDisconnect(name string) error {

	treeid := c.treeId(name)
	if treeid == 0 {
		err := fmt.Errorf("unable to find tree path for disconnect")
		log.Debugln(err)
		return err
	}

	log.Debugf("Sending TreeDisconnect request [%s]\n", name)
	req, err := c.NewTreeDisconnectReq(treeid)
	if err != nil {
		log.Debugln(err)
		return err
	}
	buf, err := c.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	log.Tracef("Unmarshalling TreeDisconnect response for [%s]\n", name)
	var res TreeDisconnectRes
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return err
	}
	if err = statusError("TreeDisconnect", res.Header.Status); err != nil {
		return err
	}
	c.treeLock.Lock()
	delete(c.trees, name)
	c.treeLock.Unlock()

	log.Debugf("TreeDisconnect completed [%s]\n", name)
	return nil
}

func (f *File) IsOpen() bool {
	return f.fd != nil
}

// Echo sends an SMB2 ECHO (MS-SMB2 §2.2.28) and waits for the reply. It is a
// connection-level keepalive that probes the server is still responsive
// without touching any share or file.
func (c *Connection) Echo() error {
	return c.EchoContext(context.Background())
}

// EchoContext is Echo with cancellation.
func (c *Connection) EchoContext(ctx context.Context) error {
	req := c.NewEchoReq()
	buf, err := c.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	_, err = headerStatus("Echo", buf)
	return err
}

// Flush issues an SMB2 FLUSH (MS-SMB2 §2.2.17) for this open handle, asking the
// server to commit all buffered writes to stable storage, and waits for
// confirmation. Call it after a sequence of WriteFile calls when durability
// must be guaranteed before proceeding.
func (f *File) Flush() error {
	return f.FlushContext(context.Background())
}

// FlushContext is Flush with cancellation.
func (f *File) FlushContext(ctx context.Context) error {
	if f.fd == nil {
		return fmt.Errorf("can't operate on a closed file")
	}
	req := f.NewFlushReq(f.share, f.fd)
	buf, err := f.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	_, err = headerStatus("Flush", buf)
	return err
}

func (f *File) CloseFile() error {

	if f.fd == nil {
		// Already closed
		return nil
	}
	log.Debugf("Sending Close request [%s] for fileid [%x]\n", f.share, f.fd)
	req, err := f.NewCloseReq(f.share, f.fd)
	if err != nil {
		log.Debugln(err)
		return err
	}

	buf, err := f.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	var res CloseRes
	log.Tracef("Unmarshalling Close response [%s] for fileid [%x]\n", f.share, f.fd)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugln(err)
		return err
	}

	if err = statusError("CloseFile", res.Header.Status); err != nil {
		return err
	}
	log.Debugf("Close of file completed [%s] fileid [%x]\n", f.share, f.fd)
	f.fd = nil
	return nil
}

// QueryDirectory enumerates one buffer's worth of directory entries. See
// QueryDirectoryContext for the cancellable form.
func (f *File) QueryDirectory(pattern string, flags byte, fileIndex uint32, bufferSize uint32) (sf []SharedFile, err error) {
	return f.QueryDirectoryContext(context.Background(), pattern, flags, fileIndex, bufferSize)
}

// QueryDirectoryContext is QueryDirectory with cancellation.
func (f *File) QueryDirectoryContext(ctx context.Context, pattern string, flags byte, fileIndex uint32, bufferSize uint32) (sf []SharedFile, err error) {
	if f.fd == nil {
		return nil, fmt.Errorf("can't operate on a closed file")
	}
	sf = make([]SharedFile, 0)
	req, err := f.NewQueryDirectoryReq(
		f.share,
		pattern,
		f.fd,
		FileBothDirectoryInformation,
		flags,
		fileIndex,
		bufferSize,
	)
	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := f.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var res QueryDirectoryRes
	log.Tracef("Unmarshalling QueryDirectory response [%s]\n", f.share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return sf, err
	}

	if res.Header.Status == StatusNoMoreFiles {
		return
	} else if res.Header.Status == StatusNoSuchFile {
		return
	}

	if err = statusError("QueryDirectory", res.Header.Status); err != nil {
		return
	}
	if res.OutputBufferLength == 0 {
		return
	}

	// NextEntryOffset is server-controlled and drives the walk below, so every
	// entry boundary has to be re-validated: an oversized (or zero-but-repeating)
	// offset would otherwise slice past the buffer and panic on the caller's
	// goroutine, where the receiver's recover() cannot help. Clamp the end to
	// the bytes we actually received, since OutputBufferLength is server-supplied
	// too and need not match the buffer.
	stop := res.OutputBufferLength
	if int(stop) > len(res.Buffer) {
		stop = uint32(len(res.Buffer))
	}
	start := uint32(0)
	for start < stop {
		var fs FileBothDirectoryInformationStruct
		if err = fs.UnmarshalBinary(res.Buffer[start:stop]); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
			return sf, err
		}
		if int(fs.FileNameLength) > len(fs.FileName) {
			return sf, fmt.Errorf("QueryDirectory: entry declares a %d-byte name but only %d bytes are present", fs.FileNameLength, len(fs.FileName))
		}
		fileName, err := encoder.FromUnicodeString(fs.FileName[:fs.FileNameLength])
		if err != nil {
			log.Debugln(err)
			return sf, err
		}
		// A zero NextEntryOffset marks the last entry; anything else must move
		// strictly forward and stay inside the buffer, or the walk would either
		// spin forever or run off the end.
		next := start
		if fs.NextEntryOffset != 0 {
			next = start + fs.NextEntryOffset
			if fs.NextEntryOffset > stop || next <= start || next > stop {
				return sf, fmt.Errorf("QueryDirectory: entry at %d has an out-of-range NextEntryOffset of %d", start, fs.NextEntryOffset)
			}
		}
		start = next
		if (fileName == ".") || (fileName == "..") {
			// We don't care about the current and parent dir references
			if fs.NextEntryOffset == 0 {
				break
			}
			continue
		}
		sharedFile := SharedFile{
			Name:           fileName,
			Size:           fs.EndOfFile,
			CreationTime:   fs.CreationTime,
			LastAccessTime: fs.LastAccessTime,
			LastWriteTime:  fs.LastWriteTime,
			ChangeTime:     fs.ChangeTime,
			IsHidden:       (fs.FileAttributes & FileAttrHidden) == FileAttrHidden,
			IsDir:          (fs.FileAttributes & FileAttrDirectory) == FileAttrDirectory,
			IsReadOnly:     (fs.FileAttributes & FileAttrReadonly) == FileAttrReadonly,
			IsJunction:     (fs.FileAttributes & FileAttrReparsePoint) == FileAttrReparsePoint,
		}

		sf = append(sf, sharedFile)
		if fs.NextEntryOffset == 0 {
			break
		}
	}
	return
}

func (f *File) QueryInfoSecurity(bufferSize uint32) (fs *FileSecurityInformation, err error) {
	sd, err := f.QueryInfoSecurityRaw(
		OwnerSecurityInformation|GroupSecurityInformation|DACLSecurityInformation,
		bufferSize,
	)
	if err != nil {
		return nil, err
	}

	fs = &FileSecurityInformation{}
	// OwnerSid/GroupSid are nil when the server returns a descriptor without an
	// owner or group; ToString would dereference a nil *SID and panic.
	if sd.OwnerSid != nil {
		fs.OwnerSID = sd.OwnerSid.ToString()
	}
	if sd.GroupSid != nil {
		fs.GroupSID = sd.GroupSid.ToString()
	}
	if sd.Dacl != nil {
		for _, acl := range sd.Dacl.ACLS {
			if acl.Header.Type != AccessAllowedAceType {
				continue
			}
			fs.Access = append(fs.Access, FileSecurityInformationACL{
				Permissions: ParseAccessMask(acl.Mask),
				SID:         acl.Sid.ToString(),
			})
		}
	}

	return
}

// QueryInfoSecurityRaw queries the security descriptor of an open file and
// returns it parsed, preserving every ACE and its raw access mask. Unlike
// QueryInfoSecurity (which reduces the DACL to friendly allow-ACE permission
// names and so loses the object-specific bits such as FILE_WRITE_DATA), this
// gives callers the full descriptor to evaluate themselves. additionalInformation
// selects the components to request, e.g.
// OwnerSecurityInformation|GroupSecurityInformation|DACLSecurityInformation.
// A bufferSize of 0 selects a default and retries once on a buffer overflow.
func (f *File) QueryInfoSecurityRaw(additionalInformation, bufferSize uint32) (*msdtyp.SecurityDescriptor, error) {
	if f.fd == nil {
		return nil, fmt.Errorf("can't operate on a closed file")
	}
	if bufferSize == 0 {
		bufferSize = 8192
	}

	query := func(size uint32) (*QueryInfoRes, error) {
		req, err := f.NewQueryInfoReq(f.share, f.fd, OInfoSecurity, 0, additionalInformation, 0, size, nil)
		if err != nil {
			return nil, fmt.Errorf("new request: %w", err)
		}
		buf, err := f.sendrecv(&req)
		if err != nil {
			return nil, fmt.Errorf("sendrecv: %w", err)
		}
		res := &QueryInfoRes{}
		if err := res.UnmarshalBinary(buf); err != nil {
			log.Debugf("error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
			return nil, err
		}
		return res, nil
	}

	res, err := query(bufferSize)
	if err != nil {
		return nil, err
	}
	// A large DACL overflows a small buffer; retry once with a bigger one.
	if res.Header.Status == StatusBufferOverflow || res.Header.Status == StatusInfoLengthMismatch {
		if res, err = query(65536); err != nil {
			return nil, err
		}
	}

	if res.Header.Status == StatusNoSuchFile {
		return nil, fmt.Errorf("file not found")
	}
	if err := statusError("QueryInfo", res.Header.Status); err != nil {
		return nil, err
	}
	if res.OutputBufferLength == 0 {
		return nil, fmt.Errorf("server response didn't contain any info")
	}

	end := res.OutputBufferLength
	if int(end) > len(res.Buffer) {
		end = uint32(len(res.Buffer))
	}
	sd := &msdtyp.SecurityDescriptor{}
	if err := sd.UnmarshalBinary(res.Buffer[:end]); err != nil {
		return nil, fmt.Errorf("failed parsing security descriptor: %w", err)
	}
	return sd, nil
}

// Assumes a tree connect is already performed
func (s *Connection) ListDirectory(share, dir, pattern string) (files []SharedFile, err error) {
	req, err := s.NewCreateReq(share, dir,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		DAccMaskFileListDirectory|DAccMaskFileReadAttributes,
		FileAttrDirectory,
		FileShareRead|FileShareWrite,
		FileOpen,
		FileDirectoryFile,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return
	}
	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return files, err
	}

	if err = statusError("Create (list directory)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return files, err
	}
	f := &File{Connection: s, share: share, fd: res.FileId, filename: dir, shareid: s.treeId(share)}
	defer f.CloseFile()

	maxResponseBufferSize := uint32(65536)
	if s.supportsMultiCredit {
		maxResponseBufferSize = s.maxTransactSize
	}

	// QueryDirectory request
	for {
		moreFiles, err := f.QueryDirectory(pattern, 0, 0, maxResponseBufferSize)
		if err != nil {
			log.Debugln(err)
			return files, err
		}
		if len(moreFiles) == 0 {
			break
		}
		files = append(files, moreFiles...)
	}

	// Update files with full path
	for i := range files {
		file := &files[i]
		if (file.Name == ".") || (file.Name == "..") {
			continue
		}
		if dir == "" {
			file.FullPath = file.Name
		} else {
			file.FullPath = fmt.Sprintf("%s\\%s", dir, file.Name)
		}
	}
	return
}

// Assumes a tree connect is already performed
func (s *Connection) ListRecurseDirectory(share, dir, pattern string) (files []SharedFile, err error) {
	files, err = s.ListDirectory(share, dir, pattern)
	if err != nil {
		log.Debugln(err)
		return
	}
	for _, file := range files {
		if !file.IsDir {
			continue
		}
		if (file.Name == ".") || (file.Name == "..") {
			continue
		}
		if file.IsJunction {
			// Don't follow junctions
			continue
		}

		moreFiles, err := s.ListRecurseDirectory(share, file.FullPath, pattern)
		if err != nil {
			log.Debugln(err)
			return files, err
		}
		files = append(files, moreFiles...)
	}
	return
}

func (s *Connection) ListShare(share, dir string, recurse bool) (files []SharedFile, err error) {

	files = make([]SharedFile, 0)
	// Connect to Tree
	err = s.TreeConnect(share)
	if err != nil {
		log.Debugln(err)
		return
	}
	// Defer tree disconnect
	defer s.TreeDisconnect(share)

	if recurse {
		files, err = s.ListRecurseDirectory(share, dir, "*")
	} else {
		files, err = s.ListDirectory(share, dir, "*")
	}

	return
}

func (s *Connection) OpenFileExt(tree string, filepath string, opts *CreateReqOpts) (file *File, err error) {
	// If tree is not connected, connect to it
	if !s.hasTree(tree) {
		err = s.TreeConnect(tree)
		if err != nil {
			log.Debugln(err)
			return
		}
		//defer s.TreeDisconnect(tree)
	}

	req, err := s.NewCreateReq(tree, filepath,
		opts.OpLockLevel,
		opts.ImpersonationLevel,
		opts.DesiredAccess,
		opts.FileAttr,
		opts.ShareAccess,
		opts.CreateDisp,
		opts.CreateOpts,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return nil, err
	}

	if err = statusError("Create (custom options)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", tree)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return nil, err
	}

	//TODO Perhaps change to contain date objects instead of uint32
	return &File{
		Connection: s,
		FileMetadata: FileMetadata{
			CreateAction:   res.CreateAction,
			CreationTime:   res.CreationTime,
			LastAccessTime: res.LastAccessTime,
			LastWriteTime:  res.LastWriteTime,
			ChangeTime:     res.ChangeTime,
			Attributes:     res.FileAttributes,
			EndOfFile:      res.EndOfFile,
		},
		shareid:  s.treeId(tree),
		fd:       res.FileId,
		share:    tree,
		filename: filepath,
	}, nil

}

func (s *Connection) OpenFile(tree string, filepath string) (file *File, err error) {
	return s.OpenFileExt(tree, filepath, NewCreateReqOpts())

}

// OpenFileReadAttributes opens a file or directory requesting only READ_CONTROL
// (plus FILE_READ_ATTRIBUTES and SYNCHRONIZE) — enough to read its security
// descriptor via QueryInfoSecurity / QueryInfoSecurityRaw even when the caller
// has no data-read access. Remember to call CloseFile on the returned handle.
func (s *Connection) OpenFileReadAttributes(tree string, filepath string) (file *File, err error) {
	opts := NewCreateReqOpts()
	opts.DesiredAccess = FAccMaskReadControl | FAccMaskFileReadAttributes | FAccMaskSynchronize
	return s.OpenFileExt(tree, filepath, opts)
}

// connectToTree connects to share if not already connected.
// Returns true if a new connection was made (caller should defer TreeDisconnect),
// or false if already connected. Returns an error if the connection failed.
func (s *Connection) connectToTree(share string) (bool, error) {
	if s.hasTree(share) {
		return false, nil
	}
	if err := s.TreeConnect(share); err != nil {
		return false, err
	}
	return true, nil
}

// RetrieveFile streams a remote file to callback. See RetrieveFileContext for
// the cancellable form.
func (s *Connection) RetrieveFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {
	return s.RetrieveFileContext(context.Background(), share, filepath, offset, callback)
}

// RetrieveFileContext is RetrieveFile with cancellation. The context is checked
// between chunks and threaded into every round trip, so a cancelled transfer
// stops promptly instead of running to completion.
func (s *Connection) RetrieveFileContext(ctx context.Context, share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {

	if callback == nil {
		err = fmt.Errorf("must specify a callback function to handle retrieved data")
		log.Debugln(err)
		return
	}

	disconnectFromTree, err := s.connectToTree(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

	req, err := s.NewCreateReq(share, filepath,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		FAccMaskFileReadData|FAccMaskFileReadEA|FAccMaskFileReadAttributes|FAccMaskReadControl|FAccMaskSynchronize,
		0,
		FileShareRead|FileShareWrite,
		FileOpen,
		FileNonDirectoryFile,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if err = statusError("Create (read file)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		share:      share,
		filename:   filepath,
		shareid:    s.treeId(share),
		fd:         res.FileId,
	}
	defer f.CloseFile()

	if res.EndOfFile == 0 {
		return
	}

	log.Traceln("Sending ReadFile requests")
	data := make([]byte, s.maxReadSize)
	fileSize := res.EndOfFile

	readOffset := offset
	for readOffset < fileSize {
		// Check between chunks as well as inside each round trip: a cancelled
		// transfer should stop at the next boundary even if the current READ
		// happened to complete first.
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := f.ReadFileContext(ctx, data, readOffset)
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("got EOF before finished reading")
				return err
			}
			log.Debugln(err)
			return err
		}
		nw, err := callback(data[:n])
		if err != nil {
			log.Debugln(err)
			return err
		} else if n != nw {
			err = fmt.Errorf("failed to write all the data to callback")
			log.Debugln(err)
			return err
		}
		readOffset += uint64(n)
	}

	return err
}

// ReadFile reads into b starting at offset, returning the number of bytes
// read. See ReadFileContext for the cancellable form.
func (f *File) ReadFile(b []byte, offset uint64) (n int, err error) {
	return f.ReadFileContext(context.Background(), b, offset)
}

// ReadFileContext is ReadFile with cancellation. Cancelling ctx abandons the
// in-flight READ and sends an SMB2 CANCEL for it.
func (f *File) ReadFileContext(ctx context.Context, b []byte, offset uint64) (n int, err error) {
	if f.fd == nil {
		return 0, fmt.Errorf("can't operate on a closed file")
	}
	// Bound a single READ request. Without multi-credit support the server
	// permits only one 64 KiB credit per request. With it, cap to the
	// server-advertised MaxReadSize and then to what the current credit window
	// can cover, so a read larger than the granted window is split across
	// several requests instead of charging more credits than exist and blocking
	// forever in reserve. Splitting is transparent: each READ carries its own
	// offset, and callers already loop on the returned (possibly short) count.
	//
	// NOTE: like WriteFile, this trusts the server-advertised MaxReadSize. Some
	// servers misbehave on transfers larger than 1 MiB regardless of what they
	// advertise; if reads fail or stall, clamp maxReadBufferSize to 1<<20.
	maxReadBufferSize := 65536
	if f.supportsMultiCredit {
		maxReadBufferSize = int(f.maxReadSize)
		if w := f.creditWindowBytes(); w < maxReadBufferSize {
			maxReadBufferSize = w
		}
	}
	if maxReadBufferSize < 65536 {
		maxReadBufferSize = 65536
	}
	if len(b) > maxReadBufferSize {
		b = b[:maxReadBufferSize]
	}

	req, err := f.NewReadReq(f.share, f.fd,
		//f.MaxReadSize,
		uint32(len(b)),
		offset,
		0, // Read at least 1 byte
	)
	if err != nil {
		return
	}

	buf, err := f.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return
	}

	h, err := parseHeader("Read", buf)
	if err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return n, err
	}

	/*
	   Handle EOF:
	   MS-SMB2 Section 2.2.20 SMB2 READ Response
	   The minimum length is 1 byte. If 0 bytes are returned from the
	   underlying object store, the server MUST send a failure response with status equal to
	   STATUS_END_OF_FILE
	*/
	if h.Status == StatusEndOfFile {
		return 0, io.EOF
	} else if h.Status == FsctlStatusPipeDisconnected {
		return 0, StatusMap[FsctlStatusPipeDisconnected]
	} else if err = statusError("Read", h.Status); err != nil {
		return
	}

	var res ReadRes
	log.Tracef("Unmarshalling Read response [%s]\n", f.share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugln(err)
		return n, err
	}

	// DataOffset is measured from the start of the SMB2 header and res.Buffer
	// begins after the 64-byte header plus the 16-byte fixed part of the READ
	// response, so the index into res.Buffer is DataOffset-80. DataOffset is a
	// single byte: computing this in byte arithmetic would wrap modulo 256 for
	// any value below 80 (0 becomes 176) and silently read from the wrong place,
	// so widen first and reject anything that cannot be a valid offset.
	const readResFixedLen = headerSize + 16
	if int(res.DataOffset) < readResFixedLen {
		err = fmt.Errorf("read response DataOffset %d precedes the response body", res.DataOffset)
		log.Debugln(err)
		return
	}
	bufferOffset := int(res.DataOffset) - readResFixedLen
	if bufferOffset > len(res.Buffer) {
		err = fmt.Errorf("returned offset is outside response buffer")
		log.Debugln(err)
		return
	}
	nCopy := copy(b, res.Buffer[bufferOffset:])
	n = int(res.DataLength)
	if nCopy != n {
		err = fmt.Errorf("failed to copy result data into supplied buffer")
		log.Debugln(err)
		return
	}
	return
}

// PutFile streams data from callback into a remote file. See PutFileContext
// for the cancellable form.
func (s *Connection) PutFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {
	return s.PutFileContext(context.Background(), share, filepath, offset, callback)
}

// PutFileContext is PutFile with cancellation. The context is checked between
// chunks and threaded into every round trip.
func (s *Connection) PutFileContext(ctx context.Context, share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {
	disconnectFromTree, err := s.connectToTree(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

	accessMask := FAccMaskFileReadData |
		FAccMaskFileWriteData |
		FAccMaskFileAppendData |
		FAccMaskFileReadEA |
		FAccMaskFileWriteEA |
		FAccMaskFileReadAttributes |
		FAccMaskFileWriteAttributes |
		FAccMaskReadControl |
		FAccMaskSynchronize

	req, err := s.NewCreateReq(share, filepath,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		accessMask,
		0,
		FileShareRead|FileShareWrite,
		FileOverwriteIf,
		FileNonDirectoryFile,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecvContext(ctx, &req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if err = statusError("Create (write file)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		filename:   filepath,
		fd:         res.FileId,
		share:      share,
		shareid:    s.treeId(share),
	}
	defer f.CloseFile()

	log.Traceln("Sending WriteFile requests")

	writeOffset := offset
	for {
		// See RetrieveFileContext: stop at the next chunk boundary on
		// cancellation rather than pulling more data from the callback.
		if err := ctx.Err(); err != nil {
			return err
		}
		outBuffer := make([]byte, s.maxWriteSize)
		nr, err := callback(outBuffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		n, err := f.WriteFileContext(ctx, outBuffer[:nr], writeOffset)
		if err != nil {
			log.Debugln(err)
			return err
		}
		writeOffset += uint64(n)
	}

	return
}

// WriteFile writes data at offset, returning the number of bytes written. See
// WriteFileContext for the cancellable form.
func (f *File) WriteFile(data []byte, offset uint64) (n int, err error) {
	return f.WriteFileContext(context.Background(), data, offset)
}

// WriteFileContext is WriteFile with cancellation. Cancelling ctx abandons the
// in-flight WRITE and sends an SMB2 CANCEL for it.
func (f *File) WriteFileContext(ctx context.Context, data []byte, offset uint64) (n int, err error) {
	if f.fd == nil {
		return 0, fmt.Errorf("can't operate on a closed file")
	}

	// Write all of data, splitting it across as many WRITE requests as the
	// per-request ceiling requires. Without multi-credit support a request is
	// limited to a single 64 KiB credit; with it, cap each chunk to the
	// server-advertised MaxWriteSize and then to what the current credit window
	// covers, so a large write is split into requests whose CreditCharge stays
	// within the granted window rather than deadlocking in reserve. Callers
	// (PutFile) rely on WriteFile consuming the whole buffer, so the loop
	// continues until data is exhausted.
	//
	// NOTE: MaxWriteSize is trusted as the per-request ceiling, but in practice
	// some servers misbehave on WRITE requests larger than 1 MiB even though
	// they advertise a bigger MaxWriteSize (an earlier revision of this code
	// hard-capped transfers at 1 MiB for exactly this reason). If large writes
	// start failing or stalling against a particular server, clamp chunkMax to
	// 1<<20 here (and the read path in ReadFile) before assuming the bug is
	// elsewhere.
	for n < len(data) {
		chunkMax := 65536
		if f.supportsMultiCredit {
			chunkMax = int(f.maxWriteSize)
			if w := f.creditWindowBytes(); w < chunkMax {
				chunkMax = w
			}
		}
		if chunkMax < 65536 {
			chunkMax = 65536
		}
		end := n + chunkMax
		if end > len(data) {
			end = len(data)
		}
		chunk := data[n:end]

		req, err := f.NewWriteReq(f.share, f.fd, offset+uint64(n), chunk)
		if err != nil {
			log.Debugln(err)
			return n, err
		}

		buf, err := f.sendrecvContext(ctx, &req)
		if err != nil {
			log.Debugln(err)
			return n, err
		}

		var res WriteRes
		log.Tracef("Unmarshalling Write response [%s]\n", f.share)
		if err := res.UnmarshalBinary(buf); err != nil {
			log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
			return n, err
		}
		if err = statusError("Write", res.Status); err != nil {
			return n, err
		}
		if res.Count == 0 {
			// A server that acknowledges zero bytes would otherwise spin the
			// loop forever; surface it instead.
			return n, fmt.Errorf("Write made no progress at offset %d", offset+uint64(n))
		}
		n += int(res.Count)
	}
	return n, nil
}

func (f *File) IsDir() bool {
	return (f.Attributes & FileAttrDirectory) == FileAttrDirectory
}

func (s *Connection) deleteFileDir(share string, path string, isDir bool) (err error) {
	disconnectFromTree, err := s.connectToTree(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	var accessMask uint32
	var createOpts uint32

	if isDir {
		accessMask = DAccMaskDelete
		createOpts = FileDirectoryFile
	} else {
		accessMask = FAccMaskFileReadData |
			FAccMaskFileReadAttributes |
			FAccMaskDelete
		createOpts = FileNonDirectoryFile
	}

	req, err := s.NewCreateReq(share, path,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		accessMask,
		0,
		FileShareRead|FileShareWrite|FileShareDelete,
		FileOpen,
		createOpts,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		return err
	}

	if err = statusError("Create (delete file)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugln(err)
		return err
	}
	f := &File{
		Connection: s,
		filename:   path,
		fd:         res.FileId,
		share:      share,
		shareid:    s.treeId(share),
	}
	defer f.CloseFile()

	// Set Info
	sReq, err := s.NewSetInfoReq(share, f.fd)
	if err != nil {
		log.Debugln(err)
		return
	}
	sReq.InfoType = OInfoFile
	sReq.FileInfoClass = FileDispositionInformation

	// Simple structure of the FileDispositionInformation request to delete a file or directory
	sReq.Buffer = make([]byte, 1)
	sReq.Buffer[0] = 1

	buf, err = s.sendrecv(&sReq)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h2 Header
	if err := h2.UnmarshalBinary(buf); err != nil {
		log.Debugln(err)
		return err
	}

	if err = statusError("SetInfo response when deleting file or directory", h2.Status); err != nil {
		return err
	}

	return
}

func (s *Connection) DeleteFile(share string, filepath string) (err error) {
	return s.deleteFileDir(share, filepath, false)
}

func (s *Connection) DeleteDir(share string, dirpath string) (err error) {
	return s.deleteFileDir(share, dirpath, true)
}

func (s *Connection) WriteIoCtlReq(req *IoCtlReq) (res IoCtlRes, err error) {
	buf, err := s.sendrecv(req)
	if err != nil {
		return res, err
	}
	if _, err = headerStatus("IoCtlRequest", buf); err != nil {
		return res, err
	}

	if err = res.UnmarshalBinary(buf); err != nil {
		return res, err
	}

	return res, nil
}

// Close tears down the connection: it disconnects every mounted tree, stops
// the receiver, and closes the underlying socket. It is safe to call more than
// once and from multiple goroutines — the common "defer conn.Close()" alongside
// an explicit Close on an error path would otherwise panic on the second
// close(c.rdone).
func (c *Connection) Close() {
	c.closeOnce.Do(func() {
		log.Debug("Closing session")
		for _, k := range c.treeNames() {
			c.TreeDisconnect(k)
		}
		close(c.rdone)

		if c.conn != nil {
			log.Debug("Closing TCP connection")
			c.conn.Close()
		}
		log.Debug("Session close completed")
	})
}

// Create a new directory
func (s *Connection) Mkdir(share string, path string) (err error) {
	disconnectFromTree, err := s.connectToTree(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	req, err := s.NewCreateReq(share, path,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		DAccMaskGenericAll,
		0,
		0,
		FileCreate,
		FileDirectoryFile,
	)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecv(&req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := h.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if err = statusError("Create (write file)", h.Status); err != nil {
		return
	}

	var res CreateRes
	log.Tracef("Unmarshalling Create response [%s]\n", share)
	if err := res.UnmarshalBinary(buf); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		filename:   path,
		fd:         res.FileId,
		share:      share,
		shareid:    s.treeId(share),
	}
	defer f.CloseFile()

	return
}

// Creates a directory named path along with any necessary parent directories
// If the directory specified by path already exists, the return value is nil
func (s *Connection) MkdirAll(share string, path string) (err error) {
	disconnectFromTree, err := s.connectToTree(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	// First check if directory already exists
	createOpts := NewCreateReqOpts()
	createOpts.CreateOpts = 0

	f, err := s.OpenFileExt(share, path, createOpts)
	if err == nil {
		if f.IsDir() {
			f.CloseFile()
			return
		}
		f.CloseFile()
		return fmt.Errorf("create directory %s: already exists and is not a directory: %w", path, ErrorNotDir)
	} else {
		if !errors.Is(err, StatusMap[StatusObjectNameNotFound]) && !errors.Is(err, StatusMap[StatusObjectPathNotFound]) {
			err = fmt.Errorf("check if directory %s exists: %w", path, err)
			return
		}
	}

	// Path or directory does not exist so let's create it
	elements := strings.Split(path, `\`)
	if len(elements) > 1 {
		err = s.MkdirAll(share, strings.Join(elements[:len(elements)-1], `\`))
		if err != nil {
			return err
		}
	}

	// Now the parent dirs should exist, so create the final dir
	err = s.Mkdir(share, path)
	if err != nil {
		return fmt.Errorf("create directory %s: %w", path, err)
	}

	return
}

// IsNullSession reports whether this session is an accepted anonymous (null)
// session: the client authenticated with NTLMSSP_NEGOTIATE_ANONYMOUS (empty
// LM/NT responses) and the SessionSetup succeeded. This is derived from the
// client's own auth attempt plus success, not from the server's
// SMB2_SESSION_FLAG_IS_NULL — some servers accept a null session without
// setting that flag, so the flag alone is an unreliable signal.
func (c *Session) IsNullSession() bool {
	return c.isAuthenticated && c.authedAsNull
}

// IsGuestSession reports whether the server mapped this logon onto its Guest
// account, as signalled by SMB2_SESSION_FLAG_IS_GUEST in the SESSION_SETUP
// response. Unlike the null case there is no client-side signal for guest — the
// client sends a genuine credential and only the server decides — so the
// server's flag is the only, and authoritative, indicator.
func (c *Session) IsGuestSession() bool {
	return c.sessionFlags&SessionFlagIsGuest == SessionFlagIsGuest
}

// SessionAuthResult classifies how an authenticated session was established:
// as a normal user, as a guest (server verdict), or as an anonymous/null
// session (client-requested and accepted).
type SessionAuthResult int

const (
	// AuthResultUser indicates a normal authenticated session: neither guest
	// nor anonymous.
	AuthResultUser SessionAuthResult = iota
	// AuthResultGuest indicates the server mapped the logon onto its Guest
	// account (SMB2_SESSION_FLAG_IS_GUEST).
	AuthResultGuest
	// AuthResultAnonymous indicates an accepted anonymous/null session (the
	// client sent NTLMSSP_NEGOTIATE_ANONYMOUS and SessionSetup succeeded). Note
	// that "null session" and "anonymous" are the same NTLM mechanism.
	AuthResultAnonymous
)

func (r SessionAuthResult) String() string {
	switch r {
	case AuthResultGuest:
		return "guest"
	case AuthResultAnonymous:
		return "anonymous"
	default:
		return "user"
	}
}

// AuthResult classifies how the authenticated session was established. This is
// the single accessor a caller should use to fingerprint a server's auth
// policy: run each probe (normal creds, NTLMAuthAnonymous, NTLMAuthGuest) and
// read AuthResult on the resulting session. Guest (the server's verdict) takes
// precedence in the unlikely event the server also flags a requested null
// session as guest.
func (c *Session) AuthResult() SessionAuthResult {
	switch {
	case c.IsGuestSession():
		return AuthResultGuest
	case c.IsNullSession():
		return AuthResultAnonymous
	default:
		return AuthResultUser
	}
}

// FileID returns the 16-byte SMB2 FileId of an open handle, or nil once the
// file has been closed. Exposed for callers that need to address the handle in
// a hand-built PDU (see Connection.SendRawPDU) — for example commands this
// client does not model natively.
func (f *File) FileID() []byte {
	if f.fd == nil {
		return nil
	}
	return append([]byte(nil), f.fd...)
}

// SessionID returns the negotiated SMB2 SessionId of this connection. Zero
// before SessionSetup completes.
func (c *Connection) SessionID() uint64 {
	return c.sessionID
}

// TreeID returns the TreeId of a connected share, or 0 when the share is not
// currently connected.
func (c *Connection) TreeID(share string) uint32 {
	return c.treeId(share)
}
