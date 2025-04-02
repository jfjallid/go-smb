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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
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
	isSigningRequired   atomic.Bool
	isSigningDisabled   bool
	isAuthenticated     bool
	supportsEncryption  bool
	clientGuid          []byte
	securityMode        uint16
	messageID           uint64
	sessionID           uint64 // Does this need to be atomic?
	credits             uint64
	sessionFlags        uint16
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
	signer         hash.Hash
	verifier       hash.Hash
	encrypter      cipher.AEAD
	decrypter      cipher.AEAD
	conn           net.Conn
	dialect        uint16
	options        Options
	trees          map[string]uint32
	lock           sync.RWMutex
	authUsername   string // Combined domain and username as sent in SessionSetup2 request
	targetInfo     *TargetInfo
}

type Options struct {
	Host                  string
	Port                  int
	Workstation           string
	Domain                string
	User                  string
	Password              string
	Hash                  string
	DisableSigning        bool
	RequireMessageSigning bool
	DisableEncryption     bool
	ForceSMB2             bool
	Initiator             gss.Mechanism
	DialTimeout           time.Duration
	ProxyDialer           proxy.Dialer
	RelayPort             int
	ManualLogin           bool
}

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return fmt.Errorf("Missing required option: Host. Use -h for help on usage.")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return fmt.Errorf("Invalid or missing value: Port. Use -h for help on usage.")
	}
	if opt.Initiator == nil && !opt.ManualLogin {
		return fmt.Errorf("Initiator empty")
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

func (c *Connection) NegotiateProtocol() error {
	var rr *requestResponse
	var negRes NegotiateRes

	negReq1, err := c.NewSMB1NegotiateReq()
	if err != nil {
		log.Errorln(err)
		return err
	}
	log.Debugln("Sending SMB1 NegotiateProtocol request")
	rr, err = c.send(&negReq1)
	if err != nil {
		log.Debugln(err)
		return err
	}

	negResBuf, err := c.recv(rr)
	if err != nil {
		log.Debugln(err)
		return err
	}

	if negResBuf[0] == 0xFF {
		// Server does not support or want to use SMB2.
		err = fmt.Errorf("Target %s is only accepting SMBv1, but SMBv1 support is not implemented", c.conn.RemoteAddr().String())
		log.Errorln(err) // Skip print?
		return err
	}

	negRes1 := NewNegotiateRes()
	log.Debugln("Unmarshalling NegotiateProtocol response")
	if err := encoder.Unmarshal(negResBuf, &negRes1); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(negResBuf))
		return err
	}

	if negRes1.DialectRevision <= DialectSmb2_ALL {
		if negRes1.DialectRevision != DialectSmb2_ALL {
			// NOTE this is likely breaking the SMB2 specification, but since
			// servers such as impacket's smbserver.py responds incorrectly to
			// a multi-protocol negotiation request we attempt to renegotiate
			// the protocol dialect using SMB2.
			err = fmt.Errorf("Server responded to the multi-protocol negotiation with an invalid DialectRevision of 0x%x, but expected 0x%x. Restarting protocol negotiation using SMB2.\n", negRes1.DialectRevision, DialectSmb2_ALL)
			log.Errorln(err)
		}
		// Send new SMB2 NegotiateRequest message
		negReq, err := c.NewNegotiateReq()
		if err != nil {
			log.Errorln(err)
			return err
		}
		log.Debugln("Sending SMB2 NegotiateProtocol request")
		// Reuse rr variable for second neg protocol req to keep reference
		// for calculation of pre-auth integrity hash
		rr, err = c.send(negReq)
		if err != nil {
			log.Debugln(err)
			return err
		}

		negResBuf, err = c.recv(rr)
		if err != nil {
			log.Debugln(err)
			return err
		}

		negRes = NewNegotiateRes()
		log.Debugln("Unmarshalling second NegotiateProtocol response")
		if err := encoder.Unmarshal(negResBuf, &negRes); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(negResBuf))
			return err
		}
	} else {
		err = fmt.Errorf("Server responded to the multi-protocol negotiation with an invalid DialectRevision of 0x%x\n", negRes1.DialectRevision)
		log.Debugln(err)
		return err
	}

	if negRes.Header.Status != StatusOk {
		status, found := StatusMap[negRes.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Negotiate response: 0x%x\n", negRes.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("NT Status Error: %v\n", status)
		return status
	}

	oid := negRes.SecurityBlob.OID
	if !oid.Equal(gss.SpnegoOid) {
		err = fmt.Errorf("Unknown security type OID: %s\n", oid)
		log.Errorln(err)
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
		return fmt.Errorf("Right now, this library only supports NTLMSSP and KRB5 Kerberos, and the server supports neither")
	}

	c.securityMode = negRes.SecurityMode
	c.dialect = negRes.DialectRevision

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
		return nil
	}

	// Handle context for SMB 3.1.1
	foundSigningContext := false
	for _, context := range negRes.ContextList {
		switch context.ContextType {
		case PreauthIntegrityCapabilities:
			pic := PreauthIntegrityContext{}
			err = encoder.Unmarshal(context.Data, &pic)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if pic.HashAlgorithmCount != 1 { // Must be 1 selection according to spec
				err = fmt.Errorf("multiple hash algorithms")
				log.Errorln(err)
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
				err = fmt.Errorf("Unknown hash algorithm")
				log.Errorln(err)
				return err
			}
		case EncryptionCapabilities:
			ec := EncryptionContext{}
			err = encoder.Unmarshal(context.Data, &ec)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if ec.CipherCount != 1 { // Must be 1 according to spec
				err = fmt.Errorf("multiple cipher algorithms")
				log.Errorln(err)
				return err
			}
			c.cipherId = ec.Ciphers[0]
			switch c.cipherId {
			case AES128GCM:
			case AES256GCM:
			case AES128CCM:
			case AES256CCM:
			default:
				err = fmt.Errorf("Unknown cipher algorithm (%d)\n", c.cipherId)
				log.Errorln(err)
				return err
			}
			c.supportsEncryption = true

		case SigningCapabilities: // Only supported by Windows 11/Window Server 2022 and later
			sc := SigningContext{}
			err = encoder.Unmarshal(context.Data, &sc)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if sc.SigningAlgorithmCount != 1 {
				err = fmt.Errorf("multiple signing algorithms")
				log.Errorln(err)
				return err
			}
			c.signingId = sc.SigningAlgorithms[0]
			switch c.signingId {
			case HMAC_SHA256:
			case AES_CMAC:
			default:
				err = fmt.Errorf("Unknown signing algorithm (%d)\n", c.signingId)
				log.Errorln(err)
				return err
			}

			foundSigningContext = true

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

func (c *Connection) SessionSetup() error {
	// Make sure to reset relevant options to allow multiple logins
	c.disableSession()
	c.sessionID = 0
	c.isAuthenticated = false

	spnegoClient, err := spnego.NewClient([]gss.Mechanism{c.options.Initiator})
	if err != nil {
		log.Errorln(err)
		return err
	}
	log.Debugln("Sending SessionSetup1 request")
	ssreq, err := c.NewSessionSetup1Req(spnegoClient)
	if err != nil {
		log.Debugln(err)
		return err
	}
	// Since I'm not currently handling credits I try to request more than I need
	// Turns out that with Kerberos auth I sometimes lack credits due to shorter
	// SessionSetup flow
	ssreq.Header.Credits = 127
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		log.Debugln(err)
		return err
	}

	rr, err := c.send(ssreq)
	if err != nil {
		log.Errorln(err)
		return err
	}
	ssresbuf, err := c.recv(rr)
	if err != nil {
		log.Errorln(err)
		return err
	}

	log.Debugln("Unmarshalling SessionSetup1 response")
	if err := encoder.Unmarshal(ssresbuf, &ssres); err != nil {
		log.Debugln(err)
		return err
	}

	resp := ssres.SecurityBlob
	// Extracting target info only works for NTLMSSP and not for Kerberos
	if resp.SupportedMech.Equal(gss.NtLmSSPMechTypeOid) {
		challenge := ntlmssp.NewChallenge()
		if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
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
					log.Errorf("Failed to decode DNS Domain Name from AV Pair with error: %s\n", err)
				}
			case ntlmssp.MsvAvDnsComputerName:
				c.targetInfo.DnsComputerName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Errorf("Failed to decode DNS Computer Name from AV Pair with error: %s\n", err)
				}
			case ntlmssp.MsvAvNbDomainName:
				c.targetInfo.NBDomainName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Errorf("Failed to decode NB Domain Name from AV Pair with error: %s\n", err)
				}
			case ntlmssp.MsvAvNbComputerName:
				c.targetInfo.NBComputerName, err = encoder.FromUnicodeString(av.Value)
				if err != nil {
					log.Errorf("Failed to decode NB Computer Name from AV Pair with error: %s\n", err)
				}
			default:
			}
		}
	}

	if (ssres.Header.Status != StatusMoreProcessingRequired) && (ssres.Header.Status != StatusOk) {
		status, found := StatusMap[ssres.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for SessionSetup1 response: 0x%x\n", ssres.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("NT Status Error: %v\n", status)
		return status
	}

	c.sessionID = ssres.Header.SessionID

	if c.isSigningRequired.Load() {
		if ssres.Flags&SessionFlagIsGuest != 0 {
			err = fmt.Errorf("guest account doesn't support signing")
			log.Errorln(err)
			return err
		} else if ssres.Flags&SessionFlagIsNull != 0 {
			err = fmt.Errorf("anonymous account doesn't support signing")
			log.Errorln(err)
			return err
		}
	}

	//TODO Validate Challenge security options?
	c.sessionFlags = ssres.Flags
	if c.Session.options.DisableEncryption {
		c.sessionFlags &= ^SessionFlagEncryptData
	} else if c.supportsEncryption {
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
		// Anonymous auth
		c.sessionFlags |= SessionFlagIsNull
		c.sessionFlags &= ^SessionFlagEncryptData
	}

	securityBlob, err := encoder.Marshal(ssres.SecurityBlob)
	if err != nil {
		log.Errorln(err)
		return err
	}

	sc, err := spnegoClient.InitSecContext(securityBlob)
	if err != nil {
		log.Errorln(err)
		return err
	}

	var ss2req SessionSetup2Req

	// Retrieve the full username used in the authentication attempt
	// <domain\username> or just <username> if domain component is empty
	c.Session.authUsername = c.options.Initiator.GetUsername()

	if ssres.Status == StatusMoreProcessingRequired {
		log.Debugln("Sending SessionSetup2 request")
		ss2req, err = c.NewSessionSetup2Req(sc, &ssres)
		if err != nil {
			log.Debugln(err)
			return err
		}
		ss2req.Header.Credits = 127

		rr, err = c.send(ss2req)
		if err != nil {
			log.Errorln(err)
			log.Debugln(err)
			return err
		}

		ss2resbuf, err := c.recv(rr)
		if err != nil {
			log.Errorln(err)
			return err
		}
		log.Debugln("Unmarshalling SessionSetup2 response header")

		var authResp Header
		if err := encoder.Unmarshal(ss2resbuf, &authResp); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(ss2resbuf))
			return err
		}
		if authResp.Status != StatusOk {
			status, found := StatusMap[authResp.Status]
			if !found {
				err = fmt.Errorf("Received unknown SMB Header status for SessionSetup2 response: 0x%x\n", authResp.Status)
				log.Errorln(err)
				return err
			}
			log.Debugf("NT Status Error: %v\n", status)
			return status
		}

		log.Debugln("Unmarshalling SessionSetup2 response")
		ssres2, err := NewSessionSetup2Res()
		if err != nil {
			log.Debugln(err)
			return err
		}
		if err := encoder.Unmarshal(ss2resbuf, &ssres2); err != nil {
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
			if ssres2.Flags&SessionFlagIsGuest == SessionFlagIsGuest {
				c.Session.sessionFlags |= SessionFlagIsGuest
			}
			if ssres2.Flags&SessionFlagIsNull == SessionFlagIsNull {
				c.Session.sessionFlags |= SessionFlagIsNull
			}
		}
	}

	// Check if we authenticated as guest or with a null session. If so, disable signing and encryption
	if ((c.sessionFlags & SessionFlagIsGuest) == SessionFlagIsGuest) || ((c.sessionFlags & SessionFlagIsNull) == SessionFlagIsNull) {
		c.isSigningRequired.Store(false)
		c.options.DisableEncryption = true
		//c.sessionFlags = ssres2.Flags             //NOTE Replace all sessionFlags here?
		c.sessionFlags &= ^SessionFlagEncryptData // Make sure encryption is disabled
	}

	c.isAuthenticated = true

	// Handle signing and encryption options
	if c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
		sessionKey := spnegoClient.SessionKey()[:16]
		c.exportedSessionKey = sessionKey

		switch c.dialect {
		case DialectSmb_2_0_2, DialectSmb_2_1:
			if !c.isSigningDisabled {
				c.Session.signer = hmac.New(sha256.New, sessionKey)
				c.Session.verifier = hmac.New(sha256.New, sessionKey)
			}
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
			signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), c.Session.preauthIntegrityHashValue[:], 128)

			switch c.signingId {
			case AES_CMAC:
				c.Session.signer, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.verifier, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
			default:
				err = fmt.Errorf("Unknown signing algorithm (%d) not implemented", c.signingId)
				log.Errorln(err)
				return err
			}

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
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}

			encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)
			decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)

			switch c.cipherId {
			case AES128GCM, AES256GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}
				log.Debugln("Initialized encrypter and decrypter with GCM")
			case AES128CCM, AES256CCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
				log.Debugln("Initialized encrypter and decrypter with CCM")
			default:
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}

			// Handle ApplicationKey
			c.applicationKey = kdf(sessionKey, []byte("SMBAppKey\x00"), c.Session.preauthIntegrityHashValue[:], 128)
		}
	}

	log.Debugln("Completed NegotiateProtocol and SessionSetup")

	c.enableSession()

	return nil
}

func (c *Connection) Logoff() error {
	for k := range c.trees {
		c.TreeDisconnect(k)
	}

	req := c.NewLogoffReq()
	buf, err := c.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		return err
	}

	res := NewLogoffRes()
	log.Debugln("Unmarshalling Logoff response")
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugln(err)
		return err
	}

	if res.Status != StatusOk {
		status, found := StatusMap[res.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Logoff response: 0x%x\n", res.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("NT Status Error: %v\n", status)
		return status
	}
	c.disableSession()
	c.sessionID = 0
	c.options.Initiator.Logoff()
	c.isAuthenticated = false

	return nil
}

func (s *Session) sign(buf []byte) ([]byte, error) {
	var hdr Header
	err := encoder.Unmarshal(buf[:64], &hdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	hdr.Flags |= SMB2_FLAGS_SIGNED
	hdr.Signature = make([]byte, 16)
	hdrBuf, err := encoder.Marshal(hdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	copy(buf[:64], hdrBuf[:64])
	h := s.signer
	h.Reset()
	h.Write(buf)
	copy(buf[48:64], h.Sum(nil))

	return buf, nil
}

func (s *Session) verify(buf []byte) (ok bool) {
	signature := make([]byte, 16)
	copy(signature, buf[48:64])
	// Remove signature
	copy(buf[48:64], make([]byte, 16))
	h := s.verifier
	h.Reset()
	h.Write(buf)
	// Restore signature
	copy(buf[48:64], signature)
	newSig := h.Sum(nil)
	// Not sure this is entirely correct, but smb 2.1 uses sha256 which generates too long hashes
	// Might be worth to investigate if signature is ever more than 16 bytes
	if s.dialect <= DialectSmb_2_1 {
		newSig = newSig[:16]
	}

	return bytes.Equal(signature, newSig)
}

func (s *Session) encrypt(buf []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	tHdr := NewTransformHeader()
	copy(tHdr.Nonce, nonce)
	tHdr.OriginalMessageSize = uint32(len(buf))
	tHdr.SessionId = s.sessionID
	tHdrBytes, err := encoder.Marshal(tHdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	ciphertext := make([]byte, 0)
	ciphertext = s.encrypter.Seal(nil, nonce, buf, tHdrBytes[20:52])
	copy(tHdrBytes[4:20], ciphertext[len(ciphertext)-16:])
	return append(tHdrBytes, ciphertext[:len(ciphertext)-16]...), nil
}

func (s *Session) decrypt(buf []byte) ([]byte, error) {
	tHdr := NewTransformHeader()
	err := encoder.Unmarshal(buf[:52], &tHdr)
	if err != nil {
		log.Errorln(err)
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

func (c *Connection) TreeConnect(name string) error {
	// Check if already connected
	if _, ok := c.trees[name]; ok {
		return nil
	}

	log.Debugf("Sending TreeConnect request [%s]\n", name)
	req, err := c.NewTreeConnectReq(name)
	if err != nil {
		log.Debugln(err)
		return err
	}
	buf, err := c.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return err
	}

	if len(buf) < 64 {
		return fmt.Errorf("TreeConnect received unexpected response from server that was too short")
	}

	var resHeader Header
	log.Debugf("Unmarshalling TreeConnect response Header [%s]\n", name)
	if err := encoder.Unmarshal(buf[:64], &resHeader); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return err
	}
	if resHeader.Status == StatusAccessDenied {
		return StatusMap[StatusAccessDenied]
	} else if resHeader.Status == StatusBadNetworkName {
		return StatusMap[StatusBadNetworkName]
	}

	var res TreeConnectRes

	log.Debugf("Unmarshalling TreeConnect response [%s]\n", name)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return err
	}

	if res.Header.Status != StatusOk {
		status, found := StatusMap[res.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for TreeConnect response: 0x%x\n", res.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("Failed to perform TreeConnect with NT Status Error: %v\n", status)
		return status
	}
	c.trees[name] = res.Header.TreeID
	c.credits += uint64(res.Header.Credits) // Add granted credits

	log.Debugf("Completed TreeConnect [%s]\n", name)
	return nil
}

func (c *Connection) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range c.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := fmt.Errorf("Unable to find tree path for disconnect")
		log.Debugln(err)
		return err
	}

	log.Debugf("Sending TreeDisconnect request [%s]\n", name)
	req, err := c.NewTreeDisconnectReq(treeid)
	if err != nil {
		log.Debugln(err)
		return err
	}
	buf, err := c.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	log.Debugf("Unmarshalling TreeDisconnect response for [%s]\n", name)
	var res TreeDisconnectRes
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return err
	}
	if res.Header.Status != StatusOk {
		status, found := StatusMap[res.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for TreeDisconnect response: 0x%x\n", res.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("Failed to perform TreeDisconnect with NT Status Error: %v\n", status)
		return status
	}
	delete(c.trees, name)

	log.Debugf("TreeDisconnect completed [%s]\n", name)
	return nil
}

func (f *File) IsOpen() bool {
	if f.fd == nil {
		return false
	}
	return true
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

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return err
	}
	var res CloseRes
	log.Debugf("Unmarshalling Close response [%s] for fileid [%x]\n", f.share, f.fd)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugln(err)
		return err
	}

	if res.Header.Status != StatusOk {
		status, found := StatusMap[res.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for CloseFile response: 0x%x\n", res.Header.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("Failed to CloseFile with NT Status Error: %v\n", status)
		return status
	}
	log.Debugf("Close of file completed [%s] fileid [%x]\n", f.share, f.fd)
	f.fd = nil
	return nil
}

func (f *File) QueryDirectory(pattern string, flags byte, fileIndex uint32, bufferSize uint32) (sf []SharedFile, err error) {
	if f.fd == nil {
		return nil, fmt.Errorf("Can't operate on a closed file")
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

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var res QueryDirectoryRes
	log.Debugf("Unmarshalling QueryDirectory response [%s]\n", f.share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return sf, err
	}

	if res.Header.Status == StatusNoMoreFiles {
		return
	} else if res.Header.Status == StatusNoSuchFile {
		return
	}

	if res.Header.Status != StatusOk {
		status, found := StatusMap[res.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for QueryDirectory response: 0x%x\n", res.Header.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed QueryDirectory with NT Status Error: %v\n", status)
		err = status
		return
	}
	if res.OutputBufferLength == 0 {
		return
	}

	start, stop := uint32(0), res.OutputBufferLength
	for {
		var fs FileBothDirectoryInformationStruct
		if err = encoder.Unmarshal(res.Buffer[start:stop], &fs); err != nil {
			log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
			return sf, err
		}
		fileName, err := encoder.FromUnicodeString(fs.FileName[:fs.FileNameLength])
		if err != nil {
			log.Debugln(err)
			return sf, err
		}
		start += fs.NextEntryOffset
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
	if f.fd == nil {
		return nil, fmt.Errorf("Can't operate on a closed file")
	}
	req, err := f.NewQueryInfoReq(
		f.share,
		f.fd,
		OInfoSecurity,
		0,
		OwnerSecurityInformation|GroupSecurityInformation|DACLSecurityInformation,
		0,
		bufferSize,
		nil,
	)
	if err != nil {
		err = fmt.Errorf("new request: %w", err)
		log.Debugln(err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		err = fmt.Errorf("sendrecv: %w", err)
		log.Debugln(err)
		return
	}

	var res QueryInfoRes
	log.Debugf("Unmarshalling QueryInfo response [%s]\n", f.share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(buf))
		return nil, err
	}

	if res.Header.Status == StatusNoSuchFile {
		return nil, fmt.Errorf("file not found")
	}

	if res.Header.Status != StatusOk {
		status, found := StatusMap[res.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for QueryInfo response: 0x%x\n", res.Header.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed QueryInfo with NT Status Error: %v\n", status)
		err = fmt.Errorf("status not ok: %w", status)
		return
	}
	if res.OutputBufferLength == 0 {
		return nil, fmt.Errorf("server response didn't contain any info")
	}

	start, stop := uint32(0), res.OutputBufferLength
	sd := &SecurityDescriptor{}
	err = encoder.Unmarshal(res.Buffer[start:stop], sd)
	if err != nil {
		return nil, fmt.Errorf("failed parsing security descriptor: %w", err)
	}

	fs = &FileSecurityInformation{
		OwnerSID: sd.OwnerSid.String(),
		GroupSID: sd.GroupSid.String(),
	}
	for _, acl := range sd.Dacl.ACLS {
		if acl.Header.Type != AccessAllowedAceType {
			continue
		}
		fs.Access = append(fs.Access, FileSecurityInformationACL{
			Permissions: acl.Permissions(),
			SID:         acl.Sid.String(),
		})
	}

	return
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

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}
	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return files, err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create/open file response attempting to list files in directory: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed to Create/open file for list directory with NT Status Error: %v\n", status)
		err = status
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return files, err
	}
	f := &File{Connection: s, share: share, fd: res.FileId, filename: dir, shareid: s.trees[share]}
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
	if _, ok := s.trees[tree]; !ok {
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

	//req.Credits = 256
	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return nil, err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create/open file response when opening with special options: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed to Create/open file using custom options with NT Status Error: %v\n", status)
		err = status
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", tree)
	if err := encoder.Unmarshal(buf, &res); err != nil {
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
		shareid:  s.trees[tree],
		fd:       res.FileId,
		share:    tree,
		filename: filepath,
	}, nil

}

func (s *Connection) OpenFile(tree string, filepath string) (file *File, err error) {
	return s.OpenFileExt(tree, filepath, NewCreateReqOpts())

}

func (s *Connection) RetrieveFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {

	if callback == nil {
		err = fmt.Errorf("Must specify a callback function to handle retrieved data.")
		log.Debugln(err)
		return
	}

	disconnectFromTree := false
	// Only disconnect from share if it wasn't already connected.
	// Otherwise, allow reuse of existing connection.
	if _, ok := s.trees[share]; !ok {
		disconnectFromTree = true
	}

	err = s.TreeConnect(share)
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

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create/open file response when attempting to download a file: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed to Create/open file for reading with NT Status Error: %v\n", status)
		err = status
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		share:      share,
		filename:   filepath,
		shareid:    s.trees[share],
		fd:         res.FileId,
	}
	defer f.CloseFile()

	if res.EndOfFile == 0 {
		return
	}

	log.Debugln("Sending ReadFile requests")
	data := make([]byte, s.maxReadSize)
	fileSize := res.EndOfFile

	readOffset := offset
	for readOffset < fileSize {
		n, err := f.ReadFile(data, readOffset)
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("Got EOF before finished reading")
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
			err = fmt.Errorf("Failed to write all the data to callback")
			log.Debugln(err)
			return err
		}
		readOffset += uint64(n)
	}

	return err
}

func (f *File) ReadFile(b []byte, offset uint64) (n int, err error) {
	if f.fd == nil {
		return 0, fmt.Errorf("Can't operate on a closed file")
	}
	maxReadBufferSize := 65536
	if f.supportsMultiCredit {
		maxReadBufferSize = len(b)
	}

	// If connection supports multi-credit requests, we can request as large chunks
	// as the caller wants up to an upper limit of the connection maxReadSize. Otherwise the size is limited to
	// 64KiB
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
		log.Errorln(err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	log.Debugln("Reading response")
	var h Header
	if err := encoder.Unmarshal(buf[:64], &h); err != nil {
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
		return 0, FsctlStatusMap[FsctlStatusPipeDisconnected]
	}

	var res ReadRes
	log.Debugf("Unmarshalling Read response [%s]\n", f.share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugln(err)
		return n, err
	}

	// An offset to indicate if the file data is the first thing
	// in the response buffer or if it begins later.
	bufferOffset := int(res.DataOffset - 64 - 16)
	if len(res.Buffer) < bufferOffset {
		err = fmt.Errorf("Returned offset is outside response buffer")
		log.Debugln(err)
		return
	}
	nCopy := copy(b, res.Buffer[bufferOffset:])
	n = int(res.DataLength)
	if nCopy != n {
		err = fmt.Errorf("Failed to copy result data into supplied buffer")
		log.Debugln(err)
		return
	}
	return
}

func (s *Connection) PutFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {
	disconnectFromTree := false
	// Only disconnect from share if it wasn't already connected.
	// Otherwise, allow reuse of existing connection.
	if _, ok := s.trees[share]; !ok {
		disconnectFromTree = true
	}

	err = s.TreeConnect(share)
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

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create/open file response when attempting to upload a file: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed to Create/open file for writing with NT Status Error: %v\n", status)
		err = status
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		filename:   filepath,
		fd:         res.FileId,
		share:      share,
		shareid:    s.trees[share],
	}
	defer f.CloseFile()

	log.Debugln("Sending WriteFile requests")

	writeOffset := offset
	for {
		outBuffer := make([]byte, s.maxWriteSize)
		nr, err := callback(outBuffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Errorln(err)
			return err
		}

		n, err := f.WriteFile(outBuffer[:nr], writeOffset)
		if err != nil {
			log.Debugln(err)
			return err
		}
		writeOffset += uint64(n)
	}

	return
}

func (f *File) WriteFile(data []byte, offset uint64) (n int, err error) {
	if f.fd == nil {
		return 0, fmt.Errorf("Can't operate on a closed file")
	}
	maxWriteBufferSize := 65536
	if f.supportsMultiCredit {
		// Reading data in chunks of max 1MiB blocks as f.MaxReadSize seems to cause problems
		//maxWriteBufferSize = 1048576 // Arbitrary value of 1MiB
		maxWriteBufferSize = len(data)
	}

	// If connection supports multi-credit requests, we can send as large chunks
	// as the caller wants up to an upper limit of 1MiB. Otherwise the size is limited to
	// 64KiB
	if len(data) > maxWriteBufferSize {
		data = data[:maxWriteBufferSize]
	}

	req, err := f.NewWriteReq(f.share, f.fd, offset, data)

	if err != nil {
		log.Debugln(err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var res WriteRes
	log.Debugf("Unmarshalling Write response [%s]\n", f.share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return n, err
	}
	if res.Status != StatusOk {
		status, found := StatusMap[res.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Write response when writing to file: 0x%x\n", res.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("Failed to write file with NT Status Error: %v\n", status)
		err = status
		return
	}
	n = int(res.Count)
	return
}

func (f *File) IsDir() bool {
	return (f.Attributes & FileAttrDirectory) == FileAttrDirectory
}

func (s *Connection) deleteFileDir(share string, path string, isDir bool) (err error) {
	disconnectFromTree := false
	// Only disconnect from share if it wasn't already connected.
	// Otherwise, allow reuse of existing connection.
	if _, ok := s.trees[share]; !ok {
		disconnectFromTree = true
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	err = s.TreeConnect(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

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

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		return err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create response when opening file for deletion: 0x%x\n", h.Status)
			log.Errorln(err)
			return err
		}
		err = status
		if h.Status != StatusObjectNameNotFound {
			log.Debugf("Failed to Create/open file for deletion with NT Status Error: %v\n", status)
		}
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugln(err)
		return err
	}
	f := &File{
		Connection: s,
		filename:   path,
		fd:         res.FileId,
		share:      share,
		shareid:    s.trees[share],
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

	buf, err = s.sendrecv(sReq)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h2 Header
	if err := encoder.Unmarshal(buf, &h2); err != nil {
		log.Debugln(err)
		return err
	}

	if h2.Status != StatusOk {
		status, found := StatusMap[h2.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for SetInfo response when deleting file or directory: 0x%x\n", h2.Status)
			log.Errorln(err)
			return err
		}
		log.Debugf("Failed to delete file or directory with NT Status Error: %v\n", status)
		return status
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
		log.Errorln(err)
		return res, err
	}
	var h Header
	if err = encoder.Unmarshal(buf[:64], &h); err != nil {
		log.Errorln(err)
		return res, err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for IoCtlRequest: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		return res, fmt.Errorf("IoCtlRequest failed with status: %s\n", status)
	}

	if err = encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		return res, err
	}

	return res, nil
}

func (c *Connection) Close() {
	log.Debug("Closing session")
	for k := range c.trees {
		c.TreeDisconnect(k)
	}
	//c.outstandingRequests.shutdown(nil)
	close(c.rdone)

	if c.conn != nil {
		log.Debug("Closing TCP connection")
		c.conn.Close()
	}
	log.Debug("Session close completed")
}

// Create a new directory
func (s *Connection) Mkdir(share string, path string) (err error) {
	disconnectFromTree := false
	// Only disconnect from share if it wasn't already connected.
	// Otherwise, allow reuse of existing connection.
	if _, ok := s.trees[share]; !ok {
		disconnectFromTree = true
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	err = s.TreeConnect(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

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

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Debugln(err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}

	if h.Status != StatusOk {
		status, found := StatusMap[h.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for Create/open file response when attempting to upload a file: 0x%x\n", h.Status)
			log.Errorln(err)
			return
		}
		err = status
		if h.Status != StatusObjectNameCollision {
			// Skip printing error message if it just says that directory already exists
			log.Debugf("Failed to Create/open file for writing with NT Status Error: %v\n", status)
		}
		return
	}

	var res CreateRes
	log.Debugf("Unmarshalling Create response [%s]\n", share)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Debugf("Error: %v\nRaw\n%v\n", err, hex.Dump(buf))
		return err
	}
	f := &File{
		Connection: s,
		filename:   path,
		fd:         res.FileId,
		share:      share,
		shareid:    s.trees[share],
	}
	defer f.CloseFile()

	return
}

// Creates a directory named path along with any necessary parent directories
// If the directory specified by path already exists, the return value is nil
func (s *Connection) MkdirAll(share string, path string) (err error) {
	disconnectFromTree := false
	// Only disconnect from share if it wasn't already connected.
	// Otherwise, allow reuse of existing connection.
	if _, ok := s.trees[share]; !ok {
		disconnectFromTree = true
	}

	// Normalize path
	path = strings.ReplaceAll(path, `/`, `\`)
	path = strings.Trim(path, `\`)

	err = s.TreeConnect(share)
	if err != nil {
		log.Debugln(err)
		return
	}

	if disconnectFromTree {
		defer s.TreeDisconnect(share)
	}

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
		log.Errorf("Failed to create directory (%s) as it already exists and is not a directory\n", path)
		return ErrorNotDir
	} else {
		if err != StatusMap[StatusObjectNameNotFound] && err != StatusMap[StatusObjectPathNotFound] {
			log.Errorf("Attempted to check if file or directory exists but got unexpected error: %s\n", err)
			return
		}
	}

	// Path or directory does not exist so let's create it
	elements := strings.Split(path, `\`)
	if len(elements) > 1 {
		err = s.MkdirAll(share, strings.Join(elements[:len(elements)-1], `\`))
		if err != nil {
			if err == ErrorNotDir {
				return err
			}
			log.Errorf("Failed to create directory (%s) with error: %s\n", elements[:len(elements)-1], err)
			return err
		}
	}

	// Now the parent dirs should exist, so create the final dir
	err = s.Mkdir(share, path)
	if err != nil {
		log.Errorf("Failed to create directory (%s) with error: %s\n", path, err)
		return err
	}

	return
}

func (c *Session) IsNullSession() bool {
	return c.sessionFlags&SessionFlagIsNull == SessionFlagIsNull
}

func (c *Session) IsGuestSession() bool {
	return c.sessionFlags&SessionFlagIsGuest == SessionFlagIsGuest
}
