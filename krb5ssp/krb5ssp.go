// MIT License
//
// # Copyright (c) 2024 Jimmy Fjällid
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
package krb5ssp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/gokrb5/v8/asn1tools"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/iana"
	"github.com/jfjallid/gokrb5/v8/iana/asnAppTag"
	"github.com/jfjallid/gokrb5/v8/iana/etypeID"
	"github.com/jfjallid/gokrb5/v8/iana/keyusage"
	"github.com/jfjallid/gokrb5/v8/iana/msgtype"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/jfjallid/golog"
	"golang.org/x/net/proxy"
)

var le = binary.LittleEndian
var log = golog.Get("github.com/jfjallid/go-smb/krb5ssp").SetDisplayName("krb5ssp")

// Possible values for the KRB5Token struct's TokenId field
const (
	TokenIdKrb5APReq uint16 = 1
	TokenIdKrb5APRep uint16 = 2
	TokenIdKrb5Error uint16 = 3
)

// https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml
const IanaKrb5ChecksumGSSAPI int32 = 32771

// RFC4120 Section 5.5.1 APOption Flags
const (
	APOptionUseSessionKey  = 1
	APOptionMutualRequired = 2
)

// defaultSPNAliases mirrors the subset of AD's sPNMappings relevant to this
// library: "host" is accepted as an alias for each of these service types,
// so a cached ticket for host/<target> can satisfy a request for, e.g.,
// cifs/<target> or ldap/<target>.
var defaultSPNAliases = map[string][]string{
	"cifs":  {"host"},
	"ldap":  {"host"},
	"www":   {"host"},
	"http":  {"host"},
	"rpcss": {"host"},
	"dcom":  {"host"},
}

// This is the type that is marshallized into the mechToken in the negTokenInit request
type KRB5Token struct {
	Oid      asn1.ObjectIdentifier
	TokenId  uint16
	APReq    messages.APReq
	APRep    messages.APRep
	KRBError messages.KRBError
}

type Client struct {
	*client.Client
	sessionKey          types.EncryptionKey
	sessionSubKey       types.EncryptionKey
	micSubkey           types.EncryptionKey
	encAPRepPart        *messages.EncAPRepPart // saved for DCERPC 3rd leg
	authenticatorSeqNum int64                  // saved from AP_REQ authenticator
	spnFallbacks        map[string]string      // requested SPN -> effective SPN (lowercased keys)
}

func NewClient(client *client.Client) *Client {
	return &Client{Client: client}
}

func (t *KRB5Token) MarshalBinary() (res []byte, err error) {
	log.Traceln("In MarshalBinary for KRB5Token")
	res, err = asn1.Marshal(t.Oid)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = le.AppendUint16(res, t.TokenId)

	switch t.TokenId {
	case TokenIdKrb5APReq:
		buf, err := t.APReq.Marshal()
		if err != nil {
			log.Errorln(err)
			return nil, err
		}
		res = append(res, buf...)
	case TokenIdKrb5APRep:
		err = fmt.Errorf("MarshalBinary of KRB5Token APRep not yet implemented!")
		log.Errorln(err)
		return
	case TokenIdKrb5Error:
		err = fmt.Errorf("MarshalBinary of KRB5Token KRBError not yet implemented!")
		log.Errorln(err)
		return
	}

	// Add an Application Tag
	r := asn1.RawValue{
		Class:      asn1.ClassApplication,
		IsCompound: true,
		Tag:        0,
		Bytes:      res,
	}
	res, err = asn1.Marshal(r)
	if err != nil {
		log.Errorln(err)
		return
	}

	return
}

func (t *KRB5Token) UnmarshalBinary(buf []byte) (err error) {
	log.Traceln("In UnmarshalBinary for KRB5Token")

	rest, err := asn1.UnmarshalWithParams(buf, &t.Oid, "application,explicit,tag:0")
	if err != nil {
		log.Errorf("Failed to unmarshal KRB5Token OID: %v\n", err)
		return
	}

	if !t.Oid.Equal(gss.KerberosSSPMechTypeOid) {
		err = fmt.Errorf("KRB5Token OID is %s and not %s as expected", t.Oid.String(), gss.KerberosSSPMechTypeOid.String())
		log.Errorln(err)
		return
	}
	if len(rest) < 2 {
		err = fmt.Errorf("Buffer is too short for KRB5Token")
		log.Errorln(err)
		return
	}

	t.TokenId = le.Uint16(rest[0:2])
	switch t.TokenId {
	case TokenIdKrb5APReq:
		err = fmt.Errorf("Unmarshal of KRB5Token APReq not yet implemented!")
		log.Errorln(err)
		return
	case TokenIdKrb5APRep:
		rep := messages.APRep{}
		err = rep.Unmarshal(rest[2:])
		if err != nil {
			log.Errorln(err)
			return
		}
		t.APRep = rep
	case TokenIdKrb5Error:
		krb5err := messages.KRBError{}
		err = krb5err.Unmarshal(rest[2:])
		if err != nil {
			log.Errorln(err)
			return
		}
		t.KRBError = krb5err
	default:
		err = fmt.Errorf("Unmarshal av KRB5Token failed with unknown TokenId of: %d\n", t.TokenId)
		log.Errorln(err)
		return
	}

	return
}

func InitKerberosClientExt(username, domain, password string, hash, aesKey []byte, spn string, timeout time.Duration, dialer proxy.Dialer, cfg *config.Config, spnAliases map[string][]string) (c *Client, err error) {
	if cfg == nil {
		err = fmt.Errorf("Must specify a config when using InitKerberosClientExt")
		return
	}
	c = &Client{}
	settings := []func(*client.Settings){}
	settings = append(settings, client.DisablePAFXFAST(true))
	if dialer != nil {
		settings = append(settings, client.SetProxyDialer(dialer))
	}
	if timeout > 0 {
		settings = append(settings, client.SetDialTimout(timeout))
	}

	log.Debugf("Trying to find a cached ticket for user: %q, domain: %q, spn: %q\n", username, strings.ToUpper(domain), spn)
	var fallbackSPN string
	c.Client, fallbackSPN, err = getClientFromCachedTicket(cfg, username, strings.ToUpper(domain), spn, spnAliases, settings...)
	if err != nil {
		log.Errorln(err)
		// Try other methods
		c.Client = nil
	}
	if c.Client != nil && fallbackSPN != "" {
		c.spnFallbacks = map[string]string{
			strings.ToLower(spn): strings.ToLower(fallbackSPN),
		}
	}

	if c.Client == nil {
		if aesKey != nil {
			c.Client, _ = client.NewWithKey(username, strings.ToUpper(domain), aesKey, cfg, settings...)
			//c.Client = client.NewWithKey(username, strings.ToUpper(domain), aesKey, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used pass the key to create new kerberos client")
		} else if hash != nil {
			c.Client, _ = client.NewWithHash(username, strings.ToUpper(domain), hash, cfg, settings...)
			//c.Client = client.NewWithHash(username, strings.ToUpper(domain), hash, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used pass the hash to create new kerberos client")
		} else if password != "" {
			c.Client, _ = client.NewWithPassword(username, strings.ToUpper(domain), password, cfg, settings...)
			//c.Client = client.NewWithPassword(username, strings.ToUpper(domain), password, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used password to create new kerberos client")
		} else {
			return nil, fmt.Errorf("Cannot initialize a Kerberos client with an empty cache and without specifying either a password, hash or AES key")
		}
		err = c.Client.Login()
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if c.Client == nil {
		return nil, fmt.Errorf("Failed to initialize Kerberos client")
	}

	return
}

func InitKerberosClient(username, domain, password string, hash, aesKey []byte, dcip, spn string, timeout time.Duration, dialer proxy.Dialer, dnsHost string, dnsTCP bool, spnAliases map[string][]string) (c *Client, err error) {
	cfg := config.New()
	// Default to TCP for all KDC traffic. Against Active Directory the AS/TGS
	// responses carry a PAC and almost always exceed the KDC's UDP datagram
	// reply limit, so a UDP attempt just earns a KRB_ERR_RESPONSE_TOO_BIG and a
	// mandatory TCP retry. Skipping the wasted UDP round-trip also avoids the
	// confusing "response too big" failure mode. The gokrb5 client still
	// iterates across multiple DCs on a TCP transport failure, so always-TCP is
	// safe even when one DC has a filtered TCP/88.
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultRealm = strings.ToUpper(domain)
	cfg.Realms = []config.Realm{
		config.Realm{
			Realm: strings.ToUpper(domain),
		},
	}
	if dcip != "" {
		cfg.Realms[0].KDC = []string{dcip + ":88"}
	} else {
		cfg.Realms[0].KDC = []string{domain + ":88"}
	}
	if dialer != nil {
		// KDC traffic already defaults to TCP above; a socks proxy just needs
		// the DNS resolver pointed through it over TCP.
		if dnsHost != "" {
			cfg.SetDNSResolver(dialer.(proxy.ContextDialer), dnsHost, "tcp")
		}
	} else {
		protocol := "udp"
		if dnsTCP {
			protocol = "tcp"
		}
		if dnsHost != "" {
			cfg.SetDNSResolver(&net.Dialer{Timeout: timeout}, dnsHost, protocol)
		}
	}

	return InitKerberosClientExt(username, domain, password, hash, aesKey, spn, timeout, dialer, cfg, spnAliases)
}

// Context of the Authenticator checksum is decribed in RFC1964 Section 1.1.1
func newAuthenticatorChecksum(flags []int) []byte {
	/*
	   Checksum
	   byte   field:
	   0..3   Length of Bnd field
	   4..19  Bnd (MD5 hash of channel bindings)
	   20..23 Flags
	   24..25 DlgOpt (optional)
	   26..27 Dlgth (optional)
	   28..n  Deleg (optional)
	*/
	// The checksum should be atleast 24 bytes of length + any optional fields
	a := make([]byte, 24)
	// First 4 bytes is the length of the Bnd field which is assumed to be 16 bytes
	le.PutUint32(a[:4], 16)
	// Skip channel bindings for now since it is not implemented
	for _, flag := range flags {
		if flag == gss.GssContextFlagDeleg {
			// If Delegation flag is set, we need 4 more bytes for the DlgOpt, Dlgth, and Deleg fields
			x := make([]byte, 28-len(a))
			a = append(a, x...)
			// Not completely implemented yet.
			log.Warningln("GssContextFlagDeleg is not yet implemented")
		}
		// The value of each flag should be logically OR:ed with eachother to form a 4 byte value
		le.PutUint32(a[20:24], le.Uint32(a[20:24])|uint32(flag))
	}
	return a
}

func (i *Client) GetAPReq(spn string, dceStyle bool) ([]byte, error) {
	var ticket messages.Ticket
	var authenticator types.Authenticator
	var apReq messages.APReq
	var err error
	effectiveSPN := spn
	if fallback, ok := i.spnFallbacks[strings.ToLower(spn)]; ok {
		log.Debugf("Using fallback SPN %q for requested SPN %q\n", fallback, spn)
		effectiveSPN = fallback
	}
	ticket, i.sessionKey, err = i.Client.GetServiceTicket(effectiveSPN)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	token := KRB5Token{
		Oid:     gss.KerberosSSPMechTypeOid,
		TokenId: TokenIdKrb5APReq,
	}
	authenticator, err = types.NewAuthenticator(i.Client.Credentials.Domain(), i.Client.Credentials.CName())
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	flags := []int{
		gss.GssContextFlagMutual,
		gss.GssContextFlagReplay,
		gss.GssContextFlagSequence,
		gss.GssContextFlagConf,
		gss.GssContextFlagInteg,
	}
	if dceStyle {
		flags = append(flags, gss.GssContextFlagDCEStyle)
	}
	authenticator.Cksum = types.Checksum{
		CksumType: IanaKrb5ChecksumGSSAPI,
		Checksum:  newAuthenticatorChecksum(flags),
	}

	etype, err := crypto.GetEtype(i.sessionKey.KeyType)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	subkey := make([]byte, etype.GetKeyByteSize())
	_, err = rand.Read(subkey)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	authenticator.SubKey = types.EncryptionKey{
		KeyType:  i.sessionKey.KeyType,
		KeyValue: subkey,
	}
	// Used to calculate a checksum
	i.micSubkey = authenticator.SubKey
	// Save authenticator SeqNumber for Wrap Token sequence numbering (RFC 4121)
	i.authenticatorSeqNum = authenticator.SeqNumber

	apReq, err = messages.NewAPReq(ticket, i.sessionKey, authenticator)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	types.SetFlag(&apReq.APOptions, APOptionMutualRequired)
	token.APReq = apReq
	return token.MarshalBinary()
}

// ParseRawAPRep parses a bare AP_REP (with APPLICATION 15 tag, not wrapped
// in a KRB5Token). Used for DCE-style SPNEGO where the server sends a bare
// AP_REP in the NegTokenResp's ResponseToken field.
func (client *Client) ParseRawAPRep(rawAPRep []byte) error {
	var apRep messages.APRep
	err := apRep.Unmarshal(rawAPRep)
	if err != nil {
		return fmt.Errorf("failed to unmarshal bare AP_REP: %w", err)
	}
	return client.ParseAPRep(apRep.EncPart)
}

func (client *Client) ParseAPRep(encpart types.EncryptedData) error {
	// KeyUsage is 12 according to RFC 4120 Section 7.5.1
	var data []byte
	var repPart messages.EncAPRepPart
	var err error
	data, err = crypto.DecryptEncPart(encpart, client.sessionKey, 12)
	if err != nil {
		log.Errorf("Failed to decrypt APRep encrypted part: %v\n", err)
		return err
	}

	err = repPart.Unmarshal(data)
	if err != nil {
		log.Errorln(err)
		return err
	}

	// Validate the time for the AP_REP
	if time.Since(repPart.CTime).Abs() > client.Config.LibDefaults.Clockskew {
		err = fmt.Errorf("AP_REP time out of range. Current time is: %v and AP_REP time: %v\n", time.Now(), repPart.CTime)
		log.Errorln(err)
		return err
	}

	// Store the sessionSubkey from the payload.Subkey
	// This is used to derive the signing/encryption keys
	client.sessionSubKey = repPart.Subkey
	// Save EncAPRepPart for DCERPC 3rd leg (modified AP_REP)
	client.encAPRepPart = &repPart
	return nil
}

// encAPRepPartNoSubkey is a version of EncAPRepPart for the DCERPC 3rd leg
// where the subkey must be completely absent (not just zeroed). The gokrb5
// struct has Cusec (tag 1) as the last field which produces non-standard DER,
// so we also fix the field order here.
type encAPRepPartNoSubkey struct {
	CTime          time.Time `asn1:"generalized,explicit,tag:0"`
	Cusec          int       `asn1:"explicit,tag:1"`
	// Subkey (tag 2) intentionally omitted — Impacket clears it entirely
	SequenceNumber int64 `asn1:"optional,explicit,tag:3"`
}

// BuildDCEThirdLeg constructs a modified AP_REP for the DCERPC SPNEGO 3rd leg.
// Following Impacket's approach: the subkey is cleared, timestamps are updated
// to current time, and the EncAPRepPart is re-encrypted using the ORIGINAL
// session key (not the subkey) with the subkey's cipher type and Key Usage 12.
func (client *Client) BuildDCEThirdLeg() ([]byte, error) {
	if client.encAPRepPart == nil {
		return nil, fmt.Errorf("cannot build DCERPC 3rd leg: AP_REP not yet processed")
	}

	now := time.Now().UTC()

	// Build modified EncAPRepPart with subkey completely absent and current timestamps.
	// Subkey field is excluded from the struct so it's not encoded at all.
	modifiedPart := encAPRepPartNoSubkey{
		CTime:          now,
		Cusec:          now.Nanosecond() / 1000,
		SequenceNumber: client.encAPRepPart.SequenceNumber,
	}

	// Marshal EncAPRepPart with application tag 27
	plainBytes, err := asn1.Marshal(modifiedPart)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal modified EncAPRepPart: %w", err)
	}
	plainBytes = asn1tools.AddASNAppTag(plainBytes, asnAppTag.EncAPRepPart)

	// Encrypt using the subkey's cipher type but with the ORIGINAL session key.
	// Key Usage 12 (AP_REP_ENCPART).
	encKey := types.EncryptionKey{
		KeyType:  client.sessionSubKey.KeyType,
		KeyValue: client.sessionKey.KeyValue,
	}
	encryptedData, err := crypto.GetEncryptedData(plainBytes, encKey, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt modified EncAPRepPart: %w", err)
	}

	// Build AP_REP
	apRep := messages.APRep{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: encryptedData,
	}

	// Marshal AP_REP with application tag 15
	apRepBytes, err := asn1.Marshal(apRep)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AP_REP: %w", err)
	}
	apRepBytes = asn1tools.AddASNAppTag(apRepBytes, asnAppTag.APREP)

	return apRepBytes, nil
}

func (client *Client) GetMICToken(bs []byte, seqNum uint64) ([]byte, error) {
	// RFC 4121 Section 4.2.6.1
	micToken := MICToken{
		TokenId:      0x0404,
		Filler:       []byte{0xff, 0xff, 0xff, 0xff, 0xff},
		SenderSeqNum: seqNum,
		Payload:      bs,
	}
	buf := make([]byte, MICTokenHdrLen+len(bs))
	copy(buf, bs)
	copy(buf[len(bs):], micToken.MarshalHeader())

	// Calculate the checksum using the micSubKey
	encType, err := crypto.GetEtype(client.micSubkey.KeyType)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	checksum, err := encType.GetChecksumHash(client.micSubkey.KeyValue, buf, gss.KGUsageInitiatorSign)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	micToken.Checksum = checksum

	res, err := micToken.MarshalBinary()
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	return res, err
}

func (client *Client) GetSessionSubKey() []byte {
	return client.sessionSubKey.KeyValue
}

// OutboundSeqNum returns the initial outbound sequence number for Wrap Tokens.
// This is the authenticator's SeqNumber from the AP_REQ.
func (client *Client) OutboundSeqNum() uint64 {
	return uint64(client.authenticatorSeqNum)
}

// InboundSeqNum returns the initial inbound sequence number for Wrap Tokens.
// This is the SequenceNumber from the AP_REP's EncAPRepPart.
func (client *Client) InboundSeqNum() uint64 {
	if client.encAPRepPart != nil {
		return uint64(client.encAPRepPart.SequenceNumber)
	}
	return uint64(client.authenticatorSeqNum)
}

func (client *Client) GetSessionKey() []byte {
	return client.sessionKey.KeyValue
}

// WrapDCE encrypts plaintext for DCE-RPC using the acceptor subkey.
// Returns body (PDU stub) and authValue (PDU auth_value).
func (client *Client) WrapDCE(plaintext []byte, seqNum uint64) (body, authValue []byte, err error) {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return wrapDCERC4(client.sessionSubKey.KeyValue, plaintext, uint32(seqNum), true)
	}
	return WrapDCE(client.sessionSubKey, gss.KGUsageInitiatorSeal, plaintext, seqNum)
}

// UnwrapDCE decrypts a DCE-RPC sealed PDU using the acceptor subkey.
// seqNum is the expected sequence number for replay/reorder detection.
func (client *Client) UnwrapDCE(body, authValue []byte, seqNum uint64) (plaintext []byte, err error) {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return unwrapDCERC4(client.sessionSubKey.KeyValue, body, authValue, uint32(seqNum), false)
	}
	return UnwrapDCE(client.sessionSubKey, gss.KGUsageAcceptorSeal, body, authValue, seqNum)
}

// GetMICDCE computes a MIC token (RFC 4121 Section 4.2.6.1) over data
// using the acceptor subkey (sessionSubKey). Used for DCE-RPC PktIntegrity.
func (client *Client) GetMICDCE(data []byte, seqNum uint64) ([]byte, error) {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return getMICRC4(client.sessionSubKey.KeyValue, data, uint32(seqNum), true)
	}
	micToken := MICToken{
		TokenId:      0x0404,
		Flags:        0x04, // AcceptorSubkey
		Filler:       []byte{0xff, 0xff, 0xff, 0xff, 0xff},
		SenderSeqNum: seqNum,
		Payload:      data,
	}
	buf := make([]byte, MICTokenHdrLen+len(data))
	copy(buf, data)
	copy(buf[len(data):], micToken.MarshalHeader())

	encType, err := crypto.GetEtype(client.sessionSubKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("GetMICDCE: failed to get etype: %w", err)
	}
	checksum, err := encType.GetChecksumHash(client.sessionSubKey.KeyValue, buf, gss.KGUsageInitiatorSign)
	if err != nil {
		return nil, fmt.Errorf("GetMICDCE: checksum failed: %w", err)
	}
	micToken.Checksum = checksum
	return micToken.MarshalBinary()
}

// VerifyMICDCE verifies a MIC token received from the acceptor using the
// acceptor subkey (sessionSubKey). Used for DCE-RPC PktIntegrity.
func (client *Client) VerifyMICDCE(data, token []byte, expectedSeqNum uint64) error {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return verifyMICRC4(client.sessionSubKey.KeyValue, data, token, uint32(expectedSeqNum), false)
	}
	if len(token) < MICTokenHdrLen {
		return fmt.Errorf("VerifyMICDCE: token too short: %d bytes", len(token))
	}

	gotSeqNum := be.Uint64(token[8:16])
	if gotSeqNum != expectedSeqNum {
		return fmt.Errorf("VerifyMICDCE: sequence number mismatch: got %d, want %d", gotSeqNum, expectedSeqNum)
	}

	receivedChecksum := token[MICTokenHdrLen:]

	// Rebuild the MIC header with received fields
	micToken := MICToken{
		TokenId:      0x0404,
		Flags:        token[2],
		Filler:       token[3:8],
		SenderSeqNum: gotSeqNum,
		Payload:      data,
	}
	buf := make([]byte, MICTokenHdrLen+len(data))
	copy(buf, data)
	copy(buf[len(data):], micToken.MarshalHeader())

	encType, err := crypto.GetEtype(client.sessionSubKey.KeyType)
	if err != nil {
		return fmt.Errorf("VerifyMICDCE: failed to get etype: %w", err)
	}
	// Acceptor sends with AcceptorSign usage
	expectedChecksum, err := encType.GetChecksumHash(client.sessionSubKey.KeyValue, buf, gss.KGUsageAcceptorSign)
	if err != nil {
		return fmt.Errorf("VerifyMICDCE: checksum failed: %w", err)
	}

	if !bytes.Equal(receivedChecksum, expectedChecksum) {
		return fmt.Errorf("VerifyMICDCE: checksum mismatch")
	}
	return nil
}

// MICTokenSize returns the MIC token size for the current session key type.
func (client *Client) MICTokenSize() int {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return micTokenRC4Size()
	}
	encType, err := crypto.GetEtype(client.sessionSubKey.KeyType)
	if err != nil {
		log.Errorf("MICTokenSize failed: %v\n", err)
		return 0
	}
	return MICTokenHdrLen + encType.GetHMACBitLength()/8
}

// WrapTokenOverhead returns the signature size and encryption overhead
// for the current session key type.
func (client *Client) WrapTokenOverhead() (signatureSize, encryptionOverhead int) {
	if client.sessionSubKey.KeyType == etypeID.RC4_HMAC {
		return wrapTokenRC4Overhead()
	}
	sigSize, overhead, err := WrapTokenOverhead(client.sessionSubKey.KeyType)
	if err != nil {
		log.Errorf("WrapTokenOverhead failed: %v\n", err)
		return 0, 0
	}
	return sigSize, overhead
}
