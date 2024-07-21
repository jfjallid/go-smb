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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/gokrb5/v8/client"
	"github.com/jfjallid/gokrb5/v8/config"
	"github.com/jfjallid/gokrb5/v8/crypto"
	"github.com/jfjallid/gokrb5/v8/messages"
	"github.com/jfjallid/gokrb5/v8/types"
	"github.com/jfjallid/golog"
)

var le = binary.LittleEndian
var log = golog.Get("github.com/jfjallid/go-smb/krb5ssp")

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
	sessionKey    types.EncryptionKey
	sessionSubKey types.EncryptionKey
	micSubkey     types.EncryptionKey
}

func NewClient(client *client.Client) *Client {
	return &Client{Client: client}
}

func (self *KRB5Token) MarshalBinary() (res []byte, err error) {
	log.Debugln("In MarshalBinary for KRB5Token")
	res, err = asn1.Marshal(self.Oid)
	if err != nil {
		log.Errorln(err)
		return
	}

	res = le.AppendUint16(res, self.TokenId)

	switch self.TokenId {
	case TokenIdKrb5APReq:
		buf, err := self.APReq.Marshal()
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

func (self *KRB5Token) UnmarshalBinary(buf []byte) (err error) {
	log.Debugln("In UnmarshalBinary for KRB5Token")

	rest, err := asn1.UnmarshalWithParams(buf, &self.Oid, "application,explicit,tag:0")
	if err != nil {
		log.Errorf("Failed to unmarshal KRB5Token OID: %v\n", err)
		return
	}

	if !self.Oid.Equal(gss.KerberosSSPMechTypeOid) {
		err = fmt.Errorf("KRB5Token OID is %s and not %s as expected", self.Oid.String(), gss.KerberosSSPMechTypeOid.String())
		log.Errorln(err)
		return
	}
	if len(rest) < 2 {
		err = fmt.Errorf("Buffer is too short for KRB5Token")
		log.Errorln(err)
		return
	}

	self.TokenId = le.Uint16(rest[0:2])
	switch self.TokenId {
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
		self.APRep = rep
	case TokenIdKrb5Error:
		krb5err := messages.KRBError{}
		err = krb5err.Unmarshal(rest[2:])
		if err != nil {
			log.Errorln(err)
			return
		}
		self.KRBError = krb5err
	default:
		err = fmt.Errorf("Unmarshal av KRB5Token failed with unknown TokenId of: %d\n", self.TokenId)
		log.Errorln(err)
		return
	}

	return
}

func InitKerberosClient(username, domain, password string, hash, aesKey []byte, dcip, spn string) (c *Client, err error) {
	c = &Client{}
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultRealm = strings.ToUpper(domain)
	if dcip != "" {
		cfg.Realms = []config.Realm{
			config.Realm{
				Realm: strings.ToUpper(domain),
				KDC:   []string{dcip + ":88"},
			},
		}
	}

	c.Client, err = getClientFromCachedTicket(cfg, username, domain, spn)
	if err != nil {
		log.Errorln(err)
		// Try other methods
		c.Client = nil
	}

	if c.Client == nil {
		if aesKey != nil {
			c.Client = client.NewWithKey(username, strings.ToUpper(domain), aesKey, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used pass the key to create new kerberos client")
		} else if hash != nil {
			c.Client = client.NewWithHash(username, strings.ToUpper(domain), hash, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used pass the hash to create new kerberos client")
		} else if password != "" {
			c.Client = client.NewWithPassword(username, strings.ToUpper(domain), password, cfg, client.DisablePAFXFAST(true))
			log.Infoln("Used password to create new kerberos client")
		} else {
			return nil, fmt.Errorf("Cannot initialize a Kerberos client with an empty cache and without specifying either a password, hash or AES key")
		}
	}

	if c.Client == nil {
		return nil, fmt.Errorf("Failed to initialize Kerberos client")
	}

	// Check for TGS
	if _, _, found := c.Client.GetCachedTicket(spn); !found {
		// We haven't found a TGS for the target but perhaps a TGT?
		parts := strings.Split(spn, "/")
		if len(parts) == 2 {
			target := parts[1]
			if _, _, found := c.Client.GetCachedTicket(fmt.Sprintf("krbtgt/%s", target)); found {
				// Found TGT so won't do anything more here
				return
			}
		}
		// No TGS and no TGT, better login
		err = c.Client.Login()
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return
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

func (i *Client) GetAPReq(spn string) ([]byte, error) {
	var ticket messages.Ticket
	var authenticator types.Authenticator
	var apReq messages.APReq
	var err error
	ticket, i.sessionKey, err = i.Client.GetServiceTicket(spn)
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
	flags := []int{gss.GssContextFlagInteg, gss.GssContextFlagConf}
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

	apReq, err = messages.NewAPReq(ticket, i.sessionKey, authenticator)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	types.SetFlag(&apReq.APOptions, APOptionMutualRequired)
	token.APReq = apReq
	return token.MarshalBinary()
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
	return nil
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

func (client *Client) GetSessionKey() []byte {
	return client.sessionKey.KeyValue
}
