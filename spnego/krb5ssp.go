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
package spnego

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/gofork/encoding/asn1"
	"golang.org/x/net/proxy"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/krb5ssp"
	"github.com/jfjallid/gokrb5/v9/keytab"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/spnego").SetDisplayName("spnego")
var le = binary.LittleEndian

// RFC4120 Section 5.3 Tickets, flags:
const (
	Reserved = iota
	Forwardable
	Forwarded
	Proxiable
	Proxy
	MayPostDate
	PostDated
	Invalid
	Renewable
	Initial
	PreAuthent
	HWAuthent
	TransitedPolicyChecked
	OKAsDelegate
)

type KRB5Initiator struct {
	User        string
	Password    string
	Hash        []byte
	AESKey      []byte
	Domain      string
	DCIP        string
	DialTimeout time.Duration
	ProxyDialer proxy.Dialer
	DnsHost     string
	DnsTCP      bool
	Host        string
	SPN         string
	// Keytab, when set, authenticates from the keys it holds instead of a
	// password/hash/AES key. A missing User/Domain is left for gokrb5 to derive
	// from the keytab's first entry and is written back from the resolved
	// credentials after login (like the ccache path).
	Keytab *keytab.Keytab
	// SPNAliases lets the caller specify acceptable fallback service types
	// when the requested SPN is not found in the ccache. Keys are requested
	// service types (e.g. "ldap"); values are ordered alternatives (e.g.
	// {"host"}). nil means use krb5ssp.defaultSPNAliases; an empty (non-nil)
	// map disables all fallbacks.
	SPNAliases map[string][]string

	client       *krb5ssp.Client
	dceStyle     bool
	micSeqNum    uint32
	sealSeqNum   uint64
	unsealSeqNum uint64
}

// SetSPN overrides the SPN used for Kerberos ticket requests.
// This is needed for DCOM where the dynamic port server process may run
// under a different identity than the machine account.
func (i *KRB5Initiator) SetSPN(spn string) {
	i.SPN = spn
}

// EnableDCEStyle enables the GSS_C_DCE_STYLE flag in the AP_REQ authenticator
// checksum. This causes Windows to return a bare AP_REP (not KRB5Token-wrapped)
// in the NegTokenResp, which is required for DCERPC TCP but must NOT be set for
// SMB transport (which uses the standard KRB5Token-wrapped AP_REP).
func (i *KRB5Initiator) EnableDCEStyle() {
	i.dceStyle = true
}

func (i *KRB5Initiator) SetClient(c *krb5ssp.Client) error {
	i.client = c
	return nil
}

// Client returns the underlying krb5ssp.Client, lazily initializing it from
// the initiator's fields (User/Password/Hash/AESKey/Domain/DCIP/etc.) if
// needed. This lets consumers that need to drive the Kerberos context through
// a different interface (e.g. the LDAP GSSAPI SASL bind in go-smb/ldap)
// share credentials and the TGS ticket cache with the DCERPC SPNEGO path
// without duplicating the Initiator fields.
//
// The returned client is owned by the initiator; do not Destroy it directly.
func (i *KRB5Initiator) Client() (*krb5ssp.Client, error) {
	if i.client == nil {
		if err := i.initKerberosClient(); err != nil {
			return nil, err
		}
	}
	return i.client, nil
}

func (i *KRB5Initiator) Logoff() {
	i.client.Destroy()
	i.client = nil
	return
}

func (i *KRB5Initiator) initKerberosClient() error {
	var err error
	if i.SPN != "" {
		parts := strings.Split(i.SPN, "/")
		if len(parts) < 2 {
			err = fmt.Errorf("Invalid SPN, expected <service>/<host>")
			log.Errorln(err)
			return err
		}
		// Validate that SPN does not contain an IP address
		ip := net.ParseIP(parts[1])
		if ip != nil {
			err = fmt.Errorf("Invalid SPN, expected a hostname and not an IP address")
			log.Errorln(err)
			return err
		}
	}
	if i.DCIP != "" {
		ip := net.ParseIP(i.DCIP)
		if ip == nil {
			err = fmt.Errorf("Invalid DC IP, expected an IP address to the domain controller")
			log.Errorln(err)
			return err
		}
	}
	if i.DialTimeout.Seconds() < 0 {
		err = fmt.Errorf("A DialTimeout cannot be a negative duration")
		log.Errorln(err)
		return err
	}
	// With a keytab the realm is self-describing: gokrb5 derives it (and the
	// principal) from the keytab during client creation, and both are written
	// back from the resolved credentials after login (see InitSecContext, same
	// as the ccache path). So skip the host-FQDN domain guess that only the
	// password/hash/key path needs.
	if i.Domain == "" && i.Keytab == nil {
		parts := strings.SplitN(i.Host, ".", 2)
		if len(parts) < 2 {
			err = fmt.Errorf("Must specify a host FQDN to initialize a Kerberos client")
			log.Errorln(err)
			return err
		}
		i.Domain = parts[1]
	}
	if i.DnsHost != "" {
		if !strings.Contains(i.DnsHost, ":") {
			log.Infoln("Kerberos Initiator DnsHost does not contain a port number, assuming port 53")
			i.DnsHost += ":53"
		}
	}
	if i.Keytab != nil {
		i.client, err = krb5ssp.InitKerberosClientWithKeytab(i.User, i.Domain, i.Keytab, i.DCIP, i.SPN, i.DialTimeout, i.ProxyDialer, i.DnsHost, i.DnsTCP, i.SPNAliases)
		return err
	}
	i.client, err = krb5ssp.InitKerberosClient(i.User, i.Domain, i.Password, i.Hash, i.AESKey, i.DCIP, i.SPN, i.DialTimeout, i.ProxyDialer, i.DnsHost, i.DnsTCP, i.SPNAliases)
	return err
}

func (i *KRB5Initiator) Oid() asn1.ObjectIdentifier {
	return gss.KerberosSSPMechTypeOid
}

func (i *KRB5Initiator) InitSecContext(inputToken []byte) (res []byte, err error) {
	/*
	   According to RFC 2743 Section 1 paragraph 4, the client calls initSecContext which returns a token
	   that is sent to the server. The server inputs the token to acceptSecContext as the input_token (argument),
	   which returns an output token returned to the client. Finally, the client calls initSecContext with the server's
	   response as input_token argument and then it is completed. At least this flow seems accurate for mutual authentication flows.
	*/

	if inputToken == nil {
		if i.client == nil {
			err = i.initKerberosClient()
			if err != nil {
				log.Errorln(err)
				return
			}
			if i.Domain == "" {
				i.Domain = i.client.Credentials.Domain()
				i.client.Config.LibDefaults.DefaultRealm = strings.ToUpper(i.Domain)
				if len(i.client.Config.Realms) > 0 {
					i.client.Config.Realms[0].Realm = strings.ToUpper(i.Domain)
				}
				log.Infof("Using Kerberos realm from ticket as domain: %s\n", i.Domain)
			}
			if i.User == "" {
				i.User = i.client.Credentials.UserName()
				log.Infof("Using username found in ticket: %s\n", i.User)
			}
		}
		return i.client.GetAPReq(i.SPN, i.dceStyle)
	} else {
		var token krb5ssp.KRB5Token
		err = token.UnmarshalBinary(inputToken)
		if err != nil {
			log.Errorln(err)
			return
		}
		switch token.TokenId {
		case krb5ssp.TokenIdKrb5APRep:
			err = i.client.ParseAPRep(token.APRep.EncPart)
			if err != nil {
				log.Errorf("Failed to parse AP_REP: %v\n", err)
				return
			}
			// Initialize Wrap Token sequence numbers from the Kerberos context
			i.sealSeqNum = i.client.OutboundSeqNum()
			i.unsealSeqNum = i.client.InboundSeqNum()
		case krb5ssp.TokenIdKrb5Error:
			if token.KRBError.ErrorCode == 41 {
				if i.SPN != "" {
					parts := strings.Split(i.SPN, "/")
					if len(parts) == 2 {
						targetName := strings.TrimSuffix(token.KRBError.SName.PrincipalNameString(), "$")
						if !strings.EqualFold(targetName, parts[1]) {
							err = fmt.Errorf("Server could not decrypt provided TGS. TGS was issued for %s and sent to %s\n", parts[1], targetName)
							log.Errorln(err)
							return
						}
					}
				}
				err = fmt.Errorf("Server could not decrypt provided TGS")
			} else {
				err = fmt.Errorf("Server returned Kerberos Error: %v\n", token.KRBError.Error())
			}
			log.Errorln(err)
		default:
			err = fmt.Errorf("Invalid KRB5Token in InitSecContext. Expected an APRep but got tokenId: %d\n", token.TokenId)
			log.Errorln(err)
		}

		// No return token is expected here
		return
	}
}

func (i *KRB5Initiator) AcceptSecContext(sc []byte) (res []byte, err error) {
	return nil, fmt.Errorf("AcceptSecContext NOT YET IMPLEMENTED!")
}

func (i *KRB5Initiator) Sum(bs []byte) []byte {
	if len(bs) == 0 {
		log.Errorln("Cannot compute a MIC Checksum with a zero length payload!")
		return nil
	}

	res, err := i.client.GetMICToken(bs, uint64(i.micSeqNum))
	if err != nil {
		log.Errorln(err)
		return nil
	}
	return res
}

func (i *KRB5Initiator) SessionKey() []byte {
	// Might be i.client.sessionKey.KeyValue if mutual auth is not performed
	return i.client.GetSessionSubKey()
}

func (i *KRB5Initiator) IsNullSession() bool {
	// Does Kerberos support null sessions?
	return false
}

func (i *KRB5Initiator) GetUsername() string {
	return i.client.Credentials.Domain() + "\\" + i.client.Credentials.UserName()
}

// DCEProcessAPRep processes a bare AP_REP (not KRB5Token-wrapped) from a
// DCE-style SPNEGO NegTokenResp. Implements the dcerpc.DCEAPRepProcessor interface.
func (i *KRB5Initiator) DCEProcessAPRep(rawAPRep []byte) error {
	err := i.client.ParseRawAPRep(rawAPRep)
	if err != nil {
		return err
	}
	// Initialize Wrap Token sequence numbers from the Kerberos context.
	// RFC 4121: SND_SEQ must match the sequence number established during
	// context setup. The outbound seq is the authenticator's SeqNumber,
	// the inbound seq is the AP_REP's SequenceNumber.
	i.sealSeqNum = i.client.OutboundSeqNum()
	i.unsealSeqNum = i.client.InboundSeqNum()
	return nil
}

// Seal encrypts toEncrypt for DCE-RPC using Kerberos Wrap Token.
// toSign is ignored (Kerberos integrity is built into the encryption).
// Implements the dcerpc.Sealer interface.
func (i *KRB5Initiator) Seal(toEncrypt, toSign []byte) (ciphertext, signature []byte, err error) {
	body, authValue, err := i.client.WrapDCE(toEncrypt, i.sealSeqNum)
	if err != nil {
		return nil, nil, fmt.Errorf("KRB5Initiator.Seal: %w", err)
	}
	i.sealSeqNum++
	return body, authValue, nil
}

// Unseal decrypts ciphertext and verifies integrity using Kerberos Wrap Token.
// pduHeader and secTrailer are ignored (Kerberos verifies integrity internally).
// Implements the dcerpc.Sealer interface.
func (i *KRB5Initiator) Unseal(ciphertext, signature, pduHeader, secTrailer []byte) ([]byte, error) {
	plaintext, err := i.client.UnwrapDCE(ciphertext, signature, i.unsealSeqNum)
	if err != nil {
		return nil, err
	}
	i.unsealSeqNum++
	return plaintext, nil
}

// Sign computes a MIC token over data without encrypting.
// Implements the dcerpc.Sealer interface for PktIntegrity.
func (i *KRB5Initiator) Sign(data, toSign []byte) ([]byte, error) {
	token, err := i.client.GetMICDCE(data, i.sealSeqNum)
	if err != nil {
		return nil, fmt.Errorf("KRB5Initiator.Sign: %w", err)
	}
	i.sealSeqNum++
	return token, nil
}

// VerifySign verifies a MIC token without decrypting.
// Implements the dcerpc.Sealer interface for PktIntegrity.
func (i *KRB5Initiator) VerifySign(data, signature, pduHeader, secTrailer []byte) error {
	err := i.client.VerifyMICDCE(data, signature, i.unsealSeqNum)
	if err != nil {
		return err
	}
	i.unsealSeqNum++
	return nil
}

// SignatureSize returns the auth_value size for Kerberos Wrap Token.
// Implements the dcerpc.Sealer interface.
func (i *KRB5Initiator) SignatureSize() int {
	sigSize, _ := i.client.WrapTokenOverhead()
	return sigSize
}

// MICSignatureSize returns the MIC token size for PktIntegrity.
// Implements the dcerpc.Sealer interface.
func (i *KRB5Initiator) MICSignatureSize() int {
	return i.client.MICTokenSize()
}

// EncryptionOverhead returns extra ciphertext bytes beyond plaintext size.
// Implements the dcerpc.Sealer interface.
func (i *KRB5Initiator) EncryptionOverhead() int {
	_, overhead := i.client.WrapTokenOverhead()
	return overhead
}

// DCEThirdLeg generates the modified AP_REP token for the DCERPC SPNEGO
// 3rd leg (AlterContext). Implements the dcerpc.DCEThirdLegProvider interface.
func (i *KRB5Initiator) DCEThirdLeg() ([]byte, error) {
	return i.client.BuildDCEThirdLeg()
}
