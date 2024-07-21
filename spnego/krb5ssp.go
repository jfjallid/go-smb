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

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/krb5ssp"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/spnego")
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
	User     string
	Password string
	Hash     []byte
	AESKey   []byte
	Domain   string
	DCIP     string

	client *krb5ssp.Client
	seqNum uint32
	SPN    string
}

func (i *KRB5Initiator) SetClient(c *krb5ssp.Client) error {
	i.client = c
	return nil
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

	i.client, err = krb5ssp.InitKerberosClient(i.User, i.Domain, i.Password, i.Hash, i.AESKey, i.DCIP, i.SPN)
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
		return i.client.GetAPReq(i.SPN)
	} else {
		var token krb5ssp.KRB5Token
		err = token.UnmarshalBinary(inputToken)
		if err != nil {
			log.Errorln(err)
			return
		}
		if token.TokenId != krb5ssp.TokenIdKrb5APRep {
			err = fmt.Errorf("Invalid KRB5Token in InitSecContext. Expected an APRep but got tokenId: %d\n", token.TokenId)
			log.Errorln(err)
			return
		}

		i.client.ParseAPRep(token.APRep.EncPart)
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

	res, err := i.client.GetMICToken(bs, uint64(i.seqNum))
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
