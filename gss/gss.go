package gss

import (
	"encoding/asn1"

	"github.com/jfjallid/go-smb/smb/encoder"
	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/gss")
var SpnegoOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 5, 5, 2})
var MsKerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 48018, 1, 2, 2})
var KerberosOid = asn1.ObjectIdentifier([]int{1, 2, 840, 113554, 1, 2, 2})
var NtLmSSPMechTypeOid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 311, 2, 2, 10})

const GssStateAcceptCompleted = 0
const GssStateAcceptIncomplete = 1
const GssStateReject = 2
const GssStateRequestMic = 3

type NegTokenInitData struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     asn1.BitString          `asn1:"explicit,optional,omitempty,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,omitempty,tag:2"`
	MechTokenMIC []byte                  `asn1:"explicit,optional,omitempty,tag:3"`
}

type NegTokenInit struct {
	OID  asn1.ObjectIdentifier
	Data NegTokenInitData `asn1:"explicit"`
}

type NegTokenResp struct {
	State         asn1.Enumerated       `asn1:"explicit,optional,omitempty,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,omitempty,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,omitempty,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,omitempty,tag:3"`
}

// gsswrapped used to force ASN1 encoding to include explicit sequence tags
// Type does not fulfill the BinaryMarshallable interfce and is used only as a
// helper to marshal a NegTokenResp
type gsswrapped struct{ G interface{} }

func NewNegTokenInit(types []asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	req := NegTokenInit{
		OID: SpnegoOid,
		Data: NegTokenInitData{
			MechTypes:    []asn1.ObjectIdentifier{NtLmSSPMechTypeOid},
			ReqFlags:     asn1.BitString{},
			MechToken:    token,
			MechTokenMIC: []byte{},
		},
	}
	//NOTE Failes to marshal the NegTokenInit

	return encoder.Marshal(&req)
}

func NewNegTokenResp() (NegTokenResp, error) {
	return NegTokenResp{}, nil
}

func (n *NegTokenInit) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*n)
	if err != nil {
		log.Criticalln(err)
		return nil, err
	}

	// When marshalling struct, asn1 uses 30 (sequence) tag by default.
	// Override to set 60 (application) to remain consistent with GSS/SMB
	buf[0] = 0x60
	return buf, nil
}

func (n *NegTokenInit) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	data := NegTokenInit{}
	if _, err := asn1.UnmarshalWithParams(buf, &data, "application"); err != nil {
		log.Debugln(err)
		return err
	}
	*n = data
	return nil
}

func (r *NegTokenResp) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	// Oddities in Go's ASN1 package vs SMB encoding mean we have to wrap our
	// struct in another struct to ensure proper tags and lengths are added
	// to encoded data
	wrapped := &gsswrapped{*r}
	return wrapped.MarshalBinary(meta)
}

func (r *NegTokenResp) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	data := NegTokenResp{}
	if _, err := asn1.UnmarshalWithParams(buf, &data, "explicit,tag:1"); err != nil {
		log.Criticalln(err)
		return err
	}
	*r = data
	return nil
}

func (g *gsswrapped) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	buf, err := asn1.Marshal(*g)
	if err != nil {
		return nil, err
	}
	buf[0] = 0xa1
	return buf, nil
}
