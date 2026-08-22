// MIT License
//
// # Copyright (c) 2026 Jimmy Fjällid
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

package msicpr

// MS-CSRA (Certificate Services Remote Administration Protocol): the
// ICertAdminD / ICertAdminD2 DCOM interfaces a CA exposes for administration.
// Only the subset needed to act on a CA is implemented here: approve/deny a
// pending request, read/write the CA's enabled-template list, and read/write
// the CA security descriptor (the CA roles ManageCA / ManageCertificates).
//
// The stubs reuse this package's CERTTRANSBLOB and the same per-parameter NDR
// layout as the enrollment calls: every pointer parameter carries `toplevel` so
// its referents are emitted inside its own deferral scope, which is what
// Windows' MIDL-generated server stubs expect (see structures.go).

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"unicode/utf16"

	"github.com/jfjallid/go-smb/dcerpc/msdcom"
	"github.com/jfjallid/ndr"
)

// Opnums on ICertAdminD (MS-CSRA 3.1.4.1) and its ICertAdminD2 extension
// (MS-CSRA 3.1.4.2). Opnums 0-2 are IUnknown, so ICertAdminD's first method
// (SetExtension) is opnum 3.
const (
	ICertAdminDResubmitRequestOp uint16 = 5  // ICertAdminD::ResubmitRequest
	ICertAdminDDenyRequestOp     uint16 = 6  // ICertAdminD::DenyRequest
	ICertAdminD2GetCAPropertyOp  uint16 = 32 // ICertAdminD2::GetCAProperty
	ICertAdminD2SetCAPropertyOp  uint16 = 33 // ICertAdminD2::SetCAProperty
	ICertAdminD2GetCASecurityOp  uint16 = 36 // ICertAdminD2::GetCASecurity
	ICertAdminD2SetCASecurityOp  uint16 = 37 // ICertAdminD2::SetCASecurity
)

// COM class / interface identifiers for the CA administration interfaces.
// Both interfaces are activated from the same CertAdmin class; ICertAdminD2
// derives from ICertAdminD and adds the property/security methods.
var (
	CLSIDICertAdminD = mustGUID("d99e6e73-fc88-11d0-b498-00a0c90312f3")
	IIDICertAdminD   = mustGUID("d99e6e71-fc88-11d0-b498-00a0c90312f3")
	IIDICertAdminD2  = mustGUID("7fe0d935-dda6-443f-85d0-1cfb58fe41dd")
)

// CA property identifiers and types (MS-WCCE 3.2.1.4.3.2, CR_PROP_* /
// PROPTYPE_*). Only the enabled-template list is needed here.
const (
	// CRPropTemplates is the newline-separated list of templates enabled on
	// the CA, as alternating name and OID entries.
	CRPropTemplates uint32 = 0x0000001D
	// PropTypeString marks a property whose value is a UTF-16LE string.
	PropTypeString uint32 = 4
)

// ResubmitRequestReq is the [in] parameter block for
// ICertAdminD::ResubmitRequest (opnum 5), MS-CSRA 3.1.4.1.3:
//
//	HRESULT ResubmitRequest(
//	    [in, string, unique] wchar_t const *pwszAuthority,
//	    [in] DWORD dwRequestId,
//	    [out] DWORD *pdwDisposition);
type ResubmitRequestReq struct {
	PwszAuthority string `ndr:"toplevel,fullpointer,conformant,varying"`
	DwRequestId   uint32
}

// ResubmitRequestRes is the [out] parameter block: the new disposition of the
// request followed by the method HRESULT.
type ResubmitRequestRes struct {
	PdwDisposition uint32 `ndr:"toplevel"`
	ReturnValue    uint32
}

// DenyRequestReq is the [in] parameter block for ICertAdminD::DenyRequest
// (opnum 6), MS-CSRA 3.1.4.1.4:
//
//	HRESULT DenyRequest(
//	    [in, string, unique] wchar_t const *pwszAuthority,
//	    [in] DWORD dwRequestId);
type DenyRequestReq struct {
	PwszAuthority string `ndr:"toplevel,fullpointer,conformant,varying"`
	DwRequestId   uint32
}

// DenyRequestRes carries only the method HRESULT.
type DenyRequestRes struct {
	ReturnValue uint32
}

// GetCAPropertyReq is the [in] parameter block for ICertAdminD2::GetCAProperty
// (opnum 32), MS-CSRA 3.1.4.2.2:
//
//	HRESULT GetCAProperty(
//	    [in, string, unique] wchar_t const *pwszAuthority,
//	    [in] LONG PropId, [in] LONG PropIndex, [in] LONG PropType,
//	    [out, ref] CERTTRANSBLOB *pctbPropertyValue);
type GetCAPropertyReq struct {
	PwszAuthority string `ndr:"toplevel,fullpointer,conformant,varying"`
	PropId        uint32
	PropIndex     uint32
	PropType      uint32
}

// GetCAPropertyRes is the [out] parameter block.
type GetCAPropertyRes struct {
	PctbPropertyValue CERTTRANSBLOB `ndr:"toplevel"`
	ReturnValue       uint32
}

// SetCAPropertyReq is the [in] parameter block for ICertAdminD2::SetCAProperty
// (opnum 33), MS-CSRA 3.1.4.2.3.
type SetCAPropertyReq struct {
	PwszAuthority     string `ndr:"toplevel,fullpointer,conformant,varying"`
	PropId            uint32
	PropIndex         uint32
	PropType          uint32
	PctbPropertyValue CERTTRANSBLOB `ndr:"toplevel"`
}

// SetCAPropertyRes carries only the method HRESULT.
type SetCAPropertyRes struct {
	ReturnValue uint32
}

// GetCASecurityReq is the [in] parameter block for ICertAdminD2::GetCASecurity
// (opnum 36), MS-CSRA 3.1.4.2.6.
type GetCASecurityReq struct {
	PwszAuthority string `ndr:"toplevel,fullpointer,conformant,varying"`
}

// GetCASecurityRes returns the CA's self-relative SECURITY_DESCRIPTOR.
type GetCASecurityRes struct {
	PctbSD      CERTTRANSBLOB `ndr:"toplevel"`
	ReturnValue uint32
}

// SetCASecurityReq is the [in] parameter block for ICertAdminD2::SetCASecurity
// (opnum 37), MS-CSRA 3.1.4.2.7.
type SetCASecurityReq struct {
	PwszAuthority string        `ndr:"toplevel,fullpointer,conformant,varying"`
	PctbSD        CERTTRANSBLOB `ndr:"toplevel"`
}

// SetCASecurityRes carries only the method HRESULT.
type SetCASecurityRes struct {
	ReturnValue uint32
}

func encodeStub(v any) ([]byte, error) {
	return ndr.NewEncoder(bytes.NewBuffer([]byte{}), false).Encode(v)
}

func decodeStub(b []byte, v any) error {
	return ndr.NewDecoder(bytes.NewReader(b), false).Decode(v)
}

// ICertAdmin drives a CA's administration interfaces over DCOM. The two
// interfaces have separate IPIDs — opnums 3-30 are dispatched on ICertAdminD
// and 31+ on its ICertAdminD2 extension — so each is activated separately, but
// only on first use: activating both up front makes a Kerberos-authenticated
// session fail its second RemoteCreateInstance with RPC_S_SEC_PKG_ERROR
// (0x721), and no single operation needs more than one of them.
//
// The activation cache is guarded by mu, so concurrent callers activate each
// interface exactly once. Note that this serialises only the cache, not the
// calls: the underlying msdcom.COMObject and its connection carry their own
// (or no) synchronisation, so treat one ICertAdmin as a single logical session.
type ICertAdmin struct {
	activate func(iid [16]byte) (comCaller, error)

	mu      sync.Mutex
	objects map[[16]byte]comCaller
}

// NewICertAdmin builds a client that obtains its interface pointers through
// activate, which is normally a closure over
// msdcom.DCOMConnection.CreateInstance bound to CLSIDICertAdminD. Objects are
// cached, so repeated calls on the same interface activate it once.
func NewICertAdmin(activate func(iid [16]byte) (*msdcom.COMObject, error)) *ICertAdmin {
	return newICertAdmin(func(iid [16]byte) (comCaller, error) {
		obj, err := activate(iid)
		if err != nil {
			return nil, err
		}
		if obj == nil {
			// Guard the typed-nil trap: a bare `return obj, nil` would give
			// the cache a non-nil interface wrapping a nil *COMObject, and the
			// first CallMethod would panic instead of erroring.
			return nil, fmt.Errorf("msicpr: activation of interface %x returned no object", iid)
		}
		return obj, nil
	})
}

// newICertAdmin is the constructor the package itself (and its tests) use, free
// of the concrete msdcom type.
func newICertAdmin(activate func(iid [16]byte) (comCaller, error)) *ICertAdmin {
	return &ICertAdmin{activate: activate, objects: map[[16]byte]comCaller{}}
}

// object returns the interface pointer for iid, activating it on first use.
func (c *ICertAdmin) object(iid [16]byte) (comCaller, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if obj, ok := c.objects[iid]; ok {
		return obj, nil
	}
	if c.activate == nil {
		return nil, fmt.Errorf("msicpr: no activation function for interface %x", iid)
	}
	obj, err := c.activate(iid)
	if err != nil {
		return nil, err
	}
	c.objects[iid] = obj
	return obj, nil
}

// Close releases every interface activated so far, returning the joined errors
// of any releases that failed. Every interface is released regardless: a failure
// on one does not leave the rest held. It is safe to call more than once; a
// released ICertAdmin activates afresh on its next call.
func (c *ICertAdmin) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for iid, obj := range c.objects {
		if err := obj.Release(); err != nil {
			errs = append(errs, fmt.Errorf("releasing interface %x: %w", iid, err))
		}
		delete(c.objects, iid)
	}
	return errors.Join(errs...)
}

func (c *ICertAdmin) call(iid [16]byte, name string, opnum uint16, req any, res any) error {
	obj, err := c.object(iid)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	inBuf, err := encodeStub(req)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	outBuf, err := obj.CallMethod(opnum, inBuf)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := decodeStub(outBuf, res); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	return nil
}

// ResubmitRequest approves a pending (or failed) certificate request, causing
// the CA to re-evaluate and normally issue it. This is the action a principal
// holding the ManageCertificates ("certificate officer") CA role can take — the
// exploitation half of ESC7. It returns the request's new disposition; the
// caller should check Issued/DispositionName.
func (c *ICertAdmin) ResubmitRequest(authority string, requestID uint32) (uint32, error) {
	log.Traceln("In ICertAdminD.ResubmitRequest")

	req := ResubmitRequestReq{PwszAuthority: authority, DwRequestId: requestID}
	res := ResubmitRequestRes{}
	if err := c.call(IIDICertAdminD, "ICertAdminD::ResubmitRequest", ICertAdminDResubmitRequestOp, &req, &res); err != nil {
		return 0, err
	}
	if err := checkReturnCode("ICertAdminD::ResubmitRequest", res.ReturnValue); err != nil {
		return res.PdwDisposition, err
	}
	return res.PdwDisposition, nil
}

// DenyRequest rejects a pending certificate request.
func (c *ICertAdmin) DenyRequest(authority string, requestID uint32) error {
	log.Traceln("In ICertAdminD.DenyRequest")

	req := DenyRequestReq{PwszAuthority: authority, DwRequestId: requestID}
	res := DenyRequestRes{}
	if err := c.call(IIDICertAdminD, "ICertAdminD::DenyRequest", ICertAdminDDenyRequestOp, &req, &res); err != nil {
		return err
	}
	if err := checkReturnCode("ICertAdminD::DenyRequest", res.ReturnValue); err != nil {
		return err
	}
	return nil
}

// GetCAProperty reads a CA property as its raw CERTTRANSBLOB payload.
func (c *ICertAdmin) GetCAProperty(authority string, propID, propIndex, propType uint32) ([]byte, error) {
	log.Traceln("In ICertAdminD2.GetCAProperty")

	req := GetCAPropertyReq{
		PwszAuthority: authority,
		PropId:        propID,
		PropIndex:     propIndex,
		PropType:      propType,
	}
	res := GetCAPropertyRes{}
	if err := c.call(IIDICertAdminD2, "ICertAdminD2::GetCAProperty", ICertAdminD2GetCAPropertyOp, &req, &res); err != nil {
		return nil, err
	}
	if err := checkReturnCode("ICertAdminD2::GetCAProperty", res.ReturnValue); err != nil {
		return nil, err
	}
	return res.PctbPropertyValue.Pb, nil
}

// SetCAProperty writes a CA property from a raw payload.
func (c *ICertAdmin) SetCAProperty(authority string, propID, propIndex, propType uint32, value []byte) error {
	log.Traceln("In ICertAdminD2.SetCAProperty")

	req := SetCAPropertyReq{
		PwszAuthority:     authority,
		PropId:            propID,
		PropIndex:         propIndex,
		PropType:          propType,
		PctbPropertyValue: newBlob(value),
	}
	res := SetCAPropertyRes{}
	if err := c.call(IIDICertAdminD2, "ICertAdminD2::SetCAProperty", ICertAdminD2SetCAPropertyOp, &req, &res); err != nil {
		return err
	}
	if err := checkReturnCode("ICertAdminD2::SetCAProperty", res.ReturnValue); err != nil {
		return err
	}
	return nil
}

// GetCASecurity reads the CA's security descriptor — the DACL carrying the CA
// roles (ManageCA, ManageCertificates, Enroll, ...) whose masks are the CA
// right bits, not directory rights.
func (c *ICertAdmin) GetCASecurity(authority string) ([]byte, error) {
	log.Traceln("In ICertAdminD2.GetCASecurity")

	req := GetCASecurityReq{PwszAuthority: authority}
	res := GetCASecurityRes{}
	if err := c.call(IIDICertAdminD2, "ICertAdminD2::GetCASecurity", ICertAdminD2GetCASecurityOp, &req, &res); err != nil {
		return nil, err
	}
	if err := checkReturnCode("ICertAdminD2::GetCASecurity", res.ReturnValue); err != nil {
		return nil, err
	}
	return res.PctbSD.Pb, nil
}

// SetCASecurity replaces the CA's security descriptor. sd must be a
// self-relative SECURITY_DESCRIPTOR; callers normally read the current one with
// GetCASecurity, edit its DACL and write it back.
func (c *ICertAdmin) SetCASecurity(authority string, sd []byte) error {
	log.Traceln("In ICertAdminD2.SetCASecurity")

	req := SetCASecurityReq{PwszAuthority: authority, PctbSD: newBlob(sd)}
	res := SetCASecurityRes{}
	if err := c.call(IIDICertAdminD2, "ICertAdminD2::SetCASecurity", ICertAdminD2SetCASecurityOp, &req, &res); err != nil {
		return err
	}
	if err := checkReturnCode("ICertAdminD2::SetCASecurity", res.ReturnValue); err != nil {
		return err
	}
	return nil
}

// GetTemplateList reads the CA's enabled-template property (CR_PROP_TEMPLATES)
// and returns it as the CA stores it: a newline-separated list of alternating
// template name and template OID entries. The final element is whatever the CA
// appended after the last newline (typically a NUL); it is preserved verbatim
// so SetTemplateList can write the list back in the CA's own format. Because of
// that trailing element, use AddTemplate/RemoveTemplate to edit the list rather
// than appending to it.
func (c *ICertAdmin) GetTemplateList(authority string) ([]string, error) {
	blob, err := c.GetCAProperty(authority, CRPropTemplates, 0, PropTypeString)
	if err != nil {
		return nil, err
	}
	if len(blob) == 0 {
		return nil, nil
	}
	return strings.Split(decodeUTF16Raw(blob), "\n"), nil
}

// SetTemplateList writes the enabled-template list back to the CA in the same
// newline-separated UTF-16LE form GetTemplateList returned.
//
// Take care when building the list by hand: because the CA's terminator is the
// last element, appending to a list from GetTemplateList puts the new entries
// where the CA will not read them. Prefer AddTemplate and RemoveTemplate, which
// handle that.
func (c *ICertAdmin) SetTemplateList(authority string, list []string) error {
	return c.SetCAProperty(authority, CRPropTemplates, 0, PropTypeString,
		encodeUTF16Raw(strings.Join(list, "\n")))
}

// AddTemplate enables a certificate template on the CA, naming it by its CN and
// its OID (the template's msPKI-Cert-Template-OID). It reports whether the list
// changed: a template already enabled is left alone and nothing is written.
func (c *ICertAdmin) AddTemplate(authority, name, oid string) (bool, error) {
	log.Traceln("In ICertAdminD2.AddTemplate")

	list, err := c.GetTemplateList(authority)
	if err != nil {
		return false, err
	}
	if templateIndex(list, name) >= 0 {
		return false, nil
	}
	// Prepend rather than append. The list's final element is the CA's
	// terminator, and entries written after it are not read back as templates —
	// which is why appending silently produces a list the CA ignores.
	list = append([]string{name, oid}, list...)
	if err := c.SetTemplateList(authority, withTerminator(list)); err != nil {
		return false, err
	}
	return true, nil
}

// RemoveTemplate disables a certificate template on the CA, dropping its name
// and OID pair from the enabled list. It reports whether the list changed.
func (c *ICertAdmin) RemoveTemplate(authority, name string) (bool, error) {
	log.Traceln("In ICertAdminD2.RemoveTemplate")

	list, err := c.GetTemplateList(authority)
	if err != nil {
		return false, err
	}
	i := templateIndex(list, name)
	if i < 0 {
		return false, nil
	}
	pruned := append(append([]string{}, list[:i]...), list[i+2:]...)
	if err := c.SetTemplateList(authority, withTerminator(pruned)); err != nil {
		return false, err
	}
	return true, nil
}

// templateIndex returns the position of name among the list's name slots — the
// even positions, each followed by that template's OID — or -1 when it is not
// enabled. Template names are compared case-insensitively, as AD treats them.
// The loop bound stops before a trailing terminator element, so the CA's
// terminator is never mistaken for a template name.
func templateIndex(list []string, name string) int {
	for i := 0; i+1 < len(list); i += 2 {
		if strings.EqualFold(list[i], name) {
			return i
		}
	}
	return -1
}

// withTerminator restores the trailing element the CA keeps after the last
// newline when editing has left the list without one (a pair count, i.e. an
// even length). A CA with templates enabled always has it, so this normally
// changes nothing; it matters when the list was emptied or read from a CA whose
// property was absent.
func withTerminator(list []string) []string {
	if len(list)%2 == 0 {
		return append(list, "\x00")
	}
	return list
}

// decodeUTF16Raw decodes a UTF-16LE buffer without stripping a trailing NUL,
// unlike decodeUTF16 which is used for human-readable status strings. The CA's
// template list relies on the NUL surviving a read/modify/write round trip.
func decodeUTF16Raw(b []byte) string {
	// A trailing odd byte is dropped by the loop bound below.
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, le.Uint16(b[i:i+2]))
	}
	return string(utf16.Decode(u))
}

// encodeUTF16Raw encodes a string as UTF-16LE with no added NUL terminator.
func encodeUTF16Raw(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, len(u)*2)
	for i, c := range u {
		le.PutUint16(b[i*2:], c)
	}
	return b
}
