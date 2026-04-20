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
//
// High-level DCOM Connection API orchestrating the full activation flow.

package msdcom

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/gss"
)

// DCOMOptions configures authentication and connection parameters.
type DCOMOptions struct {
	// MechFactory creates fresh gss.Mechanism instances for each TCP connection
	// that needs authenticated binding. Each connection requires its own
	// mechanism since a mechanism can only complete one security context.
	// If nil, unauthenticated binding is used.
	MechFactory func() gss.Mechanism

	// AuthLevel specifies the DCERPC authentication level.
	// Typically dcerpc.RpcAuthnLevelPktPrivacy (6) for DCOM.
	AuthLevel uint8

	// Timeout for TCP connection establishment. Defaults to 10 seconds.
	Timeout time.Duration

	// Dialer, if set, is used instead of net.DialTimeout for all TCP
	// connections (port 135 and dynamic port). This allows clients to
	// route connections through a SOCKS proxy or custom transport.
	// The function receives the target address as "host:port" and should
	// return an established net.Conn.
	Dialer func(addr string) (net.Conn, error)
}

// DCOMConnection manages the lifecycle of a DCOM session including
// the port 135 activator connection and dynamic port connection.
type DCOMConnection struct {
	host string
	cid  [16]byte // Causality ID, constant per session
	opts DCOMOptions

	// Port 135 connections
	activatorTransport *dcerpc.TCPTransport
	activator          *SCMActivator

	// Dynamic port connection (established after first activation)
	dynTransport *dcerpc.TCPTransport
	dynAddr      string              // host:port of established dynamic connection
	dynBind      *dcerpc.ServiceBind // Initial bind (IDispatch)

	// IRemUnknown for release/QueryInterface (lazily created via AlterContext when needed)
	remUnknown     *RemUnknown
	ipidRemUnknown [16]byte

	// Cached AlterContext bindings keyed by IID (for COM method calls)
	ifaceBinds map[[16]byte]*dcerpc.ServiceBind

	// Tracked objects for cleanup
	objects []*COMObject
}

// COMObject wraps an interface pointer for making DCOM method calls.
type COMObject struct {
	conn *DCOMConnection
	ipid [16]byte
	iid  [16]byte
	oxid uint64
	oid  uint64
	refs uint32
}

// NewDCOMConnection establishes a DCOM session to the specified host.
// It connects to port 135 and binds to the IRemoteSCMActivator interface.
func NewDCOMConnection(host string, opts DCOMOptions) (*DCOMConnection, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}

	var cid [16]byte
	if _, err := rand.Read(cid[:]); err != nil {
		return nil, fmt.Errorf("failed to generate causality ID: %w", err)
	}

	conn := &DCOMConnection{
		host: host,
		cid:  cid,
		opts: opts,
	}

	if err := conn.connectActivator(); err != nil {
		return nil, err
	}

	return conn, nil
}

// CreateInstance activates a COM class and returns a COMObject for the
// requested interface. This performs the full DCOM activation flow:
//
//  1. RemoteCreateInstance on port 135 (IRemoteSCMActivator)
//  2. Parse the returned OXID bindings for the dynamic port
//  3. Connect to the dynamic port and bind to IDispatch
//  4. Return a COMObject wrapping the interface IPID
func (d *DCOMConnection) CreateInstance(clsid, iid [16]byte) (*COMObject, error) {
	result, err := d.activator.RemoteCreateInstance(d.cid, clsid, iid)
	if err != nil {
		return nil, fmt.Errorf("RemoteCreateInstance: %w", err)
	}

	log.Debugf("Activation result: OXID=0x%x IpidRemUnknown=%x InterfaceIPID=%x InterfaceOXID=0x%x InterfaceOID=0x%x",
		result.OXID, result.IpidRemUnknown, result.InterfaceIPID, result.InterfaceOXID, result.InterfaceOID)

	// Establish dynamic port connection if not already connected
	if d.dynTransport == nil {
		if err := d.connectDynamic(result, iid); err != nil {
			return nil, err
		}
	} else {
		if err := d.validateDynamicPort(result); err != nil {
			return nil, err
		}
	}

	obj := &COMObject{
		conn: d,
		ipid: result.InterfaceIPID,
		iid:  iid,
		oxid: result.InterfaceOXID,
		oid:  result.InterfaceOID,
		refs: 5, // initial reference count from activation
	}
	d.objects = append(d.objects, obj)

	return obj, nil
}

// ClearObjectRefs zeroes the reference count on all tracked COM objects so
// that Close will skip RemRelease calls. Use this after invoking a method
// (e.g., Application.Quit) that causes the server to drop the connection,
// since RemRelease would fail on the dead connection.
func (d *DCOMConnection) ClearObjectRefs() {
	for _, obj := range d.objects {
		obj.refs = 0
	}
}

// Close releases all tracked COM objects and closes all connections.
func (d *DCOMConnection) Close() error {
	// Release all tracked objects
	for _, obj := range d.objects {
		if obj.refs > 0 {
			obj.release()
		}
	}
	d.objects = nil

	var firstErr error
	if d.dynTransport != nil {
		if err := d.dynTransport.Close(); err != nil {
			firstErr = err
		}
		d.dynTransport = nil
		d.dynBind = nil
		d.remUnknown = nil
	}
	if d.activatorTransport != nil {
		if err := d.activatorTransport.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		d.activatorTransport = nil
		d.activator = nil
	}

	return firstErr
}

// dial establishes a TCP connection to addr using the custom Dialer if
// configured, falling back to net.DialTimeout with the configured timeout.
func (d *DCOMConnection) dial(addr string) (net.Conn, error) {
	if d.opts.Dialer != nil {
		return d.opts.Dialer(addr)
	}
	return net.DialTimeout("tcp", addr, d.opts.Timeout)
}

// connectActivator establishes the port 135 connection and binds to
// IRemoteSCMActivator.
func (d *DCOMConnection) connectActivator() error {
	addr := net.JoinHostPort(d.host, "135")
	conn, err := d.dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to port 135 on %s: %w", d.host, err)
	}

	transport := dcerpc.NewTCPTransport(conn)

	sb, err := d.bindToInterface(transport,
		MSRPCUuidIRemoteSCMActivator,
		MSRPCIRemoteSCMActivatorMajorVersion,
		MSRPCIRemoteSCMActivatorMinorVersion,
		"")
	if err != nil {
		transport.Close()
		return fmt.Errorf("failed to bind IRemoteSCMActivator: %w", err)
	}

	d.activatorTransport = transport
	d.activator = &SCMActivator{ServiceBind: sb}
	return nil
}

// connectDynamic establishes the dynamic port connection, resolves the OXID,
// and binds to the requested interface. Tries all TCP string bindings in order.
// IRemUnknown is lazily created via AlterContext when needed.
func (d *DCOMConnection) connectDynamic(activation *ActivationResult, iid [16]byte) error {
	addrs := d.resolveDynamicAddresses(activation)
	if len(addrs) == 0 {
		return fmt.Errorf("no TCP binding found in OXID bindings")
	}

	// Extract SPN from security bindings so the Kerberos ticket is
	// requested for the correct server identity (e.g. mmc.exe vs wmiprvse.exe).
	// The Principal field may be in SPN format ("host/server.domain.com") or
	// in DOMAIN\User format. Only use it as an
	// SPN override when it's in service/host format.
	spn := ""
	secBindings := activation.OxidBindings.ParseSecurityBindings()
	for _, sb := range secBindings {
		log.Debugf("Security binding: AuthnSvc=%d AuthzSvc=%d Principal=%q", sb.AuthnSvc, sb.AuthzSvc, sb.Principal)
		// AuthnSvc 9 = SPNEGO/Negotiate, 16 = Kerberos
		if (sb.AuthnSvc == 9 || sb.AuthnSvc == 16) && sb.Principal != "" {
			if strings.Contains(sb.Principal, "/") {
				// Already in SPN format (e.g. "host/server.domain.com")
				spn = sb.Principal
				log.Debugf("Using SPN from security binding: %s", spn)
			} else {
				log.Debugf("Security binding Principal %q is not in SPN format, ignoring", sb.Principal)
			}
			break
		}
	}

	iidStr := guidToUUIDString(iid)

	var lastErr error
	for _, dynAddr := range addrs {
		conn, err := d.dial(dynAddr)
		if err != nil {
			log.Debugf("Failed to connect to %s: %v", dynAddr, err)
			lastErr = err
			continue
		}

		transport := dcerpc.NewTCPTransport(conn)

		sb, err := d.bindToInterface(transport, iidStr, 0, 0, spn)
		if err != nil {
			transport.Close()
			// Bind_Nak is an authentication/protocol rejection — retrying
			// on a different address to the same server won't help.
			var bindNak *dcerpc.BindNakError
			if errors.As(err, &bindNak) {
				return fmt.Errorf("failed to bind %s on %s: %w", iidStr, dynAddr, err)
			}
			log.Debugf("Failed to bind %s on %s: %v", iidStr, dynAddr, err)
			lastErr = err
			continue
		}

		d.dynTransport = transport
		d.dynAddr = dynAddr
		d.dynBind = sb
		d.ipidRemUnknown = activation.IpidRemUnknown

		// Pre-populate ifaceBinds with the initial interface
		d.ifaceBinds = make(map[[16]byte]*dcerpc.ServiceBind)
		d.ifaceBinds[iid] = sb

		return nil
	}

	return fmt.Errorf("failed to connect to any dynamic port: %w", lastErr)
}

// validateDynamicPort checks that a new activation's OXID bindings include
// the dynamic port we are already connected to. If none of the resolved
// addresses match, the activation targets a different server process and we
// cannot multiplex it over the existing connection.
func (d *DCOMConnection) validateDynamicPort(activation *ActivationResult) error {
	addrs := d.resolveDynamicAddresses(activation)
	for _, a := range addrs {
		if a == d.dynAddr {
			return nil
		}
	}
	return fmt.Errorf("new activation requires dynamic endpoint %v but already connected to %s; multiple dynamic transports not supported", addrs, d.dynAddr)
}

// resolveDynamicAddresses extracts all TCP host:port candidates from the
// activation result's OXID bindings. The user-provided host (d.host) is
// always tried first with each discovered port, since we know it is
// reachable (we connected to port 135 on it). Remaining bindings with
// different hosts are appended as fallbacks.
func (d *DCOMConnection) resolveDynamicAddresses(activation *ActivationResult) []string {
	bindings := activation.OxidBindings.ParseStringBindings()
	var preferred, other []string
	seenPorts := make(map[string]bool)

	for _, b := range bindings {
		if b.TowerId == TowerIDTCP && b.Address != "" {
			host, port := parseDCOMAddress(b.Address)
			if port == "" {
				continue
			}
			log.Debugf("OXID binding: host=%s port=%s", host, port)
			if host == "" || host == "0.0.0.0" || host == d.host {
				if !seenPorts[port] {
					seenPorts[port] = true
					preferred = append(preferred, net.JoinHostPort(d.host, port))
				}
			} else {
				other = append(other, net.JoinHostPort(host, port))
			}
		}
	}

	// If d.host was not found in any binding, still try d.host with each
	// unique port before falling back to other hosts. The user-provided
	// host is the most likely to be reachable from the caller's network.
	if len(preferred) == 0 {
		for _, addr := range other {
			_, port, _ := net.SplitHostPort(addr)
			if !seenPorts[port] {
				seenPorts[port] = true
				preferred = append(preferred, net.JoinHostPort(d.host, port))
			}
		}
	}

	result := append(preferred, other...)
	log.Debugf("Dynamic address candidates: %v", result)
	return result
}

// parseDCOMAddress parses a DCOM string binding address which may be
// in the format "host[port]" or just "host".
func parseDCOMAddress(addr string) (host, port string) {
	// Look for "[port]" suffix
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ']' {
			// Find matching '['
			for j := i - 1; j >= 0; j-- {
				if addr[j] == '[' {
					return addr[:j], addr[j+1 : i]
				}
			}
		}
	}
	return addr, ""
}

// spnOverrider is implemented by authentication mechanisms that support
// overriding the SPN used for ticket requests (e.g., KRB5Initiator).
type spnOverrider interface {
	SetSPN(string)
}

// bindToInterface performs either authenticated or unauthenticated binding
// depending on DCOMOptions. If spn is non-empty and the mechanism supports
// it, the SPN is overridden before binding.
func (d *DCOMConnection) bindToInterface(transport *dcerpc.TCPTransport, uuid string, major, minor uint16, spn string) (*dcerpc.ServiceBind, error) {
	if d.opts.MechFactory != nil {
		mech := d.opts.MechFactory()
		if spn != "" {
			if so, ok := mech.(spnOverrider); ok {
				log.Debugf("Overriding mechanism SPN to %q", spn)
				so.SetSPN(spn)
			}
		}
		return dcerpc.BindAuth(transport, uuid, major, minor, dcerpc.MSRPCUuidNdr, d.opts.AuthLevel, mech)
	}
	return dcerpc.Bind(transport, uuid, major, minor, dcerpc.MSRPCUuidNdr)
}

// getOrCreateIfaceBind returns a ServiceBind for the given IID, creating one
// via AlterContext if it doesn't already exist. This allows DCOM method calls
// on interfaces other than IRemUnknown to use the correct presentation context.
func (d *DCOMConnection) getOrCreateIfaceBind(iid [16]byte) (*dcerpc.ServiceBind, error) {
	if d.ifaceBinds == nil {
		d.ifaceBinds = make(map[[16]byte]*dcerpc.ServiceBind)
	}

	if sb, ok := d.ifaceBinds[iid]; ok {
		return sb, nil
	}

	iidStr := guidToUUIDString(iid)
	log.Debugf("AlterContext for IID %s", iidStr)

	sb, err := d.dynBind.AlterContext(iidStr, 0, 0, dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, err
	}

	d.ifaceBinds[iid] = sb
	return sb, nil
}

// getOrCreateRemUnknown lazily creates the IRemUnknown binding via AlterContext.
func (d *DCOMConnection) getOrCreateRemUnknown() (*RemUnknown, error) {
	if d.remUnknown != nil {
		return d.remUnknown, nil
	}

	sb, err := d.dynBind.AlterContext(
		MSRPCUuidIRemUnknown,
		MSRPCIRemUnknownMajorVersion,
		MSRPCIRemUnknownMinorVersion,
		dcerpc.MSRPCUuidNdr)
	if err != nil {
		return nil, fmt.Errorf("AlterContext for IRemUnknown: %w", err)
	}

	d.remUnknown = NewRemUnknown(sb, d.ipidRemUnknown)
	return d.remUnknown, nil
}

// guidToUUIDString converts a [16]byte GUID in mixed-endian wire format
// to the standard UUID string representation.
func guidToUUIDString(guid [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		le.Uint32(guid[0:4]),
		le.Uint16(guid[4:6]),
		le.Uint16(guid[6:8]),
		guid[8:10],
		guid[10:16],
	)
}

// unmarshalInterfacePointerResponse parses a DCOM method response that
// contains a returned interface pointer.
//
// Wire format (after ORPCTHAT, which CallMethod already stripped):
//
//	ppRetVal referent_id (4 bytes)
//	MInterfacePointer (deferred: maxCount + ulCntData + OBJREF)
//	HRESULT (4 bytes)
func UnmarshalInterfacePointerResponse(conn *DCOMConnection, data []byte) (*COMObject, error) {
	offset := 0

	if len(data) < 4 {
		return nil, fmt.Errorf("response too short for referent ID")
	}
	refId := le.Uint32(data[offset:])
	offset += 4

	if refId == 0 {
		return nil, fmt.Errorf("returned interface pointer is NULL")
	}

	mip, consumed, err := UnmarshalMInterfacePointer(data[offset:])
	if err != nil {
		return nil, fmt.Errorf("MInterfacePointer: %w", err)
	}
	offset += consumed

	if len(data) < offset+4 {
		return nil, fmt.Errorf("response too short for HRESULT")
	}
	hresult := le.Uint32(data[offset:])
	if hresult != 0 {
		return nil, fmt.Errorf("method failed: HRESULT 0x%08x", hresult)
	}

	objref, _, err := UnmarshalOBJREF(mip.Data)
	if err != nil {
		return nil, fmt.Errorf("OBJREF: %w", err)
	}

	if objref.Std == nil {
		return nil, fmt.Errorf("expected OBJREF_STANDARD, got flags 0x%08x", objref.Flags)
	}

	return conn.newObjectFromSTDOBJREF(objref.Std, objref.IID), nil
}

// newObjectFromSTDOBJREF creates a COMObject from a STDOBJREF and registers
// it in the connection's tracked objects list.
func (d *DCOMConnection) newObjectFromSTDOBJREF(std *STDOBJREF, iid [16]byte) *COMObject {
	obj := &COMObject{
		conn: d,
		ipid: std.IPID,
		iid:  iid,
		oxid: std.OXID,
		oid:  std.OID,
		refs: std.CPublicRefs,
	}
	d.objects = append(d.objects, obj)
	return obj
}

// --- COMObject methods ---

// CallMethod invokes a method on the remote COM object.
// It automatically prepends ORPCTHIS and strips ORPCTHAT from the response.
// The caller provides only the method-specific stub data after ORPCTHIS.
func (o *COMObject) CallMethod(opnum uint16, stubData []byte) ([]byte, error) {
	if o.conn.dynBind == nil {
		return nil, fmt.Errorf("no dynamic connection established")
	}

	sb, err := o.conn.getOrCreateIfaceBind(o.iid)
	if err != nil {
		return nil, fmt.Errorf("AlterContext for interface: %w", err)
	}

	// Prepend ORPCTHIS
	orpcThis := &ORPCTHIS{
		Version:     COMVERSION{MajorVersion: 5, MinorVersion: 7},
		CausalityId: o.conn.cid,
	}

	buf := make([]byte, 0, ORPCTHISSize+len(stubData))
	buf = append(buf, orpcThis.MarshalBinary()...)
	buf = append(buf, stubData...)

	result, err := sb.MakeRequestWithObjectUUID(opnum, o.ipid[:], buf)
	if err != nil {
		return nil, err
	}

	// Strip ORPCTHAT from response
	_, consumed, err := UnmarshalORPCTHAT(result)
	if err != nil {
		return nil, fmt.Errorf("ORPCTHAT: %w", err)
	}

	return result[consumed:], nil
}

// QueryInterface requests an additional interface on this COM object
// via IRemUnknown.RemQueryInterface.
func (o *COMObject) QueryInterface(iid [16]byte) (*COMObject, error) {
	ru, err := o.conn.getOrCreateRemUnknown()
	if err != nil {
		return nil, fmt.Errorf("QueryInterface: %w", err)
	}

	results, err := ru.RemQueryInterface(o.conn.cid, o.ipid, [][16]byte{iid})
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("QueryInterface returned no results")
	}

	if results[0].HResult != 0 {
		return nil, fmt.Errorf("QueryInterface failed: HRESULT 0x%08x", results[0].HResult)
	}

	return o.conn.newObjectFromSTDOBJREF(&results[0].Std, iid), nil
}

// Release decrements the remote reference count for this COM object.
func (o *COMObject) Release() error {
	return o.release()
}

func (o *COMObject) release() error {
	if o.refs == 0 || o.conn.dynBind == nil {
		o.refs = 0
		return nil
	}

	ru, err := o.conn.getOrCreateRemUnknown()
	if err != nil {
		log.Debugf("Failed to create IRemUnknown for release: %v", err)
		o.refs = 0
		return nil
	}

	refs := []REMINTERFACEREF{
		{
			IPID:         o.ipid,
			CPublicRefs:  o.refs,
			CPrivateRefs: 0,
		},
	}

	err = ru.RemRelease(o.conn.cid, refs)
	o.refs = 0
	return err
}

// Conn returns the underlying DCOMConnection for this COM object.
func (o *COMObject) Conn() *DCOMConnection {
	return o.conn
}

// IPID returns the interface pointer identifier for this COM object.
func (o *COMObject) IPID() [16]byte {
	return o.ipid
}

// IID returns the interface identifier for this COM object.
func (o *COMObject) IID() [16]byte {
	return o.iid
}
