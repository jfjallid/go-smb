# go-smb

## Description
Package go-smb is a work in progress to create a go library that implements
an SMB2/3 client with support for interacting with various RPC endpoints using
DCERPC over named pipes or raw TCP connections.
This project was created as a way to learn how to interact remotely with Windows
services and the remote registry, but has evolved to include support for more
RPC services.

It is based upon the work of https://github.com/stacktitan/smb but has seen a
lot of changes to add support for SMB3, DCERPC, MSRRP and other RPC services
where parts of the code are taken from or inspired by another go-smb project
located at https://github.com/hirochachacha/go-smb2. Kerberos support is
implemented with the help of a forked and modified version of the gokrb5
library from https://github.com/jcmturner/gokrb5

For inspiration on how to use the library, look at some of the other projects
that implement it:

- [go-ShareEnum](https://github.com/jfjallid/go-shareenum): Enumerate and list SMB shares
- [go-lsass](https://github.com/jfjallid/go-lsass): Remotely deploy and execute
a process dumper to retrieve an LSASS memory dump without requiring local interactive access.
- [go-secdump](https://github.com/jfjallid/go-secdump): Remotely extract
credentials from the Window SAM hive without touching disk.
- [go-CMLoot](https://github.com/jfjallid/go-cmloot): Enumerate and download files from the SCCM deployment share

## Establishing a connection
There are multiple ways to establish a connection and authenticate against the
remote system.

A direct connection could be established by using the smb.NewConnection(options)
call to authenticate against the remote server using provided credentials.

A connection could also be established through an upstream SOCKS5 proxy, either
by passing credentials through the options struct, or by relying on the upstream
proxy to handle authentication such as Impacket's ntlmrelayx.py does.

A third way is to use the NTLM relay support in the `relay/` package: listen
for incoming SMB or HTTP NTLM authentications, forward them to one or more
upstream targets (SMB, HTTP/S, LDAP/S), pool the resulting authenticated
sessions, and optionally expose the pool to local tools through a SOCKS5
proxy.

Two entry points are provided:

- `relay.RelayServer` — long-running multi-target listener with a session
  pool, post-auth actions, optional fake-server handoff, and an
  interactive REPL when driven via the `cmd/ntlmrelay` binary. See
  [`cmd/ntlmrelay/README.md`](cmd/ntlmrelay/README.md) for the user-facing
  guide.
- `relay.RelayClient` — one-shot listener that accepts a single inbound
  auth and returns the authenticated `*smb.Connection`. This replaces the
  removed `smb.NewRelayConnection` helper.

The relay forces SMB 2.1 as the max dialect with signing and encryption
disabled, so Windows targets that require SMB signing (the default on
modern domain controllers) will refuse the relay. Treat the relay as a
lab-only tool.

For inspiration on how to use the various forms of establishing a connection and
how to use the different methods of authentication I recommended inspecting the
[go-ShareEnum](https://github.com/jfjallid/go-shareenum) repo.

The following snippet of code illustrates how a program could be written to use
different connection types.

```go
    socksServerIP := "" // Specify to use an upstream SOCKS5 proxy server
    socksPort := 1080
    targetHost := "192.168.0.1"
    targetPort := 445
    username := "ServerAdmin"
    password := "SecretPass123"
    domain := "domain.local"
    hashBytes := []byte{} // Either specify a password or the NT Hash bytes for authentication
    relayConnection := false // if true, perform NTLM relaying
    relayPort := 445 // local port the relay listener binds when relayConnection is true

	options := smb.Options{
		Host: targetHost,
		Port: targetPort,
		Initiator: &spnego.NTLMInitiator{
			User:      username,
			Password:  password,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: false, // Authenticate with local and not domain account?
		},
		// Encryption defaults to smb.EncryptionPreferred: encrypt whenever the
		// connection negotiates a cipher. Other choices are
		// smb.EncryptionServerDirected (encrypt only what the server asks for),
		// smb.EncryptionRequired (refuse a connection that cannot encrypt) and
		// smb.EncryptionDisabled (useful for debugging a plaintext capture).
		// Encryption: smb.EncryptionServerDirected,
		// To pin the legacy SMB 2.1 path, set:
		// Dialects: smb.DialectsSMB2Only,
	}

    var session *smb.Connection

    if socksServerIP != "" {
        dialSocksProxy, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", socksServerIP, socksPort), nil, proxy.Direct)
        if err != nil {
            log.Errorln(err)
            return
        }
        options.ProxyDialer = dialSocksProxy
    }

    if relayConnection {
        // Listen on relayPort, relay the first inbound NTLM authentication
        // to the target, and hand back the authenticated connection.
        session, _, err = relay.RelayClient(relay.ClientConfig{
            ListenAddr:      fmt.Sprintf(":%d", relayPort),
            Target:          fmt.Sprintf("%s:%d", targetHost, targetPort),
            UpstreamOptions: options,
        })
    } else {
	    session, err = smb.NewConnection(options)
    }
	if err != nil {
		log.Criticalln(err)
		return
	}

    ...

```

## Examples

### List SMB Shares

A very basic example of how to list SMB shares available at a target server.
For a more detailed example, checkout [go-ShareEnum.](https://github.com/jfjallid/go-shareenum)

```go
package main

import (
	"fmt"

	"github.com/jfjallid/go-smb/smb"
	"github.com/jfjallid/go-smb/spnego"
	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/smbtransport"
	"github.com/jfjallid/go-smb/dcerpc/mssrvs"
)

func main() {

    hostname := "127.0.0.1"
    options := smb.Options{
        Host:           hostname,
        Port:           445,
        Initiator:      &spnego.NTLMInitiator{
            User:       "Administrator",
            Password:   "AdminPass123",
            Domain:     "",
        },
    }
    session, err := smb.NewConnection(options)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer session.Close()

    if session.IsSigningRequired() {
        fmt.Println("[-] Signing is required")
    } else {
        fmt.Println("[+] Signing is NOT required")
    }

    if session.IsAuthenticated() {
        fmt.Printf("[+] Login successful as %s\n", session.GetAuthUsername())
    } else {
        fmt.Println("[-] Login failed")
    }

    share := "IPC$"
    err = session.TreeConnect(share)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer session.TreeDisconnect(share)
    f, err := session.OpenFile(share, mssrvs.MSRPCSrvSvcPipe)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer f.CloseFile()

    transport, err := smbtransport.NewSMBTransport(f)
    if err != nil {
        fmt.Println(err)
        return
    }

    bind, err := dcerpc.Bind(transport, mssrvs.MSRPCUuidSrvSvc, mssrvs.MSRPCSrvSvcMajorVersion, mssrvs.MSRPCSrvSvcMinorVersion, dcerpc.MSRPCUuidNdr)
    if err != nil {
        fmt.Println(err)
        return
    }
    rpccon := mssrvs.NewRPCCon(bind)

    shares, err := rpccon.NetShareEnumAll(hostname)
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Printf("\nShares:\n")
    for _, share := range shares {
        fmt.Printf("Name: %s\nComment: %s\nType: %s\n\n", share.Name, share.Comment, share.Type)
    }
}
```

### List Windows services's status via direct TCP connection

When the target RPC service is accessible over a direct TCP endpoint (e.g., dynamic
RPC ports), you can connect without SMB:

```go
package main

import (
	"fmt"
	"net"
	"time"

	"github.com/jfjallid/go-smb/dcerpc"
	"github.com/jfjallid/go-smb/dcerpc/epm"
	"github.com/jfjallid/go-smb/dcerpc/msscmr"

	"github.com/jfjallid/go-smb/spnego"
)

func main() {

	hostname := "127.0.0.1"

	sb, err := epm.GetStringBindingForInterface(hostname, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, time.Second * 5)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("MS-SCMR is running at: %s\n", sb[0].String())
	conn, err := net.Dial("tcp", sb[0].String())
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	initiator := &spnego.NTLMInitiator{
			User:        "Administrator",
			Password:    "AdminPass123",
	}

    transport := dcerpc.NewTCPTransport(conn)

	bind, err := dcerpc.BindAuth(transport, msscmr.MSRPCUuidSvcCtl, msscmr.MSRPCSvcCtlMajorVersion, msscmr.MSRPCSvcCtlMinorVersion, dcerpc.MSRPCUuidNdr, dcerpc.RpcAuthnLevelPktPrivacy, initiator)
	if err != nil {
		fmt.Println(err)
		return
	}
    rpccon := msscmr.NewRPCCon(bind)
	result, err := rpccon.EnumServicesStatus(uint32(16), uint32(3))
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, service := range result {
		fmt.Printf("\nDisplayName: %s\nServiceName: %s\nStatus: %s\n", service.DisplayName, service.ServiceName, msscmr.ServiceStatusMap[service.ServiceStatus.CurrentState])
		break // Only print the first service
	}
}
```
