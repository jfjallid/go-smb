# go-smb

## Description
Package go-smb is a work in progress to create a go library that implements
an SMB2/3 client with support for DCERPC and MSRRP.
This project was created as a way to learn how to interact remotely with Windows
services and the remote registry.

It is based upon the work of https://github.com/stacktitan/smb but has seen a
lot of changes to add support for SMB3, DCERPC and MSRRP where parts of the
code are taken from or inspired by another go-smb project located at
https://github.com/hirochachacha/go-smb2.

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

A third way is to use the experimental NTLM relay support by listening for
incoming SMB connections, forwarding the NTLM authentication to the target
system and then hijacking the authenticated connection. This won't work if
SMB signing is required or if only SMB 3.x is supported as the current
implementation is locked to SMB 2.1.

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

	options := smb.Options{
		Host: targetHost,
		Port: targetPort,
		Initiator: &smb.NTLMInitiator{
			User:      username,
			Password:  password,
			Hash:      hashBytes,
			Domain:    domain,
			LocalUser: false, // Authenticate with local and not domain account?
		},
		DisableEncryption: false, // Useful for debugging when SMB 3.1.1 is used
		ForceSMB2:         false,
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
        options.RelayPort = relayPort
	    session, err = smb.NewRelayConnection(options)
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
	"github.com/jfjallid/go-smb/smb/dcerpc"
)

func main() {

    hostname := "127.0.0.1"
    options := smb.Options{
        Host:           hostname,
        Port:           445,
        Initiator:      &smb.NTLMInitiator{
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
    f, err := session.OpenFile(share, "srvsvc")
    if err != nil {
        fmt.Println(err)
        return
    }
    defer f.CloseFile()

    bind, err := dcerpc.Bind(f, dcerpc.MSRPCUuidSrvSvc, 3, 0, dcerpc.MSRPCUuidNdr)
    if err != nil {
        fmt.Println(err)
        return
    }

    shares, err := bind.NetShareEnumAll(hostname)
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
