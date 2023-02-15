# go-smb

## Description
Package go-smb is a work in progress to create a go library that implements
an SMB2/3 client with support for DCERPC and MSRRP.
This project was created as a way to learn how to interact remotely with Windows
services and the remote registry.

It is based upon the work of https://github.com/stacktitan/smb but has seen a
lot of changes to add support for SMB3, DCERPC and MSRRP where parts of the
code are taken from another go-smb project located at
https://github.com/hirochachacha/go-smb2.

## Examples

### List SMB Shares

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
    session, err := smb.NewConnection(options, false)
    if err != nil {
        fmt.Println(err)
        return
    }
    defer session.Close()

    if session.IsSigningRequired {
        fmt.Println("[-] Signing is required")
    } else {
        fmt.Println("[+] Signing is NOT required")
    }

    if session.IsAuthenticated {
        fmt.Println("[+] Login successful")
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
