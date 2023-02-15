// MIT License
//
// Copyright (c) 2017 stacktitan
// Copyright (c) 2023 Jimmy Fjällid for extensions beyond login for SMB 2.1
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"net"
	"runtime/debug"

	"github.com/jfjallid/go-smb/gss"
	"github.com/jfjallid/go-smb/ntlmssp"
	"github.com/jfjallid/go-smb/smb/crypto/cmac"
	"github.com/jfjallid/go-smb/smb/encoder"
)

type File struct {
	*Connection
	shareid  uint32
	fd       []byte
	share    string
	filename string
}

type Session struct {
	IsSigningRequired   bool
	IsSigningDisabled   bool
	IsAuthenticated     bool
	supportsEncryption  bool
	debug               bool
	clientGuid          []byte
	securityMode        uint16
	messageID           uint64
	sessionID           uint64
	credits             uint64
	sessionFlags        uint16
	supportsMultiCredit bool
	//SequenceWindow              uint64
	MaxReadSize               uint32
	MaxWriteSize              uint32
	preauthIntegrityHashValue [64]byte // Session preauthIntegrityHashValue
	exportedSessionKey        []byte   // From SPNego Auth
	signer                    hash.Hash
	verifier                  hash.Hash
	encrypter                 cipher.AEAD
	decrypter                 cipher.AEAD
	conn                      net.Conn
	dialect                   uint16
	options                   Options
	trees                     map[string]uint32
}

type Options struct {
	Host                  string
	Port                  int
	Workstation           string
	Domain                string
	User                  string
	Password              string
	Hash                  string
	DisableSigning        bool
	RequireMessageSigning bool
	DisableEncryption     bool
	ForceSMB2             bool
	Initiator             Initiator
}

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return fmt.Errorf("Missing required option: Host")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return fmt.Errorf("Invalid or missing value: Port")
	}
	if opt.Initiator == nil {
		return fmt.Errorf("Initiator empty")
	}
	return nil
}

func (s *Session) Debug(msg string, err error) {
	if s.debug {
		fmt.Printf("[ DEBUG ] %s\n", msg)
		if err != nil {
			debug.PrintStack()
		}
	}
}

func (c *Connection) NegotiateProtocol() error {
	negReq, err := c.NewNegotiateReq()
	if err != nil {
		log.Errorln(err)
		return err
	}
	c.Debug("Sending NegotiateProtocol request", nil)
	rr, err := c.send(negReq)
	if err != nil {
		log.Errorln(err)
		c.Debug("", err)
		return err
	}

	buf, err := c.recv(rr)
	if err != nil {
		log.Errorln(err)
		c.Debug("", err)
		return err
	}

	negRes := NewNegotiateRes()
	c.Debug("Unmarshalling NegotiateProtocol response", nil)
	if err := encoder.Unmarshal(buf, &negRes); err != nil {
		c.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if negRes.Header.Status != StatusOk {
		return fmt.Errorf(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}

	oid := negRes.SecurityBlob.OID
	if !oid.Equal(gss.SpnegoOid) {
		err = fmt.Errorf("Unknown security type OID")
		log.Errorln(err)
		return err
	}

	hasNTLMSSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(gss.NtLmSSPMechTypeOid) {
			hasNTLMSSP = true
			break
		}
	}
	if !hasNTLMSSP {
		return fmt.Errorf("Server does not support NTLMSSP")
	}

	c.securityMode = negRes.SecurityMode
	c.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(c.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			c.IsSigningRequired = true
		} else {
			c.IsSigningRequired = false
		}
	} else {
		c.IsSigningRequired = false
	}

	// Check if server supports multi-credit operations
	if (negRes.Capabilities & GlobalCapLargeMTU) == GlobalCapLargeMTU {
		c.supportsMultiCredit = true
	}

	// Check if encryption is enabled
	if (negRes.Capabilities & GlobalCapEncryption) == GlobalCapEncryption {
		c.supportsEncryption = true
	}

	// Update MaxReadSize and MaxWriteSize from response
	c.MaxReadSize = negRes.MaxReadSize
	c.MaxWriteSize = negRes.MaxWriteSize

	if c.dialect != DialectSmb_3_1_1 {
		return nil
	}
	// Handle context for SMB 3.1.1
	for _, context := range negRes.ContextList {
		switch context.ContextType {
		case PreauthIntegrityCapabilities:
			pic := PreauthIntegrityContext{}
			err = encoder.Unmarshal(context.Data, &pic)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if pic.HashAlgorithmCount != 1 { // Must be 1 selection according to spec
				err = fmt.Errorf("multiple hash algorithms")
				log.Errorln(err)
				return err
			}
			c.preauthIntegrityHashId = pic.HashAlgorithms[0]
			// MS-SMB2 Section 3.2.5.2 last paragraph.
			switch c.preauthIntegrityHashId {
			case SHA512:
				h := sha512.New()
				h.Write(c.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(c.preauthIntegrityHashValue[:0])

				h.Reset()
				h.Write(c.preauthIntegrityHashValue[:])
				h.Write(buf)
				h.Sum(c.preauthIntegrityHashValue[:0])
			default:
				err = fmt.Errorf("Unknown hash algorithm")
				log.Errorln(err)
				return err
			}
		case EncryptionCapabilities:
			ec := EncryptionContext{}
			err = encoder.Unmarshal(context.Data, &ec)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if ec.CipherCount != 1 { // Must be 1 according to spec
				err = fmt.Errorf("multiple cipher algorithms")
				log.Errorln(err)
				return err
			}
			c.cipherId = ec.Ciphers[0]
			switch c.cipherId {
			case AES128GCM:
			case AES256GCM:
			default:
				err = fmt.Errorf("Unknown cipher algorithm (%d)\n", c.cipherId)
				log.Errorln(err)
				return err
			}
		case SigningCapabilities: // Only supported by Windows 11/Window Server 2022 and later
			sc := SigningContext{}
			err = encoder.Unmarshal(context.Data, &sc)
			if err != nil {
				log.Errorln(err)
				return err
			}
			if sc.SigningAlgorithmCount != 1 {
				err = fmt.Errorf("multiple signing algorithms")
				log.Errorln(err)
				return err
			}
			c.signingId = sc.SigningAlgorithms[0]
			switch c.signingId {
			//case HMAC_SHA256:
			case AES_CMAC:
			case AES_GMAC:
			default:
				err = fmt.Errorf("Unknown signing algorithm (%d)\n", c.signingId)
				log.Errorln(err)
				return err
			}
		default:
			log.Debugf("Unsupported context type (%d)\n", context.ContextType)
		}
	}

	return nil
}

func (c *Connection) SessionSetup() error {
	spnegoClient := newSpnegoClient([]Initiator{c.options.Initiator})
	c.Debug("Sending SessionSetup1 request", nil)
	ssreq, err := c.NewSessionSetup1Req(spnegoClient)
	if err != nil {
		c.Debug("", err)
		return err
	}
	ssres, err := NewSessionSetup1Res()
	if err != nil {
		c.Debug("", err)
		return err
	}

	rr, err := c.send(ssreq)
	if err != nil {
		log.Errorln(err)
		return err
	}
	ssresbuf, err := c.recv(rr)
	if err != nil {
		log.Errorln(err)
		return err
	}

	c.Debug("Unmarshalling SessionSetup1 response", nil)
	if err := encoder.Unmarshal(ssresbuf, &ssres); err != nil {
		c.Debug("", err)
		return err
	}

	challenge := ntlmssp.NewChallenge()
	resp := ssres.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		c.Debug("", err)
		return err
	}

	if ssres.Header.Status != StatusMoreProcessingRequired {
		status, _ := StatusMap[ssres.Header.Status]
		return fmt.Errorf(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	c.sessionID = ssres.Header.SessionID
	if c.IsSigningRequired {
		if ssres.Flags&SessionFlagIsGuest != 0 {
			err = fmt.Errorf("guest account doesn't support signing")
			log.Errorln(err)
			return err
		} else if ssres.Flags&SessionFlagIsNull != 0 {
			err = fmt.Errorf("anonymous account doesn't support signing")
			log.Errorln(err)
			return err
		}
	}

	//TODO Validate Challenge security options?

	if c.Session.options.DisableEncryption {
		c.sessionFlags = ssres.Flags
	} else {
		c.sessionFlags = ssres.Flags | SessionFlagEncryptData
	}

	switch c.dialect {
	case DialectSmb_3_1_1:
		c.Session.preauthIntegrityHashValue = c.preauthIntegrityHashValue
		switch c.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(c.Session.preauthIntegrityHashValue[:])
			h.Write(rr.pkt)
			h.Sum(c.Session.preauthIntegrityHashValue[:0])

			h.Reset()
			h.Write(c.Session.preauthIntegrityHashValue[:])
			h.Write(ssresbuf)
			h.Sum(c.Session.preauthIntegrityHashValue[:0])
		}
	}

	c.Debug("Sending SessionSetup2 request", nil)
	ss2req, err := c.NewSessionSetup2Req(spnegoClient, &ssres)
	if err != nil {
		c.Debug("", err)
		return err
	}

	ss2req.Header.Credits = 127

	rr, err = c.send(ss2req)
	if err != nil {
		log.Errorln(err)
		c.Debug("", err)
		return err
	}

	// Handle signing and encryption options
	if c.sessionFlags&(SessionFlagIsGuest|SessionFlagIsNull) == 0 {
		sessionKey := spnegoClient.sessionKey()

		switch c.dialect {
		case DialectSmb_2_0_2, DialectSmb_2_1:
			if !c.IsSigningDisabled {
				c.Session.signer = hmac.New(sha256.New, sessionKey)
				c.Session.verifier = hmac.New(sha256.New, sessionKey)
			}
		case DialectSmb_3_1_1:
			switch c.preauthIntegrityHashId {
			case SHA512:
				h := sha512.New()
				h.Write(c.Session.preauthIntegrityHashValue[:])
				h.Write(rr.pkt)
				h.Sum(c.Session.preauthIntegrityHashValue[:0])
			}
			// Determine size of L variable for the KDF
			var l uint32
			switch c.cipherId {
			case AES128GCM:
				l = 128
			case AES128CCM:
				l = 128
			case AES256CCM:
				l = 256
			case AES256GCM:
				l = 256
			default:
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}

			if !c.IsSigningDisabled {
				signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), c.Session.preauthIntegrityHashValue[:], l)

				c.Session.signer, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.verifier, err = cmac.New(signingKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
			}

			encryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)
			decryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), c.Session.preauthIntegrityHashValue[:], l)

			switch c.cipherId {
			case AES128GCM:
				ciph, err := aes.NewCipher(encryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}

				ciph, err = aes.NewCipher(decryptionKey)
				if err != nil {
					log.Errorln(err)
					return err
				}
				c.Session.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
				if err != nil {
					log.Errorln(err)
					return err
				}
				log.Infoln("Initialized encrypter and decrypter with GCM")
			default:
				err = fmt.Errorf("Cipher algorithm (%d) not implemented", c.cipherId)
				log.Errorln(err)
				return err
			}
		}
	}

	ss2resbuf, err := c.recv(rr)
	if err != nil {
		log.Errorln(err)
		return err
	}
	c.Debug("Unmarshalling SessionSetup2 response", nil)
	var authResp Header
	if err := encoder.Unmarshal(ss2resbuf, &authResp); err != nil {
		c.Debug("Raw:\n"+hex.Dump(ss2resbuf), err)
		return err
	}
	if authResp.Status != StatusOk {
		status, _ := StatusMap[authResp.Status]
		return fmt.Errorf(fmt.Sprintf("NT Status Error: %s\n", status))
	}

	c.IsAuthenticated = true

	c.Debug("Completed NegotiateProtocol and SessionSetup", nil)

	c.enableSession()

	return nil
}

func (s *Session) sign(buf []byte) ([]byte, error) {
	var hdr Header
	err := encoder.Unmarshal(buf[:64], &hdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	hdr.Flags |= SMB2_FLAGS_SIGNED
	hdr.Signature = make([]byte, 16)
	hdrBuf, err := encoder.Marshal(hdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	copy(buf[:64], hdrBuf[:64])
	h := s.signer
	h.Reset()
	h.Write(buf)
	copy(buf[48:64], h.Sum(nil))

	return buf, nil
}

func (s *Session) verify(buf []byte) (ok bool) {
	signature := make([]byte, 16)
	copy(signature, buf[48:64])
	// Remove signature
	copy(buf[48:64], make([]byte, 16))
	h := s.verifier
	h.Reset()
	h.Write(buf)
	// Restore signature
	copy(buf[48:64], signature)

	return bytes.Equal(signature, h.Sum(nil))
}

func (s *Session) encrypt(buf []byte) ([]byte, error) {
	nonce := make([]byte, s.encrypter.NonceSize())
	_, err := rand.Read(nonce)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	tHdr := NewTransformHeader()
	copy(tHdr.Nonce, nonce)
	tHdr.OriginalMessageSize = uint32(len(buf))
	tHdr.SessionId = s.sessionID
	tHdrBytes, err := encoder.Marshal(tHdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	ciphertext := make([]byte, 0)
	ciphertext = s.encrypter.Seal(nil, nonce, buf, tHdrBytes[20:52])
	copy(tHdrBytes[4:20], ciphertext[len(ciphertext)-16:])
	return append(tHdrBytes, ciphertext[:len(ciphertext)-16]...), nil
}

func (s *Session) decrypt(buf []byte) ([]byte, error) {
	tHdr := NewTransformHeader()
	err := encoder.Unmarshal(buf[:52], &tHdr)
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	ciphertext := append(buf[52:], tHdr.Signature...)
	// Not sure where it is specified that part of the transform header is used as AdditionalData
	return s.decrypter.Open(ciphertext[:0], tHdr.Nonce[:s.decrypter.NonceSize()], ciphertext, buf[20:52])
}

func (c *Connection) TreeConnect(name string) error {
	c.Debug("Sending TreeConnect request ["+name+"]", nil)
	req, err := c.NewTreeConnectReq(name)
	if err != nil {
		c.Debug("", err)
		return err
	}
	buf, err := c.sendrecv(req)
	if err != nil {
		c.Debug("", err)
		return err
	}

	var resHeader Header
	c.Debug("Unmarshalling TreeConnect response Header ["+name+"]", nil)
	if err := encoder.Unmarshal(buf[:64], &resHeader); err != nil {
		c.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if resHeader.Status == StatusAccessDenied {
		return AccessDeniedError
	}

	var res TreeConnectRes

	c.Debug("Unmarshalling TreeConnect response ["+name+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		c.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if res.Header.Status != StatusOk {
		return fmt.Errorf("Failed to connect to tree: " + StatusMap[res.Header.Status])
	}
	c.trees[name] = res.Header.TreeID
	c.credits += uint64(res.Header.Credits) // Add granted credits

	c.Debug("Completed TreeConnect ["+name+"]", nil)
	return nil
}

func (c *Connection) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range c.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := fmt.Errorf("Unable to find tree path for disconnect")
		c.Debug("", err)
		return err
	}

	c.Debug("Sending TreeDisconnect request ["+name+"]", nil)
	req, err := c.NewTreeDisconnectReq(treeid)
	if err != nil {
		c.Debug("", err)
		return err
	}
	buf, err := c.sendrecv(req)
	if err != nil {
		c.Debug("", err)
		return err
	}
	c.Debug("Unmarshalling TreeDisconnect response for ["+name+"]", nil)
	var res TreeDisconnectRes
	if err := encoder.Unmarshal(buf, &res); err != nil {
		c.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	if res.Header.Status != StatusOk {
		return fmt.Errorf("Failed to disconnect from tree: " + StatusMap[res.Header.Status])
	}
	delete(c.trees, name)

	c.Debug("TreeDisconnect completed ["+name+"]", nil)
	return nil
}

func (f *File) CloseFile() error {

	f.Debug(fmt.Sprintf("Sending Close request [%s] for fileid [%x]", f.share, f.fd), nil)
	req, err := f.NewCloseReq(f.share, f.fd)
	if err != nil {
		f.Debug("", err)
		return err
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		f.Debug("", err)
		return err
	}
	var res CloseRes
	f.Debug(fmt.Sprintf("Unmarshalling Close response [%s] for fileid [%x]", f.share, f.fd), nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		f.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}

	if res.Header.Status != StatusOk {
		return fmt.Errorf("Failed to close file/dir: " + StatusMap[res.Header.Status])
	}
	f.Debug(fmt.Sprintf("Close of file completed [%s] fileid [%x]", f.share, f.fd), nil)
	return nil
}

func (f *File) QueryDirectory(pattern string, flags byte, fileIndex uint32, bufferSize uint32) (sf []SharedFile, err error) {
	sf = make([]SharedFile, 0)
	req, err := f.NewQueryDirectoryReq(
		f.share,
		pattern,
		f.fd,
		FileBothDirectoryInformation,
		flags,
		fileIndex,
		bufferSize,
	)

	if err != nil {
		f.Debug("", err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		f.Debug("", err)
		return
	}

	var res QueryDirectoryRes
	f.Debug(fmt.Sprintf("Unmarshalling QueryDirectory response [%s]", f.share), nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		f.Debug("Raw:\n"+hex.Dump(buf), err)
		return sf, err
	}

	if res.Header.Status == StatusNoMoreFiles {
		return
	}

	if res.Header.Status != StatusOk {
		err = fmt.Errorf("Failed to QueryDirectory: " + StatusMap[res.Header.Status])
		return
	}
	if res.OutputBufferLength == 0 {
		return
	}

	//TODO Handle response
	start, stop := uint32(0), res.OutputBufferLength
	for {
		var fs FileBothDirectoryInformationStruct
		if err = encoder.Unmarshal(res.Buffer[start:stop], &fs); err != nil {
			log.Errorln(err)
			f.Debug("Raw:\n"+hex.Dump(buf), err)
			return sf, err
		}
		fileName, err := encoder.FromUnicodeString(fs.FileName[:fs.FileNameLength])
		if err != nil {
			f.Debug("", err)
			return sf, err
		}
		start += fs.NextEntryOffset
		if (fileName == ".") || (fileName == "..") {
			// We don't care about the current and parent dir references
			if fs.NextEntryOffset == 0 {
				break
			}
			continue
		}
		sharedFile := SharedFile{
			Name:           fileName, //string(f.FileName[:f.FileNameLength]),
			Size:           fs.EndOfFile,
			CreationTime:   fs.CreationTime,
			LastAccessTime: fs.LastAccessTime,
			LastWriteTime:  fs.LastWriteTime,
			ChangeTime:     fs.ChangeTime,
			IsHidden:       (fs.FileAttributes & FileAttrHidden) == FileAttrHidden,
			IsDir:          (fs.FileAttributes & FileAttrDirectory) == FileAttrDirectory,
			IsReadOnly:     (fs.FileAttributes & FileAttrReadonly) == FileAttrReadonly,
		}

		sf = append(sf, sharedFile)
		if fs.NextEntryOffset == 0 {
			break
		}
	}
	return
}

func (s *Connection) ListDirectory(share, dir, pattern string) (files []SharedFile, err error) {
	req, err := s.NewCreateReq(share, dir,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		DAccMaskFileListDirectory|DAccMaskFileReadAttributes,
		FileAttrDirectory,
		FileShareRead|FileShareWrite,
		FileOpen,
		FileDirectoryFile,
	)

	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}
	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Errorln(err)
		s.Debug("Raw\n"+hex.Dump(buf), err)
		return files, err
	}

	if h.Status != StatusOk {
		err = fmt.Errorf("Failed to Create/open file/dir: " + StatusMap[h.Status])
		log.Errorln(err)
		return
	}

	var res CreateRes
	s.Debug("Unmarshalling Create response ["+share+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return files, err
	}
	f := &File{Connection: s, share: share, fd: res.FileId, filename: dir, shareid: s.trees[share]}
	defer f.CloseFile()

	// QueryDirectory request
	for {
		/*Using a response buffer size greater than 65536 I get an error about invalid parameter since
		  I do not set the MessageId and CreditCharge correctly.
		*/
		moreFiles, err := f.QueryDirectory(pattern, 0, 0, 65536) // If I use a smaller buffer I don't have to handle CreditCharge
		if err != nil {
			//fmt.Printf("Err: %v\n", err)
			f.Debug("", err)
			return files, err
		}
		if len(moreFiles) == 0 {
			break
		}
		files = append(files, moreFiles...)
	}

	// Update files with full path
	for i := range files {
		file := &files[i]
		if (file.Name == ".") || (file.Name == "..") {
			continue
		}
		if dir == "" {
			file.FullPath = file.Name
		} else {
			file.FullPath = fmt.Sprintf("%s\\%s", dir, file.Name)
		}
	}
	return
}

func (s *Connection) ListRecurseDirectory(share, dir, pattern string) (files []SharedFile, err error) {
	files, err = s.ListDirectory(share, dir, pattern)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}
	for _, file := range files {
		if !file.IsDir {
			continue
		}
		if (file.Name == ".") || (file.Name == "..") {
			continue
		}

		moreFiles, err := s.ListRecurseDirectory(share, file.FullPath, pattern)
		if err != nil {
			log.Errorln(err)
			s.Debug("", err)
			return files, err
		}
		files = append(files, moreFiles...)
	}
	return
}

func (s *Connection) ListShare(share, dir string, recurse bool) (files []SharedFile, err error) {

	files = make([]SharedFile, 0)
	// Connect to Tree
	err = s.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}
	// Defer tree disconnect
	defer s.TreeDisconnect(share)

	if recurse {
		files, err = s.ListRecurseDirectory(share, dir, "*")
	} else {
		files, err = s.ListDirectory(share, dir, "*")
	}

	return
}

func (s *Connection) OpenFile(tree string, filepath string) (file *File, err error) {
	req, err := s.NewCreateReq(tree, filepath,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		FAccMaskFileReadData|FAccMaskFileReadEA|FAccMaskFileReadAttributes|FAccMaskReadControl|FAccMaskSynchronize,
		0,
		FileShareRead|FileShareWrite,
		FileOpen,
		FileNonDirectoryFile,
	)

	//req.Credits = 256
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Errorln(err)
		s.Debug("Raw\n"+hex.Dump(buf), err)
		return nil, err
	}

	if h.Status != StatusOk {
		err = fmt.Errorf("Failed to Create/open file/dir: " + StatusMap[h.Status])
		log.Errorln(err)
		return
	}

	var res CreateRes
	s.Debug("Unmarshalling Create response ["+tree+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return nil, err
	}

	return &File{
		Connection: s,
		shareid:    s.trees[tree],
		fd:         res.FileId,
		share:      tree,
		filename:   filepath,
	}, nil
}

func (s *Connection) RetrieveFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {

	if callback == nil {
		err = fmt.Errorf("Must specify a callback function to handle retrieved data.")
		log.Errorln(err)
		return
	}
	err = s.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	defer s.TreeDisconnect(share)

	req, err := s.NewCreateReq(share, filepath,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		FAccMaskFileReadData|FAccMaskFileReadEA|FAccMaskFileReadAttributes|FAccMaskReadControl|FAccMaskSynchronize,
		0,
		FileShareRead|FileShareWrite,
		FileOpen,
		FileNonDirectoryFile,
	)

	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Errorln(err)
		s.Debug("Raw\n"+hex.Dump(buf), err)
		return err
	}

	if h.Status != StatusOk {
		err = fmt.Errorf("Failed to Create/open file/dir: " + StatusMap[h.Status])
		log.Errorln(err)
		return
	}

	var res CreateRes
	s.Debug("Unmarshalling Create response ["+share+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	f := &File{
		Connection: s,
		share:      share,
		filename:   filepath,
		shareid:    s.trees[share],
		fd:         res.FileId,
	}
	defer f.CloseFile()

	if res.EndOfFile == 0 {
		return
	}

	log.Debugln("Sending ReadFile requests")
	// Reading data in chunks of max 1KiB blocks as f.MaxReadSize seems to cause problems
	data := make([]byte, 1048576)
	fileSize := res.EndOfFile

	readOffset := offset
	for readOffset < fileSize {
		n, err := f.ReadFile(data, readOffset)
		if err != nil {
			if err == io.EOF {
				err = fmt.Errorf("Got EOF before finished reading")
				return err
			}
			log.Errorln(err)
			return err
		}
		nw, err := callback(data[:n])
		if err != nil {
			log.Errorln(err)
			return err
		} else if n != nw {
			err = fmt.Errorf("Failed to write all the data to callback")
			log.Errorln(err)
			return err
		}
		readOffset += uint64(n)
	}

	return err
}

func (f *File) ReadFile(b []byte, offset uint64) (n int, err error) {
	// Reading data in chunks of max 1KiB blocks as f.MaxReadSize seems to cause problems
	if len(b) > 1048576 {
		b = b[:1048576]
	}

	req, err := f.NewReadReq(f.share, f.fd,
		//f.MaxReadSize,
		uint32(len(b)),
		offset,
		1, // Read at least 1 byte
	)
	if err != nil {
		log.Errorln(err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		f.Debug("", err)
		return
	}

	log.Debugln("Reading response")
	var res ReadRes
	f.Debug("Unmarshalling Read response ["+f.share+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		f.Debug("Raw:\n"+hex.Dump(buf), err)
		return n, err
	}
	/*
	   Handle EOF:
	   MS-SMB2 Section 2.2.20 SMB2 READ Response
	   The minimum length is 1 byte. If 0 bytes are returned from the
	   underlying object store, the server MUST send a failure response with status equal to
	   STATUS_END_OF_FILE
	*/
	if res.Status == StatusEndOfFile {
		return 0, io.EOF
	}

	// An offset to indicate if the file data is the first thing
	// in the response buffer or if it begins later.
	bufferOffset := int(res.DataOffset - 64 - 16)
	if len(res.Buffer) < bufferOffset {
		err = fmt.Errorf("Returned offset is outside response buffer")
		log.Errorln(err)
		return
	}
	nCopy := copy(b, res.Buffer[bufferOffset:])
	n = int(res.DataLength)
	if nCopy != n {
		err = fmt.Errorf("Failed to copy result data into supplied buffer")
		log.Errorln(err)
		return
	}
	return
}

func (s *Connection) PutFile(share string, filepath string, offset uint64, callback func([]byte) (int, error)) (err error) {
	err = s.TreeConnect(share)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}
	defer s.TreeDisconnect(share)
	accessMask := FAccMaskFileReadData |
		FAccMaskFileWriteData |
		FAccMaskFileAppendData |
		FAccMaskFileReadEA |
		FAccMaskFileWriteEA |
		FAccMaskFileReadAttributes |
		FAccMaskFileWriteAttributes |
		FAccMaskReadControl |
		FAccMaskSynchronize

	req, err := s.NewCreateReq(share, filepath,
		OpLockLevelNone,
		ImpersonationLevelImpersonation,
		accessMask,
		0,
		FileShareRead|FileShareWrite,
		FileOverwriteIf,
		FileNonDirectoryFile,
	)

	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	buf, err := s.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		s.Debug("", err)
		return
	}

	var h Header
	if err := encoder.Unmarshal(buf, &h); err != nil {
		log.Errorln(err)
		s.Debug("Raw\n"+hex.Dump(buf), err)
		return err
	}

	if h.Status != StatusOk {
		err = fmt.Errorf("Failed to Create/open file/dir: " + StatusMap[h.Status])
		log.Errorln(err)
		return
	}

	var res CreateRes
	s.Debug("Unmarshalling Create response ["+share+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		s.Debug("Raw:\n"+hex.Dump(buf), err)
		return err
	}
	f := &File{
		Connection: s,
		filename:   filepath,
		fd:         res.FileId,
		share:      share,
		shareid:    s.trees[share],
	}
	defer f.CloseFile()

	log.Debugln("Sending WriteFile requests")
	// Writing data in chunks of max 1KiB blocks as f.MaxWriteSize seems to cause problems

	writeOffset := offset
	for {
		outBuffer := make([]byte, 1048576)
		nr, err := callback(outBuffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Errorln(err)
			return err
		}

		n, err := f.WriteFile(outBuffer[:nr], writeOffset)
		if err != nil {
			log.Errorln(err)
			return err
		}
		writeOffset += uint64(n)
	}

	return
}

func (f *File) WriteFile(data []byte, offset uint64) (n int, err error) {
	// Reading data in chunks of max 1KiB blocks as f.MaxReadSize seems to cause problems
	if len(data) > 1048576 { // 1KiB
		data = data[:1048576]
	}

	req, err := f.NewWriteReq(f.share, f.fd, offset, data)

	if err != nil {
		log.Errorln(err)
		f.Debug("", err)
		return
	}

	buf, err := f.sendrecv(req)
	if err != nil {
		log.Errorln(err)
		f.Debug("", err)
		return
	}

	var res WriteRes
	f.Debug("Unmarshalling Write response ["+f.share+"]", nil)
	if err := encoder.Unmarshal(buf, &res); err != nil {
		log.Errorln(err)
		f.Debug("Raw:\n"+hex.Dump(buf), err)
		return n, err
	}
	if res.Status != StatusOk {
		err = fmt.Errorf("Failed to write file with status code: %s\n", StatusMap[res.Status])
		log.Errorln(err)
		return
	}
	n = int(res.Count)
	return
}

func (s *Connection) WriteIoCtlReq(req *IoCtlReq) (res IoCtlRes, err error) {
	buf, err := s.sendrecv(req)
	if err != nil {
		s.Debug("", err)
		return res, err
	}
	var h Header
	if err = encoder.Unmarshal(buf[:64], &h); err != nil {
		s.Debug("", err)
		return res, err
	}

	if err = encoder.Unmarshal(buf, &res); err != nil {
		s.Debug("", err)
		fmt.Println("here1")
		return res, err
	}
	if res.MessageID != req.MessageID {
		return res, fmt.Errorf("Incorrect MessageID on response. Sent %d and received %d\n", req.MessageID, res.MessageID)
	}

	if res.Status != StatusOk {
		return res, fmt.Errorf("IoCtlRequest failed with status: %v\n", res.Status)
	}

	return res, nil
}

func (c *Connection) Close() {
	log.Debug("Closing session")
	for k := range c.trees {
		c.TreeDisconnect(k)
	}
	c.outstandingRequests.shutdown(nil)
	close(c.rdone)

	log.Debug("Closing TCP connection")
	c.conn.Close()
	log.Debug("Session close completed")
}
