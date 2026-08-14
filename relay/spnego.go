// MIT License
//
// Copyright (c) 2026 Jimmy Fjällid
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

package relay

import (
	"fmt"

	"github.com/jfjallid/gofork/encoding/asn1"

	"github.com/jfjallid/go-smb/gss"
)

// unwrapNegInit peels the inner NTLMSSP token out of an inbound SPNEGO
// NegTokenInit blob. Returns the inner MechToken and the parsed envelope (so
// callers may inspect MechTypes / MechTokenMIC).
func unwrapNegInit(blob []byte) (*gss.NegTokenInit, error) {
	if len(blob) == 0 || blob[0] != 0x60 {
		return nil, fmt.Errorf("not a NegTokenInit")
	}
	var init gss.NegTokenInit
	if err := init.UnmarshalBinary(blob); err != nil {
		return nil, fmt.Errorf("decode NegTokenInit: %w", err)
	}
	if len(init.Data.MechToken) == 0 {
		return nil, fmt.Errorf("NegTokenInit has empty MechToken")
	}
	return &init, nil
}

// unwrapNegResp peels the inner NTLMSSP token out of an inbound SPNEGO
// NegTokenResp blob. Returns the parsed response so callers may inspect
// MechListMIC / State as well as the ResponseToken.
func unwrapNegResp(blob []byte) (*gss.NegTokenResp, error) {
	if len(blob) == 0 || blob[0] != 0xa1 {
		return nil, fmt.Errorf("not a NegTokenResp")
	}
	var resp gss.NegTokenResp
	if err := resp.UnmarshalBinary(blob); err != nil {
		return nil, fmt.Errorf("decode NegTokenResp: %w", err)
	}
	if len(resp.ResponseToken) == 0 {
		return nil, fmt.Errorf("NegTokenResp has empty ResponseToken")
	}
	return &resp, nil
}

// wrapNegRespAcceptIncomplete wraps a raw NTLMSSP token (typically a CHALLENGE)
// into a SPNEGO NegTokenResp with State=accept-incomplete, MechType=NTLMSSP.
// Used by the SMB listener to hand a forwarder-supplied CHALLENGE back to the
// inbound client.
func wrapNegRespAcceptIncomplete(token []byte) ([]byte, error) {
	out := gss.NegTokenResp{
		State:         asn1.Enumerated(gss.GssStateAcceptIncomplete),
		SupportedMech: gss.NtLmSSPMechTypeOid,
		ResponseToken: token,
	}
	return out.MarshalBinary()
}

// wrapNegRespAuth wraps a raw NTLMSSP AUTHENTICATE token plus an optional
// MechListMIC into a SPNEGO NegTokenResp. State is omitted (the SMB client
// does not include a state on leg 2). Used by the SMB forwarder to re-wrap
// leg-2 bytes for the upstream's SendSessionSetup2WithBlob.
func wrapNegRespAuth(token, mic []byte) ([]byte, error) {
	out := gss.NegTokenResp{
		ResponseToken: token,
		MechListMIC:   mic,
	}
	return out.MarshalBinary()
}

// wrapNegRespAcceptCompleted produces a SPNEGO NegTokenResp with
// State=accept-completed, no SupportedMech, no ResponseToken, and an
// optional MechListMIC. Used by the fake-server handoff to answer the
// victim's SessionSetup2 leg with a successful SPNEGO completion.
func wrapNegRespAcceptCompleted(mic []byte) ([]byte, error) {
	out := gss.NegTokenResp{
		State:       asn1.Enumerated(gss.GssStateAcceptCompleted),
		MechListMIC: mic,
	}
	return out.MarshalBinary()
}
