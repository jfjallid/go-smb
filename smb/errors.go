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

package smb

import (
	"errors"
	"fmt"
)

// ErrShareRequiresEncryption is returned by TreeConnect when the server marks a
// share SMB2_SHAREFLAG_ENCRYPT_DATA but the connection did not negotiate
// encryption end-to-end (e.g. the client set DisableEncryption, so the server
// derived no decrypter). Per MS-SMB2 §3.2.5.5 the client MUST fail the tree
// connect rather than send traffic the server cannot decrypt.
var ErrShareRequiresEncryption = errors.New("share requires encryption but the connection negotiated none")

// NTStatusError represents a non-success NTSTATUS in an SMB2 response
// header. Status always preserves the raw NTSTATUS, also when no sentinel
// mapping exists. Err holds the mapped sentinel from StatusMap (nil when
// unmapped) and is exposed via Unwrap so callers can match with errors.Is,
// e.g.:
//
//	errors.Is(err, smb.StatusMap[smb.StatusAccessDenied])
type NTStatusError struct {
	Op     string // SMB operation, e.g. "TreeConnect", "IoCtlRequest"
	Status uint32 // raw NTSTATUS as received
	Err    error  // mapped sentinel from StatusMap, or nil when unmapped
}

func (e *NTStatusError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s: unknown NTSTATUS 0x%08x", e.Op, e.Status)
}

func (e *NTStatusError) Unwrap() error { return e.Err }

// statusError converts an NTSTATUS to an error where StatusOk maps to nil.
// okStatuses lists additional codes treated as success by the caller.
func statusError(op string, status uint32, okStatuses ...uint32) error {
	if status == StatusOk {
		return nil
	}
	for _, ok := range okStatuses {
		if status == ok {
			return nil
		}
	}
	return &NTStatusError{Op: op, Status: status, Err: StatusMap[status]}
}
