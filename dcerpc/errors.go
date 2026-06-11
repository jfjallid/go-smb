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

package dcerpc

import (
	"errors"
	"fmt"
)

// Sentinel errors for the DCERPC Fault status codes recognised by this
// package. Match them with errors.Is against a *FaultError, e.g.:
//
//	if errors.Is(err, dcerpc.ErrAccessDenied) { ... }
var (
	ErrAccessDenied    = errors.New("access denied")
	ErrContextMismatch = errors.New("context mismatch")
)

// faultStatusMap maps a DCERPC Fault PDU status code to its sentinel error.
// A code absent from the map is preserved verbatim in FaultError.Code and
// surfaces via the "unknown fault status" message.
var faultStatusMap = map[uint32]error{
	ErrorAccessDenied:    ErrAccessDenied,
	ErrorContextMismatch: ErrContextMismatch,
}

// FaultError represents a DCERPC Fault PDU received in response to a request.
// Code always preserves the raw fault status, also when no sentinel mapping
// exists. Err holds the mapped sentinel from faultStatusMap (nil when
// unmapped) and is exposed via Unwrap so callers can match with errors.Is:
//
//	errors.Is(err, dcerpc.ErrAccessDenied)
type FaultError struct {
	Code uint32 // raw fault status as received
	Err  error  // mapped sentinel, or nil when unmapped
}

func (e *FaultError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("DCERPC fault: %v (0x%08x)", e.Err, e.Code)
	}
	return fmt.Sprintf("DCERPC fault: unknown status 0x%08x", e.Code)
}

func (e *FaultError) Unwrap() error { return e.Err }

// newFaultError builds a FaultError, mapping code to its sentinel when known.
func newFaultError(code uint32) *FaultError {
	return &FaultError{Code: code, Err: faultStatusMap[code]}
}

// StatusError represents a non-zero return code from a DCERPC operation.
// Code always preserves the raw value, also when no sentinel mapping
// exists. Err holds the mapped sentinel from the service package's
// response-code map (nil when unmapped) and is exposed via Unwrap so
// callers can match with errors.Is, e.g.:
//
//	errors.Is(err, mssamr.ResponseCodeMap[mssamr.StatusNoSuchGroup])
type StatusError struct {
	Op   string // RPC operation, e.g. "SamrConnect5"
	Code uint32 // raw return code as received
	Err  error  // mapped sentinel, or nil when unmapped
}

func (e *StatusError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("%s: unknown return code 0x%08x", e.Op, e.Code)
}

func (e *StatusError) Unwrap() error { return e.Err }
