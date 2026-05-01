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

package ldap

import (
	"errors"
	"fmt"

	goldap "github.com/jfjallid/ldap/v3"
)

// BindFailureKind classifies a bind rejection by the AD policy or condition
// that caused it. Aliased from the underlying ldap package so callers don't
// need to import jfjallid/ldap/v3 to switch on Kind.
type BindFailureKind = goldap.BindFailureKind

const (
	BindFailureUnclassified            BindFailureKind = goldap.BindFailureUnclassified
	BindFailureChannelBinding          BindFailureKind = goldap.BindFailureChannelBinding
	BindFailureSigning                 BindFailureKind = goldap.BindFailureSigning
	BindFailureConfidentialityRequired BindFailureKind = goldap.BindFailureConfidentialityRequired
	BindFailureCredentials             BindFailureKind = goldap.BindFailureCredentials
)

// AD substatus codes carried in BindError.SubStatus when Kind is
// BindFailureCredentials. Re-exported so callers can branch (e.g. distinguish
// "account locked" from "wrong password") without importing the underlying
// ldap package.
const (
	SubStatusBadBindings         = goldap.SubStatusBadBindings
	SubStatusInvalidToken        = goldap.SubStatusInvalidToken
	SubStatusTargetUnknown       = goldap.SubStatusTargetUnknown
	SubStatusLogonDenied         = goldap.SubStatusLogonDenied
	SubStatusUserNotFound        = goldap.SubStatusUserNotFound
	SubStatusInvalidCredentials  = goldap.SubStatusInvalidCredentials
	SubStatusNotPermittedToLogon = goldap.SubStatusNotPermittedToLogon
	SubStatusPasswordExpired     = goldap.SubStatusPasswordExpired
	SubStatusAccountDisabled     = goldap.SubStatusAccountDisabled
	SubStatusAccountExpired      = goldap.SubStatusAccountExpired
	SubStatusMustResetPassword   = goldap.SubStatusMustResetPassword
	SubStatusAccountLocked       = goldap.SubStatusAccountLocked
)

var SubStatusMap = map[uint32]string {
	SubStatusBadBindings         : "bad channel bindings",
	SubStatusInvalidToken        : "invalid token",
	SubStatusTargetUnknown       : "target unknown",
	SubStatusLogonDenied         : "logon denied",
	SubStatusUserNotFound        : "user not found",
	SubStatusInvalidCredentials  : "invalid credentials",
	SubStatusNotPermittedToLogon : "not permitted to logon",
	SubStatusPasswordExpired     : "password expired",
	SubStatusAccountDisabled     : "account disabled",
	SubStatusAccountExpired      : "account expired",
	SubStatusMustResetPassword   : "must reset password",
	SubStatusAccountLocked       : "account locked",
}

// BindError is returned by Client.Bind when the underlying LDAP bind fails.
// Inspect Kind via errors.AsType to decide whether to retry with different
// options:
//
//  if be, found := errors.AsType[*ldap.BindError](err); found {
//	    switch be.Kind {
//	    case ldap.BindFailureChannelBinding:
//	        // retry with BindOptions.ChannelBinding = true (over TLS)
//	    case ldap.BindFailureSigning:
//	        // retry with BindOptions.SASLMode = SASLSign or SASLSeal
//	    case ldap.BindFailureConfidentialityRequired:
//	        // retry with ClientOptions.UseTLS or UseStartTLS
//	    case ldap.BindFailureCredentials:
//	        // be.SubStatus may carry the AD reason (locked, expired, ...)
//	    }
//	}
//
// Kind is BindFailureUnclassified for non-AD servers or rejections that don't
// match a known signal; in that case Error() prints the raw underlying error.
type BindError struct {
	Kind BindFailureKind
	// SubStatus is the AD "data <hex>" substatus extracted from the
	// diagnosticMessage. Non-zero only when Kind == BindFailureCredentials
	// and the server provided a recognisable substatus.
	SubStatus uint32
	// Description is a human-readable description for known SubStatus
	// values (e.g. "account locked"); empty when SubStatus is unknown.
	Description string
	// OverTLS records whether the failed bind was attempted over a TLS or
	// StartTLS connection. Captured here so callers retrying with
	// different options don't have to remember which connection state
	// produced this error.
	OverTLS bool
	// Err is the raw error returned by the underlying ldap bind.
	Err error
}

func (e *BindError) Error() string {
	switch e.Kind {
	case BindFailureChannelBinding:
		if e.OverTLS {
			return fmt.Sprintf("server requires LDAP channel binding (retry with ChannelBinding=true): %v", e.Err)
		}
		return fmt.Sprintf("server rejected the channel binding token (SEC_E_BAD_BINDINGS): %v", e.Err)
	case BindFailureSigning:
		return fmt.Sprintf("server requires LDAP signing (retry with SASLMode=SASLSign or SASLSeal, or use TLS): %v", e.Err)
	case BindFailureConfidentialityRequired:
		return fmt.Sprintf("server requires a confidential connection (retry with TLS or StartTLS): %v", e.Err)
	case BindFailureCredentials:
		if e.Description != "" {
			return fmt.Sprintf("ldap bind rejected: %s: %v", e.Description, e.Err)
		}
		return fmt.Sprintf("ldap bind rejected (invalid credentials): %v", e.Err)
	default:
		return fmt.Sprintf("ldap bind failed: %v", e.Err)
	}
}

func (e *BindError) Unwrap() error { return e.Err }

// IsChannelBindingRequired reports whether err (or any error wrapped by it)
// is a *BindError indicating the server enforces LDAP channel binding.
func IsChannelBindingRequired(err error) bool {
	var be *BindError
	return errors.As(err, &be) && be.Kind == BindFailureChannelBinding
}

// IsSigningRequired reports whether err is a *BindError indicating the
// server enforces LDAP signing on plaintext binds.
func IsSigningRequired(err error) bool {
	var be *BindError
	return errors.As(err, &be) && be.Kind == BindFailureSigning
}

// IsConfidentialityRequired reports whether err is a *BindError indicating
// the server requires a confidential (TLS) connection.
func IsConfidentialityRequired(err error) bool {
	var be *BindError
	return errors.As(err, &be) && be.Kind == BindFailureConfidentialityRequired
}

// IsInvalidCredentials reports whether err is a *BindError caused by an AD
// LDAPResult 49 (InvalidCredentials) rejection. The specific reason — wrong
// password, account locked, password expired, etc. — is in BindError.SubStatus.
func IsInvalidCredentials(err error) bool {
	var be *BindError
	return errors.As(err, &be) && be.Kind == BindFailureCredentials
}
