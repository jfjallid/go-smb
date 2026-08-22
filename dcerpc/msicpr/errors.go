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

package msicpr

import (
	"errors"

	"github.com/jfjallid/go-smb/dcerpc"
)

// Return codes a CA can put in the trailing status word of a call. The
// enrollment interfaces return a Win32 error over ICPR and the same condition
// as an HRESULT over DCOM, so the two spellings of the generic failures are
// both listed; everything in the CERTSRV_E_* range is HRESULT-only.
const (
	ErrorSuccess          uint32 = 0x0  // ERROR_SUCCESS
	ErrorAccessDenied     uint32 = 0x5  // ERROR_ACCESS_DENIED (Win32, over ICPR)
	ErrorInvalidParameter uint32 = 0x57 // ERROR_INVALID_PARAMETER

	EAccessDenied uint32 = 0x80070005 // E_ACCESSDENIED (HRESULT, over DCOM)
	EInvalidArg   uint32 = 0x80070057 // E_INVALIDARG
)

// CERTSRV_E_* return codes (winerror.h). These name the reason a CA refused an
// enrollment or an administrative change, which is the difference between a
// misconfigured request and a permission the caller does not hold.
const (
	CertSrvBadRequestSubject            uint32 = 0x80094001 // CERTSRV_E_BAD_REQUESTSUBJECT
	CertSrvNoRequest                    uint32 = 0x80094002 // CERTSRV_E_NO_REQUEST
	CertSrvBadRequestStatus             uint32 = 0x80094003 // CERTSRV_E_BAD_REQUESTSTATUS
	CertSrvPropertyEmpty                uint32 = 0x80094004 // CERTSRV_E_PROPERTY_EMPTY
	CertSrvInvalidCACertificate         uint32 = 0x80094005 // CERTSRV_E_INVALID_CA_CERTIFICATE
	CertSrvServerSuspended              uint32 = 0x80094006 // CERTSRV_E_SERVER_SUSPENDED
	CertSrvEncodingLength               uint32 = 0x80094007 // CERTSRV_E_ENCODING_LENGTH
	CertSrvRoleConflict                 uint32 = 0x80094008 // CERTSRV_E_ROLECONFLICT
	CertSrvRestrictedOfficer            uint32 = 0x80094009 // CERTSRV_E_RESTRICTEDOFFICER
	CertSrvKeyArchivalNotConfigured     uint32 = 0x8009400A // CERTSRV_E_KEY_ARCHIVAL_NOT_CONFIGURED
	CertSrvNoValidKRA                   uint32 = 0x8009400B // CERTSRV_E_NO_VALID_KRA
	CertSrvBadRequestKeyArchival        uint32 = 0x8009400C // CERTSRV_E_BAD_REQUEST_KEY_ARCHIVAL
	CertSrvNoCAAdminDefined             uint32 = 0x8009400D // CERTSRV_E_NO_CAADMIN_DEFINED
	CertSrvBadRenewalCertAttribute      uint32 = 0x8009400E // CERTSRV_E_BAD_RENEWAL_CERT_ATTRIBUTE
	CertSrvNoDBSessions                 uint32 = 0x8009400F // CERTSRV_E_NO_DB_SESSIONS
	CertSrvAlignmentFault               uint32 = 0x80094010 // CERTSRV_E_ALIGNMENT_FAULT
	CertSrvEnrollDenied                 uint32 = 0x80094011 // CERTSRV_E_ENROLL_DENIED
	CertSrvTemplateDenied               uint32 = 0x80094012 // CERTSRV_E_TEMPLATE_DENIED
	CertSrvDownlevelDCSSLOrUpgrade      uint32 = 0x80094013 // CERTSRV_E_DOWNLEVEL_DC_SSL_OR_UPGRADE
	CertSrvUnsupportedCertType          uint32 = 0x80094800 // CERTSRV_E_UNSUPPORTED_CERT_TYPE
	CertSrvNoCertType                   uint32 = 0x80094801 // CERTSRV_E_NO_CERT_TYPE
	CertSrvTemplateConflict             uint32 = 0x80094802 // CERTSRV_E_TEMPLATE_CONFLICT
	CertSrvSubjectAltNameRequired       uint32 = 0x80094803 // CERTSRV_E_SUBJECT_ALT_NAME_REQUIRED
	CertSrvArchivedKeyRequired          uint32 = 0x80094804 // CERTSRV_E_ARCHIVED_KEY_REQUIRED
	CertSrvSMIMERequired                uint32 = 0x80094805 // CERTSRV_E_SMIME_REQUIRED
	CertSrvBadRenewalSubject            uint32 = 0x80094806 // CERTSRV_E_BAD_RENEWAL_SUBJECT
	CertSrvBadTemplateVersion           uint32 = 0x80094807 // CERTSRV_E_BAD_TEMPLATE_VERSION
	CertSrvTemplatePolicyRequired       uint32 = 0x80094808 // CERTSRV_E_TEMPLATE_POLICY_REQUIRED
	CertSrvSignaturePolicyRequired      uint32 = 0x80094809 // CERTSRV_E_SIGNATURE_POLICY_REQUIRED
	CertSrvSignatureCount               uint32 = 0x8009480A // CERTSRV_E_SIGNATURE_COUNT
	CertSrvSignatureRejected            uint32 = 0x8009480B // CERTSRV_E_SIGNATURE_REJECTED
	CertSrvIssuancePolicyRequired       uint32 = 0x8009480C // CERTSRV_E_ISSUANCE_POLICY_REQUIRED
	CertSrvSubjectUPNRequired           uint32 = 0x8009480D // CERTSRV_E_SUBJECT_UPN_REQUIRED
	CertSrvSubjectDirectoryGUIDRequired uint32 = 0x8009480E // CERTSRV_E_SUBJECT_DIRECTORY_GUID_REQUIRED
	CertSrvSubjectDNSRequired           uint32 = 0x8009480F // CERTSRV_E_SUBJECT_DNS_REQUIRED
	CertSrvArchivedKeyUnexpected        uint32 = 0x80094810 // CERTSRV_E_ARCHIVED_KEY_UNEXPECTED
	CertSrvKeyLength                    uint32 = 0x80094811 // CERTSRV_E_KEY_LENGTH
	CertSrvSubjectEmailRequired         uint32 = 0x80094812 // CERTSRV_E_SUBJECT_EMAIL_REQUIRED
	CertSrvUnknownCertType              uint32 = 0x80094813 // CERTSRV_E_UNKNOWN_CERT_TYPE
	CertSrvCertTypeOverlap              uint32 = 0x80094814 // CERTSRV_E_CERT_TYPE_OVERLAP
	CertSrvTooManySignatures            uint32 = 0x80094815 // CERTSRV_E_TOO_MANY_SIGNATURES
	CertSrvRenewalBadPublicKey          uint32 = 0x80094816 // CERTSRV_E_RENEWAL_BAD_PUBLIC_KEY
	CertSrvInvalidEK                    uint32 = 0x80094817 // CERTSRV_E_INVALID_EK
	CertSrvKeyAttestation               uint32 = 0x8009481A // CERTSRV_E_KEY_ATTESTATION
)

// ResponseCodeMap maps a return code to a sentinel error, so callers can match
// a specific condition with errors.Is, e.g.:
//
//	errors.Is(err, msicpr.ResponseCodeMap[msicpr.CertSrvTemplateDenied])
//
// A code with no entry here still reaches the caller as the raw Code on the
// *dcerpc.StatusError.
var ResponseCodeMap = map[uint32]error{
	ErrorAccessDenied:     errors.New("Access is denied"),
	ErrorInvalidParameter: errors.New("One of the function parameters is not valid"),
	EAccessDenied:         errors.New("Access is denied"),
	EInvalidArg:           errors.New("One or more arguments are invalid"),

	CertSrvBadRequestSubject:            errors.New("The request subject name is invalid or too long"),
	CertSrvNoRequest:                    errors.New("The request does not exist"),
	CertSrvBadRequestStatus:             errors.New("The request's current status does not allow this operation"),
	CertSrvPropertyEmpty:                errors.New("The requested property value is empty"),
	CertSrvInvalidCACertificate:         errors.New("The CA's certificate contains invalid data"),
	CertSrvServerSuspended:              errors.New("Certificate service has been suspended for a database restore operation"),
	CertSrvEncodingLength:               errors.New("The certificate contains an encoded length that is potentially incompatible with older enrollment software"),
	CertSrvRoleConflict:                 errors.New("The operation is denied. The user has multiple roles assigned, and the CA is configured to enforce role separation"),
	CertSrvRestrictedOfficer:            errors.New("The operation is denied. It can only be performed by a certificate manager that is allowed to manage certificates for the current requester"),
	CertSrvKeyArchivalNotConfigured:     errors.New("Cannot archive private key. The CA is not configured for key archival"),
	CertSrvNoValidKRA:                   errors.New("Cannot archive private key. The CA could not verify one or more key recovery certificates"),
	CertSrvBadRequestKeyArchival:        errors.New("The request is incorrectly formatted. The encrypted private key must be in an unauthenticated attribute in an outermost signature"),
	CertSrvNoCAAdminDefined:             errors.New("At least one security principal must have the permission to manage this CA"),
	CertSrvBadRenewalCertAttribute:      errors.New("The request contains an invalid renewal certificate attribute"),
	CertSrvNoDBSessions:                 errors.New("An attempt was made to open a CA database session, but there are already too many active sessions. The server may need to be configured to allow additional sessions"),
	CertSrvAlignmentFault:               errors.New("A memory reference caused a data alignment fault"),
	CertSrvEnrollDenied:                 errors.New("The permissions on this CA do not allow the current user to enroll for certificates"),
	CertSrvTemplateDenied:               errors.New("The permissions on the certificate template do not allow the current user to enroll for this type of certificate"),
	CertSrvDownlevelDCSSLOrUpgrade:      errors.New("The contacted domain controller cannot support signed Lightweight Directory Access Protocol (LDAP) traffic. Update the domain controller or configure Certificate Services to use SSL for Active Directory access"),
	CertSrvUnsupportedCertType:          errors.New("The requested certificate template is not supported by this CA"),
	CertSrvNoCertType:                   errors.New("The request contains no certificate template information"),
	CertSrvTemplateConflict:             errors.New("The request contains conflicting template information"),
	CertSrvSubjectAltNameRequired:       errors.New("The request is missing a required Subject Alternate name extension"),
	CertSrvArchivedKeyRequired:          errors.New("The request is missing a required private key for archival by the server"),
	CertSrvSMIMERequired:                errors.New("The request is missing a required SMIME capabilities extension"),
	CertSrvBadRenewalSubject:            errors.New("The request was made on behalf of a subject other than the caller. The certificate template must be configured to require at least one signature to authorize the request"),
	CertSrvBadTemplateVersion:           errors.New("The request template version is newer than the supported template version"),
	CertSrvTemplatePolicyRequired:       errors.New("The template is missing a required signature policy attribute"),
	CertSrvSignaturePolicyRequired:      errors.New("The request is missing required signature policy information"),
	CertSrvSignatureCount:               errors.New("The request is missing one or more required signatures"),
	CertSrvSignatureRejected:            errors.New("One or more signatures did not include the required application or issuance policies. The request is missing one or more required valid signatures"),
	CertSrvIssuancePolicyRequired:       errors.New("The request is missing one or more required signature issuance policies"),
	CertSrvSubjectUPNRequired:           errors.New("The UPN is unavailable and cannot be added to the Subject Alternate name"),
	CertSrvSubjectDirectoryGUIDRequired: errors.New("The Active Directory GUID is unavailable and cannot be added to the Subject Alternate name"),
	CertSrvSubjectDNSRequired:           errors.New("The Domain Name System (DNS) name is unavailable and cannot be added to the Subject Alternate name"),
	CertSrvArchivedKeyUnexpected:        errors.New("The request includes a private key for archival by the server, but key archival is not enabled for the specified certificate template"),
	CertSrvKeyLength:                    errors.New("The public key does not meet the minimum size required by the specified certificate template"),
	CertSrvSubjectEmailRequired:         errors.New("The email name is unavailable and cannot be added to the Subject or Subject Alternate name"),
	CertSrvUnknownCertType:              errors.New("One or more certificate templates to be enabled on this CA could not be found"),
	CertSrvCertTypeOverlap:              errors.New("The certificate template renewal period is longer than the certificate validity period. The template should be reconfigured or the CA certificate renewed"),
	CertSrvTooManySignatures:            errors.New("The certificate template requires too many return authorization (RA) signatures. Only one RA signature is allowed"),
	CertSrvRenewalBadPublicKey:          errors.New("The key used in a renewal request does not match one of the certificates being renewed"),
	CertSrvInvalidEK:                    errors.New("The endorsement key certificate is not valid"),
	CertSrvKeyAttestation:               errors.New("Key attestation did not succeed"),
}

// checkReturnCode maps a non-zero CA return code to a *dcerpc.StatusError
// carrying op, the raw code, and the mapped sentinel from ResponseCodeMap
// (nil when unmapped).
func checkReturnCode(op string, code uint32) error {
	if code == ErrorSuccess {
		return nil
	}
	return &dcerpc.StatusError{Op: op, Code: code, Err: ResponseCodeMap[code]}
}
