// MIT License
//
// # Copyright (c) 2025 Jimmy Fjällid
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

package mslsad

import (
	"fmt"
	"github.com/jfjallid/mstypes"
)

// MS-LSAT Operations
const (
	LsarGetUserName  uint16 = 45
	LsarLookupSids2  uint16 = 57
	LsarLookupNames3 uint16 = 68
)

// MS-LSAT Section 2.2.13 SID_NAME_USE
type SidNameUse uint32

const (
	SidTypeUser SidNameUse = iota + 1
	SidTypeGroup
	SidTypeDomain
	SidTypeAlias
	SidTypeWellKnownGroup
	SidTypeDeletedAccount
	SidTypeInvalid
	SidTypeUnknown
	SidTypeComputer
	SidTypeLabel
)

var SidNameUseMap = map[SidNameUse]string{
	SidTypeUser:           "SidTypeUser",
	SidTypeGroup:          "SidTypeGroup",
	SidTypeDomain:         "SidTypeDomain",
	SidTypeAlias:          "SidTypeAlias",
	SidTypeWellKnownGroup: "SidTypeWellKnownGroup",
	SidTypeDeletedAccount: "SidTypeDeletedAccount",
	SidTypeInvalid:        "SidTypeInvalid",
	SidTypeUnknown:        "SidTypeUnknown",
	SidTypeComputer:       "SidTypeComputer",
	SidTypeLabel:          "SidTypeLabel",
}

// MS-LSAT Section 2.2.16 LSAP_LOOKUP_LEVEL
type LsapLookupLevel uint32

const (
	LsapLookupWksta LsapLookupLevel = iota + 1
	LsapLookupPDC
	LsapLookupTDL
	LsapLookupGC
	LsapLookupXForestReferral
	LsapLookupXForestResolve
	LsapLookupRODCReferralToFullDC
)

func (sb *RPCCon) LsarGetUserName() (username, domain string, err error) {
	log.Traceln("In LsarGetUserName")

	innerReq := LsarGetUserNameReq{
		SystemName: "",
		UserName:   &mstypes.PRPCUnicodeString{},
		DomainName: &mstypes.PRPCUnicodeString{},
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(LsarGetUserName, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 12 {
		return "", "", fmt.Errorf("server response to LsarGetUserName was too small, expected at least 12 bytes")
	}

	resp := LsarGetUserNameRes{
		UserName:   &mstypes.PRPCUnicodeString{Data: &mstypes.RPCUnicodeString{}},
		DomainName: &mstypes.PRPCUnicodeString{Data: &mstypes.RPCUnicodeString{}},
	}
	err = resp.Unmarshal(buffer)
	if err != nil {
		return
	}
	if err = checkReturnCode("LsarGetUserName", resp.ReturnCode); err != nil {
		return
	}
	username = resp.UserName.Data.String()
	domain = resp.DomainName.Data.String()

	return
}

func (sb *RPCCon) LsarLookupSids2(level LsapLookupLevel, sids []string) (res SidTranslations, err error) {
	log.Traceln("In LsarLookupSids2")
	if len(sids) == 0 {
		err = fmt.Errorf("LsarLookupSids2: must specify at least one SID to lookup")
		return
	}

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	//TODO Should client open the policy handle or open it here?
	var sidList []LsaprSidInformation
	var sid *mstypes.RPCSID
	for _, sidStr := range sids {
		sid, err = mstypes.ConvertStrToSID(sidStr)
		if err != nil {
			return
		}
		sidList = append(sidList, LsaprSidInformation{Sid: *sid})
	}

	innerReq := LsarLookupSids2Req{
		PolicyHandle: policyHandle,
		SidEnumBuffer: LsaprSidEnumBuffer{
			Entries: uint32(len(sidList)),
			SidInfo: sidList,
		},
		TranslatedNames: LsaprTranslatedNamesEx{},
		LookupLevel:     level,
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(LsarLookupSids2, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 36 {
		return SidTranslations{}, fmt.Errorf("server response to LsarLookupSids2 was too small, expected at least 36 bytes")
	}

	resp := LsarLookupSids2Res{}
	err = resp.Unmarshal(buffer)
	if err != nil {
		return
	}

	if resp.MappedCount > 0 {
		for _, item := range resp.ReferencedDomains.Domains {
			res.ReferencedDomains = append(res.ReferencedDomains, DomainTranslation{Name: item.Name.Value, Sid: item.Sid.String()})
		}
		for i, item := range resp.TranslatedNames.Names {
			res.TranslatedNames = append(res.TranslatedNames, SidNameTranslation{Use: item.Use, Name: item.Name.Value, Sid: sids[i], DomainIndex: item.DomainIndex, Flags: item.Flags})
		}
	}
	res.ReturnCode = resp.ReturnCode
	// STATUS_SUCCESS and STATUS_SOME_NOT_MAPPED both indicate that the translations
	// in res are valid (the latter signalling a partial mapping). Anything else is
	// a real failure and must be surfaced as an error.
	if err = checkReturnCode("LsarLookupSids2", resp.ReturnCode, StatusSomeNotMapped); err != nil {
		return
	}
	return
}

func (sb *RPCCon) LsarLookupNames3(level LsapLookupLevel, names []string) (res NameTranslations, err error) {
	log.Traceln("In LsarLookupNames3")
	if len(names) == 0 {
		err = fmt.Errorf("LsarLookupNames3: must specify at least one name to lookup")
		return
	}

	policyHandle, err := sb.LsarOpenPolicy2("")
	if err != nil {
		return
	}
	defer sb.LsarCloseHandle(policyHandle)
	//TODO Should client open the policy handle or open it here?
	var nameList []mstypes.RPCUnicodeString
	for _, name := range names {
		nameList = append(nameList, mstypes.RPCUnicodeString{Length: uint16(len(name) * 2), MaximumLength: uint16(len(name) * 2), Value: name})
	}

	innerReq := LsarLookupNames3Req{
		PolicyHandle:   policyHandle,
		Count:          uint32(len(names)),
		Names:          nameList,
		TranslatedSids: LsaprTranslatedSidsEx2{},
		LookupLevel:    level,
	}

	innerBuf, err := innerReq.Marshal()
	if err != nil {
		return
	}

	buffer, err := sb.MakeRequest(LsarLookupNames3, innerBuf)
	if err != nil {
		return
	}

	if len(buffer) < 20 {
		return NameTranslations{}, fmt.Errorf("server response to LsarLookupNames3 was too small, expected at least 20 bytes")
	}

	resp := LsarLookupNames3Res{}
	err = resp.Unmarshal(buffer)
	if err != nil {
		return
	}

	if resp.MappedCount > 0 {
		for _, item := range resp.ReferencedDomains.Domains {
			res.ReferencedDomains = append(res.ReferencedDomains, DomainTranslation{Name: item.Name.Value, Sid: item.Sid.String()})
		}
		for i, item := range resp.TranslatedSids.Sids {
			res.TranslatedSids = append(res.TranslatedSids, SidNameTranslation{Use: item.Use, Name: names[i], Sid: item.Sid.String(), DomainIndex: item.DomainIndex, Flags: item.Flags})
		}
	}
	res.ReturnCode = resp.ReturnCode
	if err = checkReturnCode("LsarLookupNames3", resp.ReturnCode, StatusSomeNotMapped); err != nil {
		return
	}
	return
}
