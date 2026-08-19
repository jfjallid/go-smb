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
package msdtyp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

func FromUnicodeString(buf []byte) (res string, err error) {
	buflen := len(buf)
	if (buflen % 2) != 0 {
		err = fmt.Errorf("invalid unicode (UTF-16-LE) string")
		return
	}

	s := make([]uint16, buflen/2)
	err = binary.Read(bytes.NewReader(buf), le, &s)
	if err != nil {
		return
	}
	return string(utf16.Decode(s)), nil
}

func FromUnicode(buf []byte) ([]byte, error) {
	s, err := FromUnicodeString(buf)
	return []byte(s), err
}

func ToUnicode(input string) []byte {
	codePoints := utf16.Encode([]rune(input))
	b := bytes.Buffer{}
	binary.Write(&b, le, &codePoints)
	return b.Bytes()
}

// Return the values needed to encode a unicode string according to NDR (except for the Ptrs and MaxCount which has to be added manually)
func NewUnicodeStr(s string, addNullByte bool) (offset uint32, actualCount uint32, paddlen int, buffer []byte) {
	if addNullByte {
		s = NullTerminate(s)
	}
	buffer = ToUnicode(s)
	actualCount = uint32(len(buffer) / 2)
	offset = 0
	paddlen = (len(buffer) % 4) //Got to be 4 byte aligned
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}
	return
}

func NullTerminate(s string) string {
	if s == "" {
		s = "\x00"
	} else if s[len(s)-1] != 0x00 {
		return s + "\x00"
	}
	return s
}

func StripNullByte(s string) string {
	if s == "" {
		return ""
	}
	if s[len(s)-1] == 0x00 {
		return s[:len(s)-1]
	}
	return s
}

// Borrowed from NDR but modified to support edge case where the unicode string is NOT terminated
// with a null byte
func ReadConformantVaryingString(r *bytes.Reader, nullTerminated bool) (s string, err error) {
	// Read the Max count
	var maxCount uint32
	err = binary.Read(r, le, &maxCount)
	if err != nil {
		return
	}

	// Read the offset
	var offset uint32
	err = binary.Read(r, le, &offset)
	if err != nil {
		return
	}
	// Read the Actual count
	var actualCount uint32
	err = binary.Read(r, le, &actualCount)
	if err != nil {
		return
	}
	if offset > 0 {
		_, err = r.Seek(int64(offset), io.SeekCurrent)
		if err != nil {
			return
		}
	}

	if actualCount > 0 {
		// actualCount is server-controlled; guard the *2 against uint32 overflow
		// and refuse a count larger than the remaining buffer before allocating, so
		// a bogus value can't trigger a multi-GB makeslice panic / OOM.
		if uint64(actualCount)*2 > uint64(r.Len()) {
			err = fmt.Errorf("ReadConformantVaryingString: actual count %d exceeds remaining buffer (%d bytes)", actualCount, r.Len())
			return
		}
		// Read the unicode string
		unc := make([]byte, actualCount*2)
		err = binary.Read(r, le, unc)
		if err != nil {
			return
		}

		// Edge case
		if nullTerminated {
			// Check for terminating null byte
			lastIndex := len(unc) - 2
			if bytes.Equal(unc[lastIndex:], []byte{0, 0}) {
				unc = unc[:lastIndex]
			}
		}

		s, err = FromUnicodeString(unc)
		if err != nil {
			return
		}
	}

	paddLen := 4 - ((offset + actualCount*2) % 4)

	if paddLen != 4 {
		_, err = r.Seek(int64(paddLen), io.SeekCurrent)
		if err != nil {
			return
		}
	}
	return
}

func ReadConformantVaryingStringPtr(r *bytes.Reader, nullTerminated bool) (s string, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		return
	}
	return ReadConformantVaryingString(r, nullTerminated)
}

// Borrowed from NDR but modified to support edge case where the unicode string is NOT terminated
// with a null byte
// Write a conformant and varying string to the output stream
func WriteConformantVaryingString(w io.Writer, s string, addNullByte bool) (n int, err error) {
	offset, count, paddlen, buffer := NewUnicodeStr(s, addNullByte)
	maxCount := count
	err = binary.Write(w, le, maxCount) // MaxCount
	if err != nil {
		return
	}
	n += 4
	err = binary.Write(w, le, offset)
	if err != nil {
		return
	}
	n += 4
	err = binary.Write(w, le, count)
	if err != nil {
		return
	}
	n += 4
	_, err = w.Write(buffer)
	if err != nil {
		return
	}
	n += len(buffer)
	padd := make([]byte, paddlen)
	_, err = w.Write(padd)
	if err != nil {
		return
	}
	n += paddlen
	return
}

// Write a ptr to a conformant and varying string to the output stream
func WriteConformantVaryingStringPtr(w io.Writer, s string, refid *uint32, addNullByte bool) (n int, err error) {
	var n2 int

	if s == "" {
		// Empty strings are represented as a NULL Ptr
		n, err = w.Write([]byte{0, 0, 0, 0})
		return
	}
	if *refid != 0 {
		err = binary.Write(w, le, *refid)
		if err != nil {
			return
		}
		*refid++
		n = 4
	}
	n2, err = WriteConformantVaryingString(w, s, addNullByte)
	n += n2
	return
}

// If maxCount is 0, use length of buf
func WriteConformantVaryingArray(w io.Writer, buf []byte, maxCount uint32) (n int, err error) {
	actualCount := uint32(len(buf))
	if maxCount == 0 {
		maxCount = actualCount
	}
	err = binary.Write(w, le, maxCount)
	if err != nil {
		return
	}
	n += 4

	err = binary.Write(w, le, uint32(0)) // Offset
	if err != nil {
		return
	}
	n += 4

	err = binary.Write(w, le, actualCount)
	if err != nil {
		return
	}
	n += 4

	_, err = w.Write(buf)
	if err != nil {
		return
	}
	n += len(buf)
	paddlen := (len(buf) % 4) //Got to be 4 byte aligned?
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}

	padd := make([]byte, paddlen)
	_, err = w.Write(padd)
	if err != nil {
		return
	}
	n += paddlen
	return
}

// If maxCount is 0, use length of buf
func WriteConformantVaryingArrayPtr(w io.Writer, buf []byte, maxCount uint32, refId *uint32) (n int, err error) {
	var n2 int

	if len(buf) == 0 && maxCount == 0 {
		// Empty buffers are represented with a NULL Ptr?
		n, err = w.Write([]byte{0, 0, 0, 0})
		return
	}
	if *refId != 0 {
		err = binary.Write(w, le, *refId)
		if err != nil {
			return
		}
		*refId++
		n = 4
	}
	n2, err = WriteConformantVaryingArray(w, buf, maxCount)
	n += n2
	return
}

func ReadConformantVaryingArray(r *bytes.Reader) (data []byte, maxLength uint32, err error) {
	err = binary.Read(r, le, &maxLength)
	if err != nil {
		return
	}

	offset := uint32(0)
	err = binary.Read(r, le, &offset)
	if err != nil {
		return
	}

	actualCount := uint32(0)

	err = binary.Read(r, le, &actualCount)
	if err != nil {
		return
	}

	if offset > 0 {
		_, err = r.Seek(int64(offset), io.SeekCurrent)
		if err != nil {
			return
		}
	}

	if actualCount > 0 {
		// actualCount is server-controlled; refuse a count larger than the
		// remaining buffer before allocating so a bogus value can't trigger a
		// multi-GB makeslice panic / OOM.
		if uint64(actualCount) > uint64(r.Len()) {
			err = fmt.Errorf("ReadConformantVaryingArray: actual count %d exceeds remaining buffer (%d bytes)", actualCount, r.Len())
			return
		}
		data = make([]byte, actualCount)
		err = binary.Read(r, le, &data)
		if err != nil {
			return
		}
	}

	paddlen := ((actualCount + offset) % 4)
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}

	_, err = r.Seek(int64(paddlen), io.SeekCurrent)
	if err != nil {
		return
	}
	return
}

func ReadConformantVaryingArrayPtr(r *bytes.Reader) (data []byte, maxLength uint32, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		return
	}
	return ReadConformantVaryingArray(r)
}

func WriteConformantArray(w io.Writer, buf []byte) (n int, err error) {
	err = binary.Write(w, le, uint32(len(buf))) // MaxCount
	if err != nil {
		return
	}
	n += 4
	_, err = w.Write(buf)
	if err != nil {
		return
	}
	n += len(buf)
	paddlen := (len(buf) % 4) //Got to be 4 byte aligned?
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}

	padd := make([]byte, paddlen)
	_, err = w.Write(padd)
	if err != nil {
		return
	}
	n += paddlen
	return
}

func WriteConformantArrayPtr(w io.Writer, buf []byte, refid *uint32) (n int, err error) {
	var n2 int

	if len(buf) == 0 {
		// Empty buffers are represented with a NULL Ptr
		n, err = w.Write([]byte{0, 0, 0, 0})
		return
	}
	if *refid != 0 {
		err = binary.Write(w, le, refid)
		if err != nil {
			return
		}
		n = 4
		*refid++
	}
	n2, err = WriteConformantArray(w, buf)
	n += n2
	return
}

func ConvertSIDtoStr(sid *SID) (s string) {
	// Not sure what the first two bytes are but the
	// Identifier Authority is stored as BigEndian while the rest is little endian
	auth := binary.BigEndian.Uint32(sid.Authority[2:])
	s = fmt.Sprintf("S-%d-%d", sid.Revision, auth)
	//NOTE Seems that perhaps the sid.NumAuth (count) does not always accurately specify number of
	// Sub Authoritys but rather number of DWORDS. E.g., a SubAuthority could take more than 1 DWORD?
	// NumAuth is server-controlled and, for an ndr-decoded SID, is an independent
	// wire field from the conformant SubAuthorities array length. Iterate over the
	// actual slice so a mismatched count can't index out of bounds and crash the
	// client on a malicious-server SID.
	for i := 0; i < len(sid.SubAuthorities); i++ {
		s = fmt.Sprintf("%s-%d", s, sid.SubAuthorities[i])
	}
	return
}

func ConvertStrToSID(s string) (sid *SID, err error) {
	sid = &SID{}
	parts := strings.Split(s, "-")
	if len(parts) < 4 {
		err = fmt.Errorf("invalid SID representation")
		return
	}
	rev, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return
	}
	sid.Revision = byte(rev)
	auth, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return
	}
	authBuf := make([]byte, 2, 6)
	authBuf = binary.BigEndian.AppendUint32(authBuf, uint32(auth))
	copy(sid.Authority[:], authBuf)
	subCount := byte(0)
	subAuths := make([]uint32, 0)
	for _, part := range parts[3:] {
		subA, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, err
		}
		subAuths = append(subAuths, uint32(subA))
		subCount += 1
	}
	sid.SubAuthorities = subAuths
	sid.NumAuth = subCount
	return
}

// GuidToString renders a GUID stored in the standard little-endian wire layout
// (as used inside object ACEs: Data1 uint32 LE, Data2/Data3 uint16 LE, Data4 8
// bytes as-is) to the canonical "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" form.
func GuidToString(b [16]byte) string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		le.Uint32(b[0:4]),
		le.Uint16(b[4:6]),
		le.Uint16(b[6:8]),
		be.Uint16(b[8:10]),
		b[10:16],
	)
}

// GuidFromString parses a canonical GUID string into the little-endian wire
// layout expected inside object ACEs. Surrounding braces are tolerated.
func GuidFromString(s string) (b [16]byte, err error) {
	s = strings.TrimSuffix(strings.TrimPrefix(s, "{"), "}")
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		err = fmt.Errorf("invalid GUID %q", s)
		return
	}
	d1, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return b, fmt.Errorf("invalid GUID %q: %w", s, err)
	}
	d2, err := strconv.ParseUint(parts[1], 16, 16)
	if err != nil {
		return b, fmt.Errorf("invalid GUID %q: %w", s, err)
	}
	d3, err := strconv.ParseUint(parts[2], 16, 16)
	if err != nil {
		return b, fmt.Errorf("invalid GUID %q: %w", s, err)
	}
	g4, err := hex.DecodeString(parts[3])
	if err != nil || len(g4) != 2 {
		return b, fmt.Errorf("invalid GUID %q: bad group 4", s)
	}
	g5, err := hex.DecodeString(parts[4])
	if err != nil || len(g5) != 6 {
		return b, fmt.Errorf("invalid GUID %q: bad group 5", s)
	}
	le.PutUint32(b[0:4], uint32(d1))
	le.PutUint16(b[4:6], uint16(d2))
	le.PutUint16(b[6:8], uint16(d3))
	copy(b[8:10], g4)
	copy(b[10:16], g5)
	return b, nil
}

func ConvertToFiletime(t time.Time) uint64 {
	// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
	ft := uint64(t.UnixNano()) / 100
	ft += 116444736000000000 // add time between unix & windows offset
	return ft
}

func ConvertFromFiletime(t *Filetime) time.Time {
	var ft uint64
	ft = (uint64(t.HighDateTime) << 32) | (uint64(t.LowDateTime))
	ft -= 116444736000000000 // remove time between unix & windows offset
	ft *= 100
	return time.Unix(0, int64(ft))
}

func ParseAccessMask(mask uint32) []string {
	permissions := []string{}
	for v, s := range accessMaskMap {
		if mask&v > 0 {
			permissions = append(permissions, s)
		}
	}
	slices.Sort(permissions)
	return permissions
}

// ParseAceFlags renders the set ACE flags. The result is sorted: map iteration
// order is randomised, so an unsorted join reorders the flags between runs and
// makes the output impossible to diff.
func ParseAceFlags(aceFlags byte) string {
	flags := []string{}
	for v, s := range aceFlagsMap {
		if aceFlags&v > 0 {
			flags = append(flags, s)
		}
	}
	slices.Sort(flags)
	return strings.Join(flags, ",")
}
