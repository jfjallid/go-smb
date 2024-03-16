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
package msrrp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf16"
)

func FromUnicodeString(buf []byte) (res string, err error) {
	buflen := len(buf)
	if (buflen % 2) != 0 {
		err = fmt.Errorf("Invalid Unicode (UTF-16-LE) string")
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
func newUnicodeStr(s string) (offset uint32, actualCount uint32, paddlen int, buffer []byte) {
	data := nullTerminate(s)
	buffer = ToUnicode(data)
	actualCount = uint32(len(buffer) / 2)
	offset = 0
	paddlen = (len(buffer) % 4) //Got to be 4 byte aligned
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}
	return
}

func nullTerminate(s string) string {
	if s == "" {
		s = "\x00"
	} else if s[len(s)-1] != 0x00 {
		return s + "\x00"
	}
	return s
}

func stripNullByte(s string) string {
	if s == "" {
		return ""
	}
	if s[len(s)-1] == 0x00 {
		return s[:len(s)-1]
	}
	return s
}

func readConformantVaryingString(r *bytes.Reader) (s string, err error) {
	// Read the Max count
	var maxCount uint32
	err = binary.Read(r, le, &maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	if maxCount == 0 {
		// If maxCount is zero, we've likely encountered a null ptr
		return
	}
	// Read the offset
	var offset uint32
	err = binary.Read(r, le, &offset)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Read the Actual count
	var actualCount uint32
	err = binary.Read(r, le, &actualCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	if offset > 0 {
		_, err = r.Seek(int64(offset)*2, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if actualCount > 0 {
		// Read the unicode string
		unc := make([]byte, actualCount*2)
		err = binary.Read(r, le, unc)
		if err != nil {
			log.Errorln(err)
			return
		}

		s, err = FromUnicodeString(unc)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	paddLen := 4 - ((offset*2 + actualCount*2) % 4)

	if paddLen != 4 {
		_, err = r.Seek(int64(paddLen), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return
}

func readConformantVaryingStringPtr(r *bytes.Reader) (s string, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return readConformantVaryingString(r)
}

/*
	Write a conformant and varying string to the output stream

NOTE that this is a bit different than the DCERPC implementation as empty
strings are not encoded as two null bytes.
Furthermore, the MaxLength from the RRPUnicodeStr should also be encoded here.
*/
func writeConformantVaryingString(w io.Writer, bo binary.ByteOrder, us *RRPUnicodeStr) (n int, err error) {
	offset, count, paddlen, buffer := newUnicodeStr(us.S)
	err = binary.Write(w, bo, uint32(us.MaxLength)) // MaxCount
	if err != nil {
		return
	}
	n += 4
	if us.S == "" {
		// Since we won't encode an empty string will null bytes, set the
		// actual length to 0
		count = 0
	}
	err = binary.Write(w, bo, offset)
	if err != nil {
		return
	}
	n += 4
	err = binary.Write(w, bo, count)
	if err != nil {
		return
	}
	n += 4
	if us.S == "" {
		// Don't encode null bytes for empty string
		return
	}

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
func writeConformantVaryingStringPtr(w io.Writer, bo binary.ByteOrder, us *RRPUnicodeStr, refid *uint32) (n int, err error) {
	var n2 int

	// Should this be supported?
	//if us.S == "" {
	//	// Empty strings are represented as a NULL Ptr
	//	n, err = w.Write([]byte{0, 0, 0, 0})
	//	if err != nil {
	//		log.Errorln(err)
	//	}
	//	return
	//}
	if *refid != 0 {
		err = binary.Write(w, bo, *refid)
		if err != nil {
			return
		}
		n = 4
	}
	*refid++
	n2, err = writeConformantVaryingString(w, bo, us)
	n += n2
	return
}

// If maxCount is 0, use length of buf
func writeConformantVaryingArray(w io.Writer, buf []byte, maxCount uint32) (n int, err error) {
	actualCount := uint32(len(buf))
	if maxCount == 0 {
		maxCount = actualCount
	}
	err = binary.Write(w, le, maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	n += 4

	err = binary.Write(w, le, uint32(0)) // Offset
	if err != nil {
		log.Errorln(err)
		return
	}
	n += 4

	err = binary.Write(w, le, actualCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	n += 4

	_, err = w.Write(buf)
	if err != nil {
		log.Errorln(err)
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
		log.Errorln(err)
		return
	}
	n += paddlen
	return
}

// If maxCount is 0, use length of buf
func writeConformantVaryingArrayPtr(w io.Writer, buf []byte, maxCount uint32, refId *uint32) (n int, err error) {
	var n2 int

	if len(buf) == 0 && maxCount == 0 {
		// Empty buffers are represented with a NULL Ptr?
		n, err = w.Write([]byte{0, 0, 0, 0})
		if err != nil {
			log.Errorln(err)
		}
		return
	}
	if *refId != 0 {
		err = binary.Write(w, le, *refId)
		if err != nil {
			log.Errorln(err)
			return
		}
		*refId++
		n = 4
	}
	n2, err = writeConformantVaryingArray(w, buf, maxCount)
	n += n2
	return
}

func readConformantVaryingArray(r *bytes.Reader) (data []byte, maxLength uint32, err error) {
	err = binary.Read(r, le, &maxLength)
	if err != nil {
		log.Errorln(err)
		return
	}

	offset := uint32(0)
	err = binary.Read(r, le, &offset)
	if err != nil {
		log.Errorln(err)
		return
	}

	actualCount := uint32(0)

	err = binary.Read(r, le, &actualCount)
	if err != nil {
		log.Errorln(err)
		return
	}

	if offset > 0 {
		_, err = r.Seek(int64(offset), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if actualCount > 0 {
		data = make([]byte, actualCount)
		err = binary.Read(r, le, &data)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	paddlen := ((actualCount + offset) % 4)
	if paddlen != 0 {
		paddlen = 4 - paddlen
	}

	_, err = r.Seek(int64(paddlen), io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return
}

func readConformantVaryingArrayPtr(r *bytes.Reader) (data []byte, maxLength uint32, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return readConformantVaryingArray(r)
}
