// MIT License
//
// Copyright (c) 2017 stacktitan
// Copyright (c) 2023 Jimmy Fjällid for contributions to support more structures
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

/*
	The original encoder package implemented only the minimal viable encoder/decoder

to support login with smb dialect 2.1 and perform a tree connect. It has been extended
to handle many more cases, but it is far from complete. Many of the structs that can
be serialized correctly cannot be deserialized and the other way around. Furthermore,
a few cases has been added that have yet to be used anywhere and as such the code is
untested.
*/
package encoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/jfjallid/golog"
)

var log = golog.Get("github.com/jfjallid/go-smb/smb/encoder").SetDisplayName("encoder")

type BinaryMarshallable interface {
	MarshalBinary(*Metadata) ([]byte, error)
	UnmarshalBinary([]byte, *Metadata) error
}

type Metadata struct {
	Tags       *TagMap
	Lens       map[string]uint64
	Offsets    map[string]uint64
	Counts     map[string]uint64
	Parent     interface{}
	ParentBuf  []byte
	CurrOffset uint64
	CurrField  string
}

type TagMap struct {
	m   map[string]interface{}
	has map[string]bool
}

func (t TagMap) Has(key string) bool {
	return t.has[key]
}

func (t TagMap) Set(key string, val interface{}) {
	t.m[key] = val
	t.has[key] = true
}

func (t TagMap) Get(key string) interface{} {
	return t.m[key]
}

func (t TagMap) GetInt(key string) (int, error) {
	if !t.Has(key) {
		return 0, errors.New("key does not exist in tag")
	}
	return t.Get(key).(int), nil
}

func (t TagMap) GetString(key string) (string, error) {
	if !t.Has(key) {
		return "", errors.New("key does not exist in tag")
	}
	return t.Get(key).(string), nil
}

func parseTags(sf reflect.StructField) (*TagMap, error) {
	ret := &TagMap{
		m:   make(map[string]interface{}),
		has: make(map[string]bool),
	}
	tag := sf.Tag.Get("smb")
	smbTags := strings.Split(tag, ",")
	for _, smbTag := range smbTags {
		tokens := strings.Split(smbTag, ":")
		switch tokens[0] {
		case "len", "offset", "count":
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data, expecting key:val")
			}
			ret.Set(tokens[0], tokens[1])
		case "fixed", "align":
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data, expecting key:val")
			}
			i, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			ret.Set(tokens[0], i)
		case "asn1":
			ret.Set(tokens[0], true)
		case "omitempty":
			if len(tokens) != 2 {
				return nil, errors.New("missing required tag data, expecting key:val")
			}
			i, err := strconv.Atoi(tokens[1])
			if err != nil {
				return nil, err
			}
			ret.Set(tokens[0], i)
		}
	}

	return ret, nil
}

func getOffsetByFieldName(fieldName string, meta *Metadata) (uint64, error) {
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field offset, missing required metadata")
	}
	var ret uint64
	var found bool
	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))
	// To determine offset, we loop through all fields of the struct, summing lengths of previous elements
	// until we reach our field
	for i := 0; i < parentvf.NumField(); i++ {
		tf := parentvf.Type().Field(i)
		if tf.Name == fieldName {
			found = true
			break
		}
		if l, ok := meta.Lens[tf.Name]; ok {
			// Length of field is in cache
			ret += l
		} else {
			// Not in cache. Must marshal field to determine length. Add to cache after
			buf, err := Marshal(parentvf.Field(i).Interface())
			if err != nil {
				return 0, err
			}
			l := uint64(len(buf))
			meta.Lens[tf.Name] = l
			ret += l
		}
	}
	if !found {
		return 0, errors.New("cannot find field name within struct: " + fieldName)
	}
	return ret, nil
}

// isFieldEmpty reports whether the named field on meta.Parent has zero length.
// It first consults meta.Lens (the marshaled-length cache), then falls back to
// reflecting on the parent struct so that callers running before the target
// field has been encoded — e.g. an offset:X tag where X comes later in the
// struct — still get an accurate empty/non-empty answer.
func isFieldEmpty(fieldName string, meta *Metadata) (bool, error) {
	if meta == nil || meta.Parent == nil {
		return false, errors.New("cannot determine field emptiness, missing required metadata")
	}
	if val, ok := meta.Lens[fieldName]; ok {
		return val == 0, nil
	}
	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))
	field := parentvf.FieldByName(fieldName)
	if !field.IsValid() {
		return false, errors.New("invalid field, cannot determine emptiness for " + fieldName)
	}
	switch field.Kind() {
	case reflect.Ptr, reflect.Interface:
		return field.IsNil(), nil
	case reflect.Slice, reflect.Array, reflect.Map, reflect.String:
		return field.Len() == 0, nil
	}
	return false, nil
}

func getFieldLengthByName(fieldName string, meta *Metadata) (uint64, error) {
	var ret uint64
	if meta == nil || meta.Tags == nil || meta.Parent == nil || meta.Lens == nil {
		return 0, errors.New("cannot determine field length, missing required metadata")
	}

	// Check if length is stored in field length cache
	if val, ok := meta.Lens[fieldName]; ok {
		return uint64(val), nil
	}

	parentvf := reflect.Indirect(reflect.ValueOf(meta.Parent))

	field := parentvf.FieldByName(fieldName)
	if !field.IsValid() {
		return 0, fmt.Errorf("invalid field %s: cannot determine length (lens: %v)", fieldName, meta.Lens)
	}

	bm, ok := field.Interface().(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.(BinaryMarshallable).MarshalBinary(meta)
		if err != nil {
			return 0, err
		}
		return uint64(len(buf)), nil
	}

	if field.Kind() == reflect.Ptr {
		field = field.Elem()
	}

	switch field.Kind() {
	case reflect.Struct:
		buf, err := Marshal(field.Interface())
		if err != nil {
			return 0, err
		}
		ret = uint64(len(buf))
	case reflect.Interface:
		return 0, errors.New("interface length calculation not implemented")
	case reflect.Slice, reflect.Array:
		switch field.Type().Elem().Kind() {
		case reflect.Uint8:
			ret = uint64(len(field.Interface().([]byte)))
		case reflect.Uint16:
			ret = uint64(len(field.Interface().([]uint16))) //TODO Is this correct?
		default:
			return 0, errors.New("cannot calculate the length of unknown slice type for " + fieldName)
		}
	case reflect.Uint8:
		ret = uint64(binary.Size(field.Interface().(uint8)))
	case reflect.Uint16:
		ret = uint64(binary.Size(field.Interface().(uint16)))
	case reflect.Uint32:
		ret = uint64(binary.Size(field.Interface().(uint32)))
	case reflect.Uint64:
		ret = uint64(binary.Size(field.Interface().(uint64)))
	default:
		return 0, errors.New("cannot calculate the length of unknown kind for field " + fieldName)
	}
	meta.Lens[fieldName] = ret
	return ret, nil
}

func Marshal(v interface{}) ([]byte, error) {
	return marshal(v, nil)
}

func marshal(v interface{}, meta *Metadata) ([]byte, error) {
	var ret []byte
	typev := reflect.TypeOf(v)
	valuev := reflect.ValueOf(v)

	bm, ok := v.(BinaryMarshallable)
	if !ok && typev != nil && typev.Kind() != reflect.Ptr {
		// MarshalBinary is conventionally defined on a pointer receiver
		// (matching the rest of this package). A caller passing a struct
		// value through interface{} would otherwise silently bypass it and
		// fall through to the reflection-based path, producing a structurally
		// different (often wire-invalid) buffer. Take the address transparently
		// so the dispatch is independent of value-vs-pointer at the call site.
		// See TestNegotiateReqContextOffsetAligned for the regression this
		// guards against.
		pv := reflect.New(typev)
		pv.Elem().Set(valuev)
		if pbm, pok := pv.Interface().(BinaryMarshallable); pok {
			bm, ok = pbm, true
		}
	}
	if ok {
		// Custom marshallable interface found.
		buf, err := bm.MarshalBinary(meta)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}

	if typev.Kind() == reflect.Ptr {
		valuev = reflect.Indirect(reflect.ValueOf(v))
		if !valuev.IsValid() {
			// Workaround for struct pointers that should not be included
			if meta != nil && meta.Tags.Has("omitempty") {
				return nil, nil
			} else {
				// Workaround to handle null pointers represented as uint32
				return []byte{0, 0, 0, 0}, nil
			}
		}
		typev = valuev.Type()
	}

	w := bytes.NewBuffer(ret)
	switch typev.Kind() {
	case reflect.Struct:
		m := &Metadata{
			Tags:   &TagMap{},
			Lens:   make(map[string]uint64),
			Parent: v,
		}
		for j := 0; j < valuev.NumField(); j++ {
			tags, err := parseTags(typev.Field(j))
			if err != nil {
				return nil, err
			}
			m.Tags = tags
			buf, err := marshal(valuev.Field(j).Interface(), m)
			if err != nil {
				return nil, err
			}
			m.Lens[typev.Field(j).Name] = uint64(len(buf))
			if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
				return nil, err
			}
		}
	case reflect.Slice, reflect.Array:
		switch typev.Elem().Kind() {
		case reflect.Uint8:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint8)); err != nil {
				return nil, err
			}
		case reflect.Uint16:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint16)); err != nil {
				return nil, err
			}
		case reflect.Uint32:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint32)); err != nil {
				return nil, err
			}
		case reflect.Uint64:
			if err := binary.Write(w, binary.LittleEndian, v.([]uint64)); err != nil {
				return nil, err
			}
		case reflect.Struct:
			if valuev.Len() == 0 {
				// Empty array
				if err := binary.Write(w, binary.LittleEndian, []byte{0, 0, 0, 0}); err != nil {
					return nil, err
				}
				//TODO Add support for non empty arrays
				//} else {
				//    for i:=0; i < valuev.Len(); i++ {

				//    }
			} else {
				for j := 0; j < valuev.Len(); j++ {
					buf, err := marshal(valuev.Index(j).Interface(), nil)
					if err != nil {
						return nil, err
					}
					if err := binary.Write(w, binary.LittleEndian, buf); err != nil {
						return nil, err
					}
				}
				//TODO Perhaps I should record the length of the array in a tag or field?
			}
		default:
			err := fmt.Errorf("want to marshal slice of unknown type: %v", typev.Elem().Kind())
			return nil, err // Originally this error was ignored
		}
	case reflect.Uint8:
		if err := binary.Write(w, binary.LittleEndian, valuev.Interface().(uint8)); err != nil {
			return nil, err
		}
	case reflect.Uint16:
		data := valuev.Interface().(uint16)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint16(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			empty, err := isFieldEmpty(fieldName, meta)
			if err != nil {
				return nil, err
			}
			if empty {
				data = uint16(0)
			} else {
				l, err := getOffsetByFieldName(fieldName, meta)
				if err != nil {
					return nil, err
				}
				data = uint16(l)
			}
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint32:
		data := valuev.Interface().(uint32)
		if meta != nil && meta.Tags.Has("len") {
			fieldName, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			l, err := getFieldLengthByName(fieldName, meta)
			if err != nil {
				return nil, err
			}
			data = uint32(l)
		}
		if meta != nil && meta.Tags.Has("offset") {
			fieldName, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			empty, err := isFieldEmpty(fieldName, meta)
			if err != nil {
				return nil, err
			}
			if empty {
				data = uint32(0)
			} else {
				l, err := getOffsetByFieldName(fieldName, meta)
				if err != nil {
					return nil, err
				}
				data = uint32(l)
			}
		}
		if meta != nil && meta.Tags.Has("omitempty") {
			omitVal, _ := meta.Tags.GetInt("omitempty")
			if data == uint32(omitVal) {
				return nil, nil
			}
		}
		if err := binary.Write(w, binary.LittleEndian, data); err != nil {
			return nil, err
		}
	case reflect.Uint64:
		if err := binary.Write(w, binary.LittleEndian, valuev.Interface().(uint64)); err != nil {
			return nil, err
		}
	default:
		err := fmt.Errorf("marshal not implemented for kind: %s", typev.Kind())
		return nil, err
	}
	return w.Bytes(), nil
}

func unmarshal(buf []byte, v interface{}, meta *Metadata) (interface{}, error) {
	typev := reflect.TypeOf(v)
	valuev := reflect.ValueOf(v)

	bm, ok := v.(BinaryMarshallable)
	if ok {
		// Custom marshallable interface found.
		if err := bm.UnmarshalBinary(buf, meta); err != nil {
			return nil, err
		}
		if meta != nil {
			if val, ok := meta.Lens[meta.CurrField]; ok {
				meta.CurrOffset += val
			}
		}
		return bm, nil
	}

	if typev.Kind() == reflect.Ptr {
		valuev = reflect.ValueOf(v).Elem()
		typev = valuev.Type()
	}

	if meta == nil {
		meta = &Metadata{
			Tags:       &TagMap{},
			Lens:       make(map[string]uint64),
			Parent:     v,
			ParentBuf:  buf,
			Offsets:    make(map[string]uint64),
			Counts:     make(map[string]uint64),
			CurrOffset: 0,
		}
	}

	r := bytes.NewBuffer(buf)
	switch typev.Kind() {
	case reflect.Struct:
		m := &Metadata{
			Tags:       &TagMap{},
			Lens:       make(map[string]uint64),
			Parent:     v,
			ParentBuf:  buf,
			Offsets:    make(map[string]uint64),
			Counts:     make(map[string]uint64),
			CurrOffset: 0,
		}
		for i := 0; i < typev.NumField(); i++ {
			m.CurrField = typev.Field(i).Name
			tags, err := parseTags(typev.Field(i))
			if err != nil {
				return nil, err
			}
			m.Tags = tags
			var data interface{}
			switch typev.Field(i).Type.Kind() {
			case reflect.Struct:
				data, err = unmarshal(buf[m.CurrOffset:], valuev.Field(i).Addr().Interface(), m)
			default:
				data, err = unmarshal(buf[m.CurrOffset:], valuev.Field(i).Interface(), m)
			}
			if err != nil {
				return nil, err
			}
			// Handle nil results
			if data == nil {
				continue
			}
			valuev.Field(i).Set(reflect.ValueOf(data))
		}
		v = reflect.Indirect(reflect.ValueOf(v)).Interface()
		meta.CurrOffset += m.CurrOffset
		return v, nil
	case reflect.Uint8:
		var ret uint8
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		if meta.Tags.Has("count") {
			ref, err := meta.Tags.GetString("count")
			if err != nil {
				return nil, err
			}
			meta.Counts[ref] = uint64(ret)
		}

		return ret, nil
	case reflect.Uint16:
		var ret uint16
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		if meta.Tags.Has("len") {
			ref, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			meta.Lens[ref] = uint64(ret)
		} else if meta.Tags.Has("offset") {
			ref, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			meta.Offsets[ref] = uint64(ret)
		}
		if meta.Tags.Has("count") {
			ref, err := meta.Tags.GetString("count")
			if err != nil {
				return nil, err
			}
			meta.Counts[ref] = uint64(ret)
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Uint32:
		var ret uint32
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		if meta.Tags.Has("len") {
			ref, err := meta.Tags.GetString("len")
			if err != nil {
				return nil, err
			}
			meta.Lens[ref] = uint64(ret)
		} else if meta.Tags.Has("offset") {
			ref, err := meta.Tags.GetString("offset")
			if err != nil {
				return nil, err
			}
			meta.Offsets[ref] = uint64(ret)
		}
		if meta.Tags.Has("count") {
			ref, err := meta.Tags.GetString("count")
			if err != nil {
				return nil, err
			}
			meta.Counts[ref] = uint64(ret)
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Uint64:
		var ret uint64
		if err := binary.Read(r, binary.LittleEndian, &ret); err != nil {
			return nil, err
		}
		if meta.Tags.Has("count") {
			ref, err := meta.Tags.GetString("count")
			if err != nil {
				return nil, err
			}
			meta.Counts[ref] = uint64(ret)
		}
		meta.CurrOffset += uint64(binary.Size(ret))
		return ret, nil
	case reflect.Slice, reflect.Array:
		switch typev.Elem().Kind() {
		case reflect.Uint8:
			var length, offset int
			var err error
			if meta.Tags.Has("fixed") {
				if length, err = meta.Tags.GetInt("fixed"); err != nil {
					return nil, err
				}
				// Fixed length fields advance current offset
				meta.CurrOffset += uint64(length)
			} else if meta.Tags.Has("align") {
				// Align the next struct field to specified align-byte boundary
				// e.g, to 4 byte boundary
				align, err := meta.Tags.GetInt("align")
				if err != nil {
					return nil, err
				}
				diff := int(meta.CurrOffset % uint64(align))
				diff = align - diff
				diff = diff % align
				//TODO Below was original align, but does not work as intended when no alignment is needed.
				// However, might break some request where padding is desired rather than alignment such that padd: 0 -> padd=align
				//if diff == 0 {
				//	diff = align
				//} else {
				//	diff = align - diff
				//}
				if len(meta.ParentBuf) > int(meta.CurrOffset) {
					// Don't increment CurrOffset if we've reached the end of the buffer
					// Meant to handle situations where the alignment padding is located
					// before an optional last element of the struct
					meta.CurrOffset += uint64(diff)
				}
				// NOTE This assumes that length is 0 so nothing is read into data below
			} else {
				if val, ok := meta.Lens[meta.CurrField]; ok {
					length = int(val)
				} else {
					err := fmt.Errorf("variable length field missing length reference in struct field: %s", meta.CurrField)
					return nil, err
				}
				if val, ok := meta.Offsets[meta.CurrField]; ok {
					offset = int(val)
				} else {
					// No offset found in map. Use current offset
					offset = int(meta.CurrOffset)
				}
				if offset != int(meta.CurrOffset) {
					// Variable length data is relative to parent/outer struct. Reset reader to point to beginning of data
					r = bytes.NewBuffer(meta.ParentBuf[offset : offset+length])
					// Variable length data fields do NOT advance current offset.
				} else {
					meta.CurrOffset += uint64(length)
				}
			}
			data := make([]byte, length)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			return data, nil
		case reflect.Uint16:
			var length, offset int
			var err error
			if meta.Tags.Has("fixed") {
				if length, err = meta.Tags.GetInt("fixed"); err != nil {
					return nil, err
				}
				// Fixed length fields advance current offset
				meta.CurrOffset += uint64(length * 2) //TODO Should this be x2? Was originally only length
			} else {
				if val, ok := meta.Counts[meta.CurrField]; ok {
					length = int(val)
				} else {
					if val, ok := meta.Lens[meta.CurrField]; ok {
						length = int(val)
					} else {
						err := fmt.Errorf("variable length field missing length reference in struct field: %s", meta.CurrField)
						return nil, err
					}
					if val, ok := meta.Offsets[meta.CurrField]; ok {
						offset = int(val)
					} else {
						// No offset found in map. Use current offset
						offset = int(meta.CurrOffset)
					}
					if offset != int(meta.CurrOffset) {
						// Variable length data is relative to parent/outer struct. Reset reader to point to beginning of data
						r = bytes.NewBuffer(meta.ParentBuf[offset : offset+length*2]) //TODO Should this be x2? Was originally only length
						// Variable length data fields do NOT advance current offset.
					} else {
						meta.CurrOffset += uint64(length * 2) //TODO Should this be x2? Was originally only length
					}
				}
			}
			data := make([]uint16, length)
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			return data, nil
		case reflect.Uint32:
			var length, count int
			var err error
			var data []uint32
			if meta.Tags.Has("fixed") {
				if length, err = meta.Tags.GetInt("fixed"); err != nil {
					return nil, err
				}
				// Fixed length fields advance current offset
				meta.CurrOffset += uint64(length)
				data = make([]uint32, length/4)
			} else {
				if val, ok := meta.Counts[meta.CurrField]; ok {
					count = int(val)
				} else {
					return nil, errors.New("variable length (uint32) field missing count reference in struct field: " + meta.CurrField)
				}
				meta.CurrOffset += uint64(count * 4)
				data = make([]uint32, count)
			}
			if err := binary.Read(r, binary.LittleEndian, &data); err != nil {
				return nil, err
			}
			return data, nil
		case reflect.Struct:
			var count uint64
			var ok bool
			if count, ok = meta.Counts[meta.CurrField]; ok {
				if count == 0 {
					return nil, nil
				}
			} else {
				err := fmt.Errorf("not implemented: unmarshal of slice of structs missing Count tag")
				return nil, err
			}
			list := reflect.MakeSlice(typev, 0, int(count))
			arrayOffset := uint64(0)
			prevCurrMetaOffset := uint64(0)
			for i := uint64(0); i < count; i++ {
				prevCurrMetaOffset = meta.CurrOffset
				x := reflect.New(typev.Elem())
				data, err := unmarshal(buf[arrayOffset:], x.Interface(), meta)
				if err != nil {
					return nil, err
				}
				arrayOffset += meta.CurrOffset - prevCurrMetaOffset
				list = reflect.Append(list, reflect.ValueOf(data))
			}

			return list.Interface(), nil

		default:
			err := fmt.Errorf("unmarshal not implemented for slice kind: %s", typev.Kind().String())
			return nil, err
		}
	default:
		err := fmt.Errorf("unmarshal not implemented for kind: %s", typev.Kind().String())
		return nil, err
	}
}

func Unmarshal(buf []byte, v interface{}) error {
	_, err := unmarshal(buf, v, nil)
	return err
}
