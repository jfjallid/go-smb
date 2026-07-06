package encoder

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// blob is a small struct used as the target of an offset:Blob tag so we can
// exercise the uint16/uint32 offset emptiness check against a *struct field.
type blob struct {
	A uint32
	B uint32
}

// offsetTagSubject mirrors the relevant shape of NegotiateRes: a uint32 offset
// pointing forward at a variable-length slice that may be empty, plus a uint16
// offset pointing at a *struct field. Layout in bytes:
//
//	StructureSize     uint16 (2)
//	BlobOffset        uint16 (2, offset:Blob)
//	Reserved          uint32 (4, pad to keep ContextListOffset 4-byte aligned)
//	ContextListOffset uint32 (4, offset:ContextList)
//	Blob              *blob  (variable: 0 or 8 bytes)
//	ContextList       []blob (variable)
type offsetTagSubject struct {
	StructureSize     uint16
	BlobOffset        uint16 `smb:"offset:Blob"`
	Reserved          uint32
	ContextListOffset uint32 `smb:"offset:ContextList"`
	Blob              *blob
	ContextList       []blob
}

// TestOffsetTagZeroForEmptySlice verifies that a uint32 offset: tag emits 0
// when the referenced slice is empty, even though the offset field is encoded
// before the slice in struct order (so the length cache is cold at the moment
// the offset is written).
func TestOffsetTagZeroForEmptySlice(t *testing.T) {
	s := offsetTagSubject{
		StructureSize: 0x41,
		Blob:          &blob{A: 0xdeadbeef, B: 0xcafef00d},
		ContextList:   nil,
	}
	buf, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	// ContextListOffset sits at bytes [8:12].
	got := buf[8:12]
	if !bytes.Equal(got, []byte{0, 0, 0, 0}) {
		t.Fatalf("ContextListOffset = % x, want 00 00 00 00", got)
	}
	// BlobOffset (uint16 at bytes [2:4]) must still point at Blob, since Blob
	// is non-nil. Expected position = 2+2+4+4 = 12.
	bo := uint16(buf[2]) | uint16(buf[3])<<8
	if bo != 12 {
		t.Fatalf("BlobOffset = %d, want 12", bo)
	}
}

// TestOffsetTagZeroForNilPointer verifies the same emptiness check fires for
// nil *struct pointers (Blob here), exercising the uint16 offset branch.
func TestOffsetTagZeroForNilPointer(t *testing.T) {
	s := offsetTagSubject{
		StructureSize: 0x41,
		Blob:          nil,
		ContextList:   nil,
	}
	buf, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	bo := uint16(buf[2]) | uint16(buf[3])<<8
	if bo != 0 {
		t.Fatalf("BlobOffset = %d, want 0 (Blob is nil)", bo)
	}
	co := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
	if co != 0 {
		t.Fatalf("ContextListOffset = %d, want 0", co)
	}
}

// varLenSubject mirrors the shape of request structs whose variable-length
// field is located via wire-controlled offset:/len: header fields (e.g.
// SessionSetupReq.SecurityBufferOffset/Length). Layout in bytes:
//
//	StructureSize uint16 (2)
//	DataLen       uint16 (2, len:Data)
//	DataOffset    uint16 (2, offset:Data)
//	Data          []byte (variable, located at DataOffset)
type varLenSubject struct {
	StructureSize uint16
	DataLen       uint16 `smb:"len:Data"`
	DataOffset    uint16 `smb:"offset:Data"`
	Data          []byte
}

// makeVarLenPacket builds a 6-byte header for varLenSubject with the given
// wire-controlled offset and length values.
func makeVarLenPacket(offset, length uint16) []byte {
	buf := make([]byte, 6)
	binary.LittleEndian.PutUint16(buf[0:2], 6) // StructureSize
	binary.LittleEndian.PutUint16(buf[2:4], length)
	binary.LittleEndian.PutUint16(buf[4:6], offset)
	return buf
}

// TestUnmarshalOutOfBoundsOffsetReturnsError is the regression guard for the
// CRITICAL encoder finding: an attacker-controlled offset:/len: pair that
// points past the end of the buffer must produce an error, not a
// slice-bounds-out-of-range panic that would crash the whole process.
func TestUnmarshalOutOfBoundsOffsetReturnsError(t *testing.T) {
	cases := []struct {
		name           string
		offset, length uint16
	}{
		{"offset past end", 0xFFFF, 2},
		{"length past end", 4, 0xFFFF},
		{"offset at boundary plus length", 6, 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := makeVarLenPacket(tc.offset, tc.length)
			var s varLenSubject
			// Must not panic; must return a non-nil error.
			if err := Unmarshal(pkt, &s); err == nil {
				t.Fatalf("Unmarshal accepted out-of-bounds offset=%d length=%d, want error", tc.offset, tc.length)
			}
		})
	}
}

// TestUnmarshalInBoundsOffsetSucceeds verifies the bounds check does not
// reject a legitimate in-bounds variable-length field.
func TestUnmarshalInBoundsOffsetSucceeds(t *testing.T) {
	pkt := append(makeVarLenPacket(6, 3), 0xAA, 0xBB, 0xCC)
	var s varLenSubject
	if err := Unmarshal(pkt, &s); err != nil {
		t.Fatalf("Unmarshal of valid packet failed: %v", err)
	}
	if !bytes.Equal(s.Data, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("Data = % x, want AA BB CC", s.Data)
	}
}

// FuzzUnmarshalVarLen fuzzes the decoder over the offset:/len: trust boundary.
// The decode must always return (never panic) regardless of the wire bytes.
func FuzzUnmarshalVarLen(f *testing.F) {
	f.Add(makeVarLenPacket(6, 3))
	f.Add(makeVarLenPacket(0xFFFF, 2))
	f.Add(makeVarLenPacket(0, 0xFFFF))
	f.Add([]byte{0x06, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		var s varLenSubject
		_ = Unmarshal(data, &s) // must not panic
	})
}

// TestOffsetTagPopulatedWhenNonEmpty verifies the offset is computed normally
// when the target field is populated.
func TestOffsetTagPopulatedWhenNonEmpty(t *testing.T) {
	s := offsetTagSubject{
		StructureSize: 0x41,
		Blob:          &blob{A: 1, B: 2},
		ContextList:   []blob{{A: 3, B: 4}},
	}
	buf, err := Marshal(s)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	// Header fixed portion is 12 bytes (StructureSize..ContextListOffset).
	// Blob is 8 bytes → ContextList starts at offset 20.
	co := uint32(buf[8]) | uint32(buf[9])<<8 | uint32(buf[10])<<16 | uint32(buf[11])<<24
	if co != 20 {
		t.Fatalf("ContextListOffset = %d, want 20", co)
	}
	bo := uint16(buf[2]) | uint16(buf[3])<<8
	if bo != 12 {
		t.Fatalf("BlobOffset = %d, want 12", bo)
	}
}
