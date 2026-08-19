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

package smb

import "testing"

// The flag lives in a single byte of the READ request that is trivial to leave
// at zero (it was, until now) — and leaving it at zero is invisible: reads
// still succeed, just never compressed. So assert on the wire byte rather than
// on the struct field.
func TestReadReqRequestCompressedFlag(t *testing.T) {
	fid := make([]byte, 16)

	for _, tc := range []struct {
		name          string
		compressReads bool
		want          byte
	}{
		{"clear when the session did not ask", false, 0},
		{"set when the session asks", true, ReadFlagRequestCompressed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Session{dialect: DialectSmb_3_1_1, compressReads: tc.compressReads}
			req, err := s.NewReadReq("share", fid, 4096, 0, 1)
			if err != nil {
				t.Fatalf("NewReadReq: %v", err)
			}
			if req.Flags != tc.want {
				t.Errorf("Flags = 0x%02x, want 0x%02x", req.Flags, tc.want)
			}
			buf, err := req.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary: %v", err)
			}
			// Header(64) + StructureSize(2) + Padding(1) = offset of Flags.
			if got := buf[67]; got != tc.want {
				t.Errorf("marshalled Flags byte = 0x%02x, want 0x%02x", got, tc.want)
			}
		})
	}
}
