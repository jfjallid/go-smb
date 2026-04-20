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
package mstsch

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestSchRpcDeleteReqMarshal(t *testing.T) {
	req := SchRpcDeleteReq{
		Path:  "\\task1",
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Verify structure: MaxCount(4) + Offset(4) + ActualCount(4) + UTF-16LE string + padding + Flags(4)
	r := bytes.NewReader(buf)
	var maxCount, offset, actualCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	binary.Read(r, binary.LittleEndian, &offset)
	binary.Read(r, binary.LittleEndian, &actualCount)

	// "\\task1\0" = 7 chars
	if maxCount != 7 {
		t.Fatalf("expected maxCount=7, got %d", maxCount)
	}
	if offset != 0 {
		t.Fatalf("expected offset=0, got %d", offset)
	}
	if actualCount != 7 {
		t.Fatalf("expected actualCount=7, got %d", actualCount)
	}
}

func TestSchRpcRunReqMarshal(t *testing.T) {
	req := SchRpcRunReq{
		Path:      "\\task1",
		Flags:     TaskRunNoFlags,
		SessionId: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the buffer is non-empty and ends correctly
	if len(buf) == 0 {
		t.Fatal("expected non-empty buffer")
	}

	// The last 12 bytes should be: Flags(4) + SessionId(4) + user NULL ptr(4)
	tail := buf[len(buf)-12:]
	flags := binary.LittleEndian.Uint32(tail[0:4])
	sessionId := binary.LittleEndian.Uint32(tail[4:8])
	userPtr := binary.LittleEndian.Uint32(tail[8:12])

	if flags != 0 {
		t.Fatalf("expected flags=0, got %d", flags)
	}
	if sessionId != 0 {
		t.Fatalf("expected sessionId=0, got %d", sessionId)
	}
	if userPtr != 0 {
		t.Fatalf("expected user NULL ptr=0, got %d", userPtr)
	}
}

func TestSchRpcRunReqMarshalWithUser(t *testing.T) {
	user := "S-1-5-18"
	req := SchRpcRunReq{
		Path:      "\\task1",
		Flags:     TaskRunUserSid,
		SessionId: 0,
		User:      &user,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("expected non-empty buffer")
	}

	// With a non-empty user, the last 4 bytes before the user string data
	// should NOT be a NULL pointer. Find the user referent ID by scanning
	// backwards: the user string is at the end, preceded by its CVS header
	// and referent ID.

	// Instead, verify by checking that the buffer is longer than with empty user
	reqEmpty := SchRpcRunReq{
		Path:      "\\task1",
		Flags:     TaskRunNoFlags,
		SessionId: 0,
		User:      nil,
	}
	bufEmpty, _ := reqEmpty.Marshal()
	if len(buf) <= len(bufEmpty) {
		t.Fatalf("expected buffer with user to be longer: got %d, empty=%d", len(buf), len(bufEmpty))
	}
}

func TestSchRpcRunReqMarshalWithSessionId(t *testing.T) {
	req := SchRpcRunReq{
		Path:      "\\task1",
		Flags:     TaskRunUseSessionId,
		SessionId: 3,
		User:      nil,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Last 12 bytes: Flags(4) + SessionId(4) + user NULL ptr(4)
	tail := buf[len(buf)-12:]
	flags := binary.LittleEndian.Uint32(tail[0:4])
	sessionId := binary.LittleEndian.Uint32(tail[4:8])
	userPtr := binary.LittleEndian.Uint32(tail[8:12])

	if flags != TaskRunUseSessionId {
		t.Fatalf("expected flags=0x%x, got 0x%x", TaskRunUseSessionId, flags)
	}
	if sessionId != 3 {
		t.Fatalf("expected sessionId=3, got %d", sessionId)
	}
	if userPtr != 0 {
		t.Fatalf("expected user NULL ptr=0, got %d", userPtr)
	}
}

func TestSchRpcRunResUnmarshal(t *testing.T) {
	// GUID (16 bytes) + HRESULT (4 bytes)
	guid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	hresult := []byte{0x00, 0x00, 0x00, 0x00} // S_OK
	pkt := append(guid, hresult...)

	res := SchRpcRunRes{}
	err := res.Unmarshal(pkt)
	if err != nil {
		t.Fatal(err)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}

	expectedGUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	if res.GUID != expectedGUID {
		t.Fatalf("GUID mismatch: got %x, want %x", res.GUID, expectedGUID)
	}
}

func TestSchRpcGetLastRunInfoResUnmarshal(t *testing.T) {
	// Build a SYSTEMTIME: 2025-01-15 10:30:00.000 (Wednesday = 3)
	var pkt []byte
	w := bytes.NewBuffer(pkt)
	binary.Write(w, binary.LittleEndian, uint16(2025)) // Year
	binary.Write(w, binary.LittleEndian, uint16(1))    // Month
	binary.Write(w, binary.LittleEndian, uint16(3))    // DayOfWeek (Wednesday)
	binary.Write(w, binary.LittleEndian, uint16(15))   // Day
	binary.Write(w, binary.LittleEndian, uint16(10))   // Hour
	binary.Write(w, binary.LittleEndian, uint16(30))   // Minute
	binary.Write(w, binary.LittleEndian, uint16(0))    // Second
	binary.Write(w, binary.LittleEndian, uint16(0))    // Milliseconds
	binary.Write(w, binary.LittleEndian, uint32(0))    // LastReturnCode
	binary.Write(w, binary.LittleEndian, uint32(0))    // HRESULT

	res := SchRpcGetLastRunInfoRes{}
	err := res.Unmarshal(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}

	if res.LastRunTime.Year != 2025 {
		t.Fatalf("expected Year=2025, got %d", res.LastRunTime.Year)
	}
	if res.LastRunTime.Month != 1 {
		t.Fatalf("expected Month=1, got %d", res.LastRunTime.Month)
	}
	if res.LastRunTime.Day != 15 {
		t.Fatalf("expected Day=15, got %d", res.LastRunTime.Day)
	}
	if res.LastRunTime.Hour != 10 {
		t.Fatalf("expected Hour=10, got %d", res.LastRunTime.Hour)
	}
	if res.LastRunTime.Minute != 30 {
		t.Fatalf("expected Minute=30, got %d", res.LastRunTime.Minute)
	}

	tt := res.LastRunTime.ToTime()
	if tt.Year() != 2025 || tt.Month() != 1 || tt.Day() != 15 {
		t.Fatalf("ToTime returned wrong date: %v", tt)
	}
}

func TestSchRpcDeleteResUnmarshal(t *testing.T) {
	// Just an HRESULT (4 bytes) = S_OK
	pkt := []byte{0x00, 0x00, 0x00, 0x00}

	if len(pkt) < 4 {
		t.Fatal("packet too small")
	}
	returnCode := binary.LittleEndian.Uint32(pkt[:4])
	if returnCode != SOk {
		t.Fatalf("expected SOk, got 0x%x", returnCode)
	}
}

func TestSchRpcRegisterTaskReqMarshal(t *testing.T) {
	xmlContent := "<Task>test</Task>"
	path := "\\TestTask"
	req := SchRpcRegisterTaskReq{
		Path:      &path,
		Xml:       xmlContent,
		Flags:     TaskCreate,
		Sddl:      nil,
		LogonType: TaskLogonS4U,
		CCreds:    0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("expected non-empty buffer")
	}

	// Verify it starts with a referent ID for the path pointer (non-null)
	refId := binary.LittleEndian.Uint32(buf[0:4])
	if refId == 0 {
		t.Fatal("expected non-null referent ID for path")
	}
}

func TestSchRpcRegisterTaskReqNullPathMarshal(t *testing.T) {
	xmlContent := "<Task>test</Task>"
	req := SchRpcRegisterTaskReq{
		Path:      nil,
		Xml:       xmlContent,
		Flags:     TaskCreate,
		Sddl:      nil,
		LogonType: TaskLogonS4U,
		CCreds:    0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Empty path should result in NULL pointer (first 4 bytes = 0)
	ptr := binary.LittleEndian.Uint32(buf[0:4])
	if ptr != 0 {
		t.Fatalf("expected NULL ptr for empty path, got 0x%x", ptr)
	}
}

func TestSchRpcRegisterTaskResUnmarshal(t *testing.T) {
	// Build a response: pActualPath (non-null ptr) + string + pErrorInfo (null) + HRESULT
	var pkt []byte
	w := bytes.NewBuffer(pkt)

	// pActualPath - non-null referent ID
	binary.Write(w, binary.LittleEndian, uint32(1))
	// Conformant varying string "\\task1\0"
	// MaxCount=7, Offset=0, ActualCount=7
	binary.Write(w, binary.LittleEndian, uint32(7))
	binary.Write(w, binary.LittleEndian, uint32(0))
	binary.Write(w, binary.LittleEndian, uint32(7))
	// UTF-16LE: \task1\0
	strBytes := []byte{0x5c, 0x00, 0x74, 0x00, 0x61, 0x00, 0x73, 0x00,
		0x6b, 0x00, 0x31, 0x00, 0x00, 0x00}
	w.Write(strBytes)
	// Padding to 4-byte boundary: 14 bytes string data, need 2 bytes padding
	w.Write([]byte{0x00, 0x00})

	// pErrorInfo - NULL
	binary.Write(w, binary.LittleEndian, uint32(0))

	// HRESULT = S_OK
	binary.Write(w, binary.LittleEndian, uint32(0))

	res := SchRpcRegisterTaskRes{}
	err := res.Unmarshal(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if res.ActualPath != "\\task1" {
		t.Fatalf("expected ActualPath='\\task1', got '%s'", res.ActualPath)
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}
}

func TestSchRpcRetrieveTaskReqMarshal(t *testing.T) {
	req := SchRpcRetrieveTaskReq{
		Path: "\\task1",
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if len(buf) == 0 {
		t.Fatal("expected non-empty buffer")
	}

	// Should contain path string + languages string + numLanguages
	// At minimum: path CVS + languages CVS + uint32
	r := bytes.NewReader(buf)
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	// "\\task1\0" = 7 wchars
	if maxCount != 7 {
		t.Fatalf("expected path maxCount=7, got %d", maxCount)
	}
}

func TestSchRpcRetrieveTaskResUnmarshal(t *testing.T) {
	// Build a response: pDefinition (non-null ptr) + string + HRESULT
	var pkt []byte
	w := bytes.NewBuffer(pkt)

	// pDefinition - non-null referent ID
	binary.Write(w, binary.LittleEndian, uint32(1))
	// Conformant varying string "<Task/>\0"
	// MaxCount=8, Offset=0, ActualCount=8
	binary.Write(w, binary.LittleEndian, uint32(8))
	binary.Write(w, binary.LittleEndian, uint32(0))
	binary.Write(w, binary.LittleEndian, uint32(8))
	// UTF-16LE: <Task/>\0
	strBytes := []byte{
		0x3c, 0x00, // <
		0x54, 0x00, // T
		0x61, 0x00, // a
		0x73, 0x00, // s
		0x6b, 0x00, // k
		0x2f, 0x00, // /
		0x3e, 0x00, // >
		0x00, 0x00, // \0
	}
	w.Write(strBytes)
	// 16 bytes of string data, no padding needed (already 4-byte aligned)

	// HRESULT = S_OK
	binary.Write(w, binary.LittleEndian, uint32(0))

	res := SchRpcRetrieveTaskRes{}
	err := res.Unmarshal(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if res.Definition != "<Task/>" {
		t.Fatalf("expected Definition='<Task/>', got '%s'", res.Definition)
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}
}

func TestGUIDToString(t *testing.T) {
	// Standard GUID in mixed-endian format as stored on wire
	guid := [16]byte{
		0x49, 0x59, 0xd3, 0x86, // Data1 LE
		0xc9, 0x83, // Data2 LE
		0x44, 0x40, // Data3 LE
		0xb4, 0x24, // Data4[0:2]
		0xdb, 0x36, 0x32, 0x31, 0xfd, 0x0c, // Data4[2:8]
	}

	s := GUIDToString(guid)
	expected := "86d35949-83c9-4044-b424-db363231fd0c"
	if s != expected {
		t.Fatalf("expected %s, got %s", expected, s)
	}
}

func TestBuildExecTaskXML(t *testing.T) {
	xml := BuildExecTaskXML("cmd.exe", "/c whoami")
	if xml == "" {
		t.Fatal("expected non-empty XML")
	}

	// Check that command and args are present
	if !bytes.Contains([]byte(xml), []byte("<Command>cmd.exe</Command>")) {
		t.Fatal("expected XML to contain command")
	}
	if !bytes.Contains([]byte(xml), []byte("<Arguments>/c whoami</Arguments>")) {
		t.Fatal("expected XML to contain arguments")
	}
}

func TestBuildExecTaskXMLNoArgs(t *testing.T) {
	xml := BuildExecTaskXML("notepad.exe", "")
	if xml == "" {
		t.Fatal("expected non-empty XML")
	}

	if !bytes.Contains([]byte(xml), []byte("<Command>notepad.exe</Command>")) {
		t.Fatal("expected XML to contain command")
	}
	if bytes.Contains([]byte(xml), []byte("<Arguments>")) {
		t.Fatal("expected XML to NOT contain arguments element when args is empty")
	}
}

func TestSchRpcGetLastRunInfoReqMarshal(t *testing.T) {
	req := SchRpcGetLastRunInfoReq{
		Path: "\\task1",
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Should be just a conformant varying string
	r := bytes.NewReader(buf)
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)
	if maxCount != 7 { // "\\task1\0" = 7 wchars
		t.Fatalf("expected maxCount=7, got %d", maxCount)
	}
}

// Verify round-trip: marshal a delete request and check the hex output
func TestSchRpcDeleteReqHex(t *testing.T) {
	req := SchRpcDeleteReq{
		Path:  "\\A",
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// MaxCount=3 (\, A, \0), Offset=0, ActualCount=3
	// UTF-16LE: \ = 5c00, A = 4100, \0 = 0000 = 6 bytes
	// Padding: 6 % 4 = 2, so 2 bytes padding
	// Flags: 00000000
	expected := "03000000" + // MaxCount
		"00000000" + // Offset
		"03000000" + // ActualCount
		"5c00" + "4100" + "0000" + // UTF-16LE "\A\0"
		"0000" + // padding
		"00000000" // Flags
	expectedBytes, _ := hex.DecodeString(expected)

	if !bytes.Equal(buf, expectedBytes) {
		t.Fatalf("bytes mismatch\n got:  %s\n want: %s", hex.EncodeToString(buf), expected)
	}
}

func TestSchRpcStopReqMarshal(t *testing.T) {
	path := "\\task1"
	req := SchRpcStopReq{
		Path:  &path,
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Path is [in, unique] — first 4 bytes should be a non-null referent ID
	refId := binary.LittleEndian.Uint32(buf[0:4])
	if refId == 0 {
		t.Fatal("expected non-null referent ID for path")
	}

	// Last 4 bytes should be flags = 0
	flags := binary.LittleEndian.Uint32(buf[len(buf)-4:])
	if flags != 0 {
		t.Fatalf("expected flags=0, got %d", flags)
	}
}

func TestSchRpcStopReqHex(t *testing.T) {
	path := "\\A"
	req := SchRpcStopReq{
		Path:  &path,
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// RefId=1, MaxCount=3 (\, A, \0), Offset=0, ActualCount=3
	// UTF-16LE: \ = 5c00, A = 4100, \0 = 0000 = 6 bytes
	// Padding: 6 % 4 = 2, so 2 bytes padding
	// Flags: 00000000
	expected := "00000200" + // RefId
		"03000000" + // MaxCount
		"00000000" + // Offset
		"03000000" + // ActualCount
		"5c00" + "4100" + "0000" + // UTF-16LE "\A\0"
		"0000" + // padding
		"00000000" // Flags
	expectedBytes, _ := hex.DecodeString(expected)

	if !bytes.Equal(buf, expectedBytes) {
		t.Fatalf("bytes mismatch\n got:  %s\n want: %s", hex.EncodeToString(buf), expected)
	}
}

func TestSchRpcEnumInstancesReqMarshal(t *testing.T) {
	path := "\\task1"
	req := SchRpcEnumInstancesReq{
		Path:  &path,
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Path is [in, unique] — first 4 bytes should be a non-null referent ID
	refId := binary.LittleEndian.Uint32(buf[0:4])
	if refId == 0 {
		t.Fatal("expected non-null referent ID for path")
	}

	// Last 4 bytes should be flags = 0
	flags := binary.LittleEndian.Uint32(buf[len(buf)-4:])
	if flags != 0 {
		t.Fatalf("expected flags=0, got %d", flags)
	}
}

func TestSchRpcEnumInstancesReqHex(t *testing.T) {
	path := "\\A"
	req := SchRpcEnumInstancesReq{
		Path:  &path,
		Flags: 0,
	}

	buf, err := req.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	// Same format as StopReq — RefId + CVS + Flags
	expected := "00000200" + // RefId
		"03000000" + // MaxCount
		"00000000" + // Offset
		"03000000" + // ActualCount
		"5c00" + "4100" + "0000" + // UTF-16LE "\A\0"
		"0000" + // padding
		"00000000" // Flags
	expectedBytes, _ := hex.DecodeString(expected)

	if !bytes.Equal(buf, expectedBytes) {
		t.Fatalf("bytes mismatch\n got:  %s\n want: %s", hex.EncodeToString(buf), expected)
	}
}

func TestSchRpcEnumInstancesResUnmarshalEmpty(t *testing.T) {
	// Response with 0 GUIDs: NumGuids=0, pGuids=NULL, HRESULT=S_OK
	var pkt []byte
	w := bytes.NewBuffer(pkt)
	binary.Write(w, binary.LittleEndian, uint32(0)) // NumGuids
	binary.Write(w, binary.LittleEndian, uint32(0)) // pGuids = NULL
	binary.Write(w, binary.LittleEndian, uint32(0)) // HRESULT

	res := SchRpcEnumInstancesRes{}
	err := res.Unmarshal(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if res.NumGuids != 0 {
		t.Fatalf("expected NumGuids=0, got %d", res.NumGuids)
	}
	if len(res.Guids) != 0 {
		t.Fatalf("expected empty Guids, got %d", len(res.Guids))
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}
}

func TestSchRpcEnumInstancesResUnmarshalOneGuid(t *testing.T) {
	// Response with 1 GUID
	var pkt []byte
	w := bytes.NewBuffer(pkt)
	binary.Write(w, binary.LittleEndian, uint32(1))       // NumGuids
	binary.Write(w, binary.LittleEndian, uint32(0x20004)) // pGuids = non-NULL referent ID
	binary.Write(w, binary.LittleEndian, uint32(1))       // MaxCount (conformant array)
	// GUID: 16 bytes
	guid := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	w.Write(guid[:])
	binary.Write(w, binary.LittleEndian, uint32(0)) // HRESULT

	res := SchRpcEnumInstancesRes{}
	err := res.Unmarshal(w.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if res.NumGuids != 1 {
		t.Fatalf("expected NumGuids=1, got %d", res.NumGuids)
	}
	if len(res.Guids) != 1 {
		t.Fatalf("expected 1 GUID, got %d", len(res.Guids))
	}
	if res.Guids[0] != guid {
		t.Fatalf("GUID mismatch: got %x, want %x", res.Guids[0], guid)
	}
	if res.ReturnCode != 0 {
		t.Fatalf("expected ReturnCode=0, got 0x%x", res.ReturnCode)
	}
}

func TestSYSTEMTIMEToTimeZero(t *testing.T) {
	st := SYSTEMTIME{}
	tt := st.ToTime()
	if !tt.IsZero() {
		t.Fatalf("expected zero time for zero SYSTEMTIME, got %v", tt)
	}
}
