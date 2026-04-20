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
package msdcom

import (
	"testing"
)

func TestCimValueSize(t *testing.T) {
	tests := []struct {
		cimType uint32
		want    int
	}{
		{cimTypeString, 4},
		{cimTypeObject, 4},
		{cimTypeUint32, 4},
		{cimTypeSint32, 4},
		{cimTypeUint16, 2},
		{cimTypeSint16, 2},
		{cimTypeBoolean, 2},
		{cimTypeUint64, 8},
		{cimTypeSint64, 8},
		{cimTypeUint8, 1},
		{cimTypeSint8, 1},
		{cimTypeString | cimTypeArray, 4}, // array type → HeapRef
	}

	for _, tc := range tests {
		got := cimValueSize(tc.cimType)
		if got != tc.want {
			t.Errorf("cimValueSize(0x%x) = %d, want %d", tc.cimType, got, tc.want)
		}
	}
}

func TestReadEncodedStringASCII(t *testing.T) {
	// ASCII encoded string: flag(0x00) + "Hello" + null
	heap := []byte{0x00, 'H', 'e', 'l', 'l', 'o', 0x00}

	s := readEncodedString(heap, 0)
	if s != "Hello" {
		t.Fatalf("expected 'Hello', got %q", s)
	}
}

func TestReadEncodedStringUnicode(t *testing.T) {
	// UTF-16LE encoded string: flag(0x01) + "Hi" + null
	heap := []byte{
		0x01,       // Unicode flag
		'H', 0x00, // 'H'
		'i', 0x00, // 'i'
		0x00, 0x00, // null terminator
	}

	s := readEncodedString(heap, 0)
	if s != "Hi" {
		t.Fatalf("expected 'Hi', got %q", s)
	}
}

func TestReadEncodedStringOutOfBounds(t *testing.T) {
	heap := []byte{0x00, 'A', 0x00}

	s := readEncodedString(heap, 100) // offset beyond heap
	if s != "" {
		t.Fatalf("expected empty string, got %q", s)
	}
}

func TestAppendEncodedString(t *testing.T) {
	buf := appendEncodedString(nil, "cmd")

	// Expected: 0x00 (ASCII) + "cmd" + 0x00
	expected := []byte{0x00, 'c', 'm', 'd', 0x00}
	if len(buf) != len(expected) {
		t.Fatalf("expected %d bytes, got %d", len(expected), len(buf))
	}
	for i := range expected {
		if buf[i] != expected[i] {
			t.Fatalf("byte %d: expected 0x%02x, got 0x%02x", i, expected[i], buf[i])
		}
	}

	// Verify round-trip
	s := readEncodedString(buf, 0)
	if s != "cmd" {
		t.Fatalf("round-trip: expected 'cmd', got %q", s)
	}
}

func TestEncodedStringSize(t *testing.T) {
	// ASCII: flag + "test" + null = 6 bytes
	ascii := []byte{0x00, 't', 'e', 's', 't', 0x00}
	n, err := encodedStringSize(ascii)
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Fatalf("expected 6, got %d", n)
	}

	// UTF-16: flag + "AB" + null = 1 + 4 + 2 = 7 bytes
	unicode := []byte{0x01, 'A', 0x00, 'B', 0x00, 0x00, 0x00}
	n, err = encodedStringSize(unicode)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("expected 7, got %d", n)
	}
}

func TestSkipDecoration(t *testing.T) {
	// Decoration = two ENCODED_STRINGs
	// ServerName: ASCII "SRV" + null = 5 bytes
	// Namespace: ASCII "ns" + null = 4 bytes
	decoration := []byte{
		0x00, 'S', 'R', 'V', 0x00, // ServerName
		0x00, 'n', 's', 0x00, // Namespace
	}

	n, err := skipDecoration(decoration)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 {
		t.Fatalf("expected 9 bytes skipped, got %d", n)
	}
}

// buildSyntheticClassPart constructs a minimal ClassPart with the given properties.
// Properties are all CIM_STRING type for simplicity.
func buildSyntheticClassPart(className string, propNames []string) []byte {
	propCount := len(propNames)

	// Build ClassHeap first so we know offsets
	heap := make([]byte, 0, 256)

	// Class name at offset 0
	classNameRef := uint32(len(heap))
	heap = appendEncodedString(heap, className)

	// Property entries in the heap
	type propInfo struct {
		nameRef uint32
		infoRef uint32
	}
	infos := make([]propInfo, propCount)

	for i, name := range propNames {
		infos[i].nameRef = uint32(len(heap))
		heap = appendEncodedString(heap, name)
	}

	// PropertyInfo entries in heap: each 14 bytes minimum
	// PropertyType(4) + DeclarationOrder(2) + ValueTableOffset(4) + ClassOfOrigin(4) + QualifierSet(4)
	for i := range propNames {
		infos[i].infoRef = uint32(len(heap))
		b := make([]byte, 18)
		le.PutUint32(b[0:4], cimTypeString) // PropertyType = CIM_STRING
		le.PutUint16(b[4:6], uint16(i))     // DeclarationOrder
		le.PutUint32(b[6:10], uint32(i*4))  // ValueTableOffset (4 bytes per string HeapRef)
		le.PutUint32(b[10:14], 0)           // ClassOfOrigin
		le.PutUint32(b[14:18], 4)           // QualifierSet EncodingLength = 4 (empty)
		heap = append(heap, b...)
	}

	// Heap wire format: HeapLength(4, MSB set) + HeapData
	heapLen := uint32(len(heap)) | 0x80000000
	heapBuf := make([]byte, 4+len(heap))
	le.PutUint32(heapBuf[0:4], heapLen)
	copy(heapBuf[4:], heap)

	// NdTable: 1 bit per property (all null/default for class)
	ndTableSize := (propCount + 3) / 4
	if ndTableSize == 0 {
		ndTableSize = 1 // minimum 1 byte
	}

	// Value table: 4 bytes per string property (all zeros = null HeapRefs)
	valueTableSize := propCount * 4
	ndTableValueLength := ndTableSize + valueTableSize

	// DerivationList: empty (just EncodingLength = 4)
	derivListLen := 4

	// ClassQualifierSet: empty (just EncodingLength = 4)
	qualSetLen := 4

	// PropertyLookupTable: PropertyCount(4) + entries(8 each)
	propTableLen := 4 + propCount*8

	// Total ClassPart size
	classPartLen := 13 + derivListLen + qualSetLen + propTableLen + ndTableValueLength + len(heapBuf)

	buf := make([]byte, 0, classPartLen)

	// ClassHeader (13 bytes)
	b := make([]byte, 13)
	le.PutUint32(b[0:4], uint32(classPartLen)) // EncodingLength (includes itself)
	b[4] = 0                                    // ReservedOctet
	le.PutUint32(b[5:9], classNameRef)          // ClassNameRef
	le.PutUint32(b[9:13], uint32(ndTableValueLength))
	buf = append(buf, b...)

	// DerivationList (4 bytes: just EncodingLength)
	b4 := [4]byte{}
	le.PutUint32(b4[:], uint32(derivListLen))
	buf = append(buf, b4[:]...)

	// ClassQualifierSet (4 bytes: just EncodingLength)
	le.PutUint32(b4[:], uint32(qualSetLen))
	buf = append(buf, b4[:]...)

	// PropertyLookupTable
	le.PutUint32(b4[:], uint32(propCount))
	buf = append(buf, b4[:]...)
	for i := 0; i < propCount; i++ {
		entry := make([]byte, 8)
		le.PutUint32(entry[0:4], infos[i].nameRef)
		le.PutUint32(entry[4:8], infos[i].infoRef)
		buf = append(buf, entry...)
	}

	// NdTable (all ones = all null)
	ndTable := make([]byte, ndTableSize)
	for i := range ndTable {
		ndTable[i] = 0xFF
	}
	buf = append(buf, ndTable...)

	// Value table (all zeros)
	buf = append(buf, make([]byte, valueTableSize)...)

	// ClassHeap
	buf = append(buf, heapBuf...)

	return buf
}

// buildSyntheticMethodsPart creates a MethodsPart with one method containing
// an InputSignature that wraps the given ClassPart as an ObjectBlock.
func buildSyntheticMethodsPart(methodName string, inParamsClassPart []byte) []byte {
	// Build MethodHeap contents:
	// 1. Method name (ENCODED_STRING)
	// 2. InputSignature (METHOD_SIGNATURE_BLOCK = EncodingLength + ObjectBlock)
	methodHeap := make([]byte, 0, 256)
	nameRef := uint32(len(methodHeap))
	methodHeap = appendEncodedString(methodHeap, methodName)

	// InputSignature ObjectBlock = ObjectFlags(1) + ClassType
	// ClassType = ParentClass(empty, 4 bytes) + CurrentClass(ClassAndMethodsPart)
	// CurrentClass ClassAndMethodsPart = ClassPart + empty MethodsPart
	// Empty MethodsPart: EncodingLength(4)=8, MethodCount(2)=0, Padding(2)=0, HeapLen(4)=0|MSB
	emptyMethods := make([]byte, 12)
	le.PutUint32(emptyMethods[0:4], 12) // EncodingLength includes itself
	le.PutUint16(emptyMethods[4:6], 0)  // MethodCount = 0
	le.PutUint16(emptyMethods[6:8], 0)  // MethodCountPadding
	le.PutUint32(emptyMethods[8:12], 0x80000000) // Empty MethodHeap

	emptyParent := make([]byte, 4)
	// ParentClass: EncodingLength = 0 (empty)

	inSigObjBlock := make([]byte, 0, 1+4+len(inParamsClassPart)+len(emptyMethods))
	inSigObjBlock = append(inSigObjBlock, cimFlagClass) // ObjectFlags: class, no decoration
	inSigObjBlock = append(inSigObjBlock, emptyParent...)
	inSigObjBlock = append(inSigObjBlock, inParamsClassPart...)
	inSigObjBlock = append(inSigObjBlock, emptyMethods...)

	// METHOD_SIGNATURE_BLOCK: EncodingLength(4, does NOT include itself) + ObjectBlock
	inputSigRef := uint32(len(methodHeap))
	b4 := [4]byte{}
	le.PutUint32(b4[:], uint32(len(inSigObjBlock)))
	methodHeap = append(methodHeap, b4[:]...)
	methodHeap = append(methodHeap, inSigObjBlock...)

	// Build heap wire format
	heapLen := uint32(len(methodHeap)) | 0x80000000
	heapBuf := make([]byte, 4+len(methodHeap))
	le.PutUint32(heapBuf[0:4], heapLen)
	copy(heapBuf[4:], methodHeap)

	// MethodDescription: 24 bytes fixed
	// MethodName(4) + Flags(1) + Padding(3) + Origin(4) + Qualifiers(4) + InSig(4) + OutSig(4)
	methodDesc := make([]byte, 24)
	le.PutUint32(methodDesc[0:4], nameRef)       // MethodName (HeapRef)
	methodDesc[4] = 0                            // MethodFlags (1 byte)
	// methodDesc[5:8] = padding (3 bytes, zero)
	le.PutUint32(methodDesc[8:12], 0)            // MethodOrigin
	le.PutUint32(methodDesc[12:16], 0xFFFFFFFF)  // MethodQualifiers (none)
	le.PutUint32(methodDesc[16:20], inputSigRef) // InputSignature (HeapRef)
	le.PutUint32(methodDesc[20:24], 0xFFFFFFFF)  // OutputSignature (none)

	// MethodsPart: EncodingLength(4, includes itself) + MethodCount(2) + Padding(2) + MethodDesc + MethodHeap
	totalLen := 4 + 2 + 2 + len(methodDesc) + len(heapBuf) // 4 for EncodingLength itself
	result := make([]byte, 0, totalLen)
	le.PutUint32(b4[:], uint32(totalLen))
	result = append(result, b4[:]...)           // EncodingLength
	result = append(result, 0x01, 0x00)         // MethodCount = 1
	result = append(result, 0x00, 0x00)         // MethodCountPadding
	result = append(result, methodDesc...)
	result = append(result, heapBuf...)

	return result
}

func TestParseClassPart(t *testing.T) {
	classPart := buildSyntheticClassPart("TestClass", []string{"Prop1", "Prop2", "Prop3"})

	classDef, err := parseClassPart(classPart)
	if err != nil {
		t.Fatal(err)
	}

	if classDef.className != "TestClass" {
		t.Fatalf("expected className 'TestClass', got %q", classDef.className)
	}

	if len(classDef.properties) != 3 {
		t.Fatalf("expected 3 properties, got %d", len(classDef.properties))
	}

	for i, name := range []string{"Prop1", "Prop2", "Prop3"} {
		if classDef.properties[i].name != name {
			t.Fatalf("property %d: expected %q, got %q", i, name, classDef.properties[i].name)
		}
		if classDef.properties[i].cimType != cimTypeString {
			t.Fatalf("property %d: expected CIM_STRING, got 0x%x", i, classDef.properties[i].cimType)
		}
		if classDef.properties[i].offset != i*4 {
			t.Fatalf("property %d: expected offset %d, got %d", i, i*4, classDef.properties[i].offset)
		}
	}

	if classDef.valueTableSize != 12 { // 3 * 4 bytes
		t.Fatalf("expected valueTableSize 12, got %d", classDef.valueTableSize)
	}
}

func TestFindMethodInParams(t *testing.T) {
	// Build a class part for the InParams (2 string properties)
	inParamsClassPart := buildSyntheticClassPart("CreateInput", []string{"CommandLine", "CurrentDirectory"})

	// Build MethodsPart with a "Create" method
	methodsPart := buildSyntheticMethodsPart("Create", inParamsClassPart)

	// Find the Create method's InParams
	inParamsBlock, err := findMethodInParams(methodsPart, "Create")
	if err != nil {
		t.Fatal(err)
	}

	// Parse the returned ObjectBlock
	classDef, err := parseClassFromObjectBlock(inParamsBlock)
	if err != nil {
		t.Fatal(err)
	}

	if classDef.className != "CreateInput" {
		t.Fatalf("expected className 'CreateInput', got %q", classDef.className)
	}

	if len(classDef.properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(classDef.properties))
	}

	if classDef.properties[0].name != "CommandLine" {
		t.Fatalf("expected first property 'CommandLine', got %q", classDef.properties[0].name)
	}
}

func TestFindMethodInParamsNotFound(t *testing.T) {
	inParamsClassPart := buildSyntheticClassPart("Input", []string{"Arg1"})
	methodsPart := buildSyntheticMethodsPart("DoSomething", inParamsClassPart)

	_, err := findMethodInParams(methodsPart, "Create")
	if err == nil {
		t.Fatal("expected error for method not found")
	}
}

func TestBuildCIMInstance(t *testing.T) {
	// Create a class definition with two string properties
	classPart := buildSyntheticClassPart("TestInput", []string{"CommandLine", "WorkDir"})

	classDef := &cimClassDef{
		className:          "TestInput",
		classPartRaw: classPart,
		valueTableSize:     8, // 2 * 4 bytes
		properties: []cimPropDef{
			{name: "CommandLine", cimType: cimTypeString, offset: 0},
			{name: "WorkDir", cimType: cimTypeString, offset: 4},
		},
	}

	// Build instance with only CommandLine set
	data, err := buildCIMInstance(classDef, map[string]MethodParam{
		"CommandLine": StringParam("cmd.exe /c whoami"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify EncodingUnit header
	if len(data) < 8 {
		t.Fatalf("instance too short: %d bytes", len(data))
	}
	if le.Uint32(data[0:4]) != cimSignature {
		t.Fatalf("bad signature: 0x%08x", le.Uint32(data[0:4]))
	}

	// Verify ObjectBlock flags
	objBlockStart := 8
	if data[objBlockStart] != cimFlagInstance {
		t.Fatalf("expected instance flag 0x%02x, got 0x%02x", cimFlagInstance, data[objBlockStart])
	}

	// The data should be parseable back
	// (basic structural check - the full round-trip is tested via ParseCIMInstanceValues)
	if len(data) < 20 {
		t.Fatalf("instance data too short for meaningful content: %d bytes", len(data))
	}
}

func TestBuildCIMInstanceWrongType(t *testing.T) {
	classDef := &cimClassDef{
		className:      "Test",
		classPartRaw:   make([]byte, 20),
		valueTableSize: 4,
		properties: []cimPropDef{
			{name: "Name", cimType: cimTypeString, offset: 0},
		},
	}

	// Setting an integer param on a string property should fail
	_, err := buildCIMInstance(classDef, map[string]MethodParam{
		"Name": UintParam(123),
	})
	if err == nil {
		t.Fatal("expected error when setting non-string param on string property")
	}
}

func TestBuildCIMInstanceIntegerTypes(t *testing.T) {
	classDef := &cimClassDef{
		className:      "Test",
		classPartRaw:   make([]byte, 20),
		valueTableSize: 20,
		properties: []cimPropDef{
			{name: "U32", cimType: cimTypeUint32, offset: 0},
			{name: "S32", cimType: cimTypeSint32, offset: 4},
			{name: "U16", cimType: cimTypeUint16, offset: 8},
			{name: "Flag", cimType: cimTypeBoolean, offset: 10},
			{name: "U8", cimType: cimTypeUint8, offset: 12},
			{name: "U64", cimType: cimTypeUint64, offset: 13},
		},
	}

	data, err := buildCIMInstance(classDef, map[string]MethodParam{
		"U32":  UintParam(0x80000002),
		"S32":  IntParam(-1),
		"U16":  UintParam(443),
		"Flag": BoolParam(true),
		"U8":   UintParam(255),
		"U64":  UintParam(9999999999),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(data) < 8 {
		t.Fatalf("instance too short: %d bytes", len(data))
	}
	if le.Uint32(data[0:4]) != cimSignature {
		t.Fatalf("bad signature: 0x%08x", le.Uint32(data[0:4]))
	}
}

func TestBuildCIMInstanceArrayTypes(t *testing.T) {
	classDef := &cimClassDef{
		className:      "Test",
		classPartRaw:   make([]byte, 20),
		valueTableSize: 8,
		properties: []cimPropDef{
			{name: "BinData", cimType: cimTypeArray | cimTypeUint8, offset: 0},
			{name: "Names", cimType: cimTypeArray | cimTypeString, offset: 4},
		},
	}

	data, err := buildCIMInstance(classDef, map[string]MethodParam{
		"BinData": BytesParam([]byte{0xDE, 0xAD, 0xBE, 0xEF}),
		"Names":   StringArrayParam([]string{"hello", "world"}),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(data) < 8 {
		t.Fatalf("instance too short: %d bytes", len(data))
	}
	if le.Uint32(data[0:4]) != cimSignature {
		t.Fatalf("bad signature: 0x%08x", le.Uint32(data[0:4]))
	}
}

func TestBuildCIMInstanceArrayWrongParam(t *testing.T) {
	classDef := &cimClassDef{
		className:      "Test",
		classPartRaw:   make([]byte, 20),
		valueTableSize: 4,
		properties: []cimPropDef{
			{name: "BinData", cimType: cimTypeArray | cimTypeUint8, offset: 0},
		},
	}

	// Using StringParam on a uint8 array should fail
	_, err := buildCIMInstance(classDef, map[string]MethodParam{
		"BinData": StringParam("not bytes"),
	})
	if err == nil {
		t.Fatal("expected error when using StringParam on uint8 array property")
	}
}

func TestGetMethodInParamsClass(t *testing.T) {
	// Build a full EncodingUnit with a class that has a "Create" method
	inParamsClassPart := buildSyntheticClassPart("CreateIn", []string{"CommandLine", "Directory"})
	methodsPart := buildSyntheticMethodsPart("Create", inParamsClassPart)

	// The outer class part (Win32_Process-like)
	outerClassPart := buildSyntheticClassPart("Win32_Process", []string{"Handle", "Name"})

	// Build CurrentClass ClassAndMethodsPart (has the methods we want)
	currentClassAndMethods := make([]byte, 0, len(outerClassPart)+len(methodsPart))
	currentClassAndMethods = append(currentClassAndMethods, outerClassPart...)
	currentClassAndMethods = append(currentClassAndMethods, methodsPart...)

	// Build ParentClass ClassAndMethodsPart (empty parent with no methods)
	parentClassPart := buildSyntheticClassPart("CIM_Process", nil)
	emptyMethodsPart := make([]byte, 12) // EncodingLength(4)=12 + MethodCount(2)=0 + Padding(2)=0 + HeapLen(4)=0|MSB
	le.PutUint32(emptyMethodsPart[0:4], 12)         // EncodingLength includes itself
	le.PutUint16(emptyMethodsPart[4:6], 0)           // MethodCount = 0
	le.PutUint16(emptyMethodsPart[6:8], 0)           // MethodCountPadding
	le.PutUint32(emptyMethodsPart[8:12], 0x80000000) // empty heap
	parentClassAndMethods := make([]byte, 0, len(parentClassPart)+len(emptyMethodsPart))
	parentClassAndMethods = append(parentClassAndMethods, parentClassPart...)
	parentClassAndMethods = append(parentClassAndMethods, emptyMethodsPart...)

	// ClassType = ParentClass + CurrentClass (MS-WMIO 2.2.14)
	classType := make([]byte, 0, len(parentClassAndMethods)+len(currentClassAndMethods))
	classType = append(classType, parentClassAndMethods...)
	classType = append(classType, currentClassAndMethods...)

	// Build ObjectBlock: flags(1) + ClassType
	objBlock := make([]byte, 0, 1+len(classType))
	objBlock = append(objBlock, cimFlagClass) // ObjectFlags: class, no decoration
	objBlock = append(objBlock, classType...)

	// Build EncodingUnit
	encodingUnit := make([]byte, 0, 8+len(objBlock))
	b4 := [4]byte{}
	le.PutUint32(b4[:], cimSignature)
	encodingUnit = append(encodingUnit, b4[:]...)
	le.PutUint32(b4[:], uint32(len(objBlock)))
	encodingUnit = append(encodingUnit, b4[:]...)
	encodingUnit = append(encodingUnit, objBlock...)

	// Parse and find Create method's InParams
	classDef, err := getMethodInParamsClass(encodingUnit, "Create")
	if err != nil {
		t.Fatal(err)
	}

	if classDef.className != "CreateIn" {
		t.Fatalf("expected className 'CreateIn', got %q", classDef.className)
	}

	if len(classDef.properties) != 2 {
		t.Fatalf("expected 2 properties, got %d", len(classDef.properties))
	}

	if classDef.properties[0].name != "CommandLine" {
		t.Fatalf("expected first property 'CommandLine', got %q", classDef.properties[0].name)
	}

	if classDef.classPartRaw == nil {
		t.Fatal("classPartRaw should be set")
	}
}

// buildSyntheticInstance constructs a CIM EncodingUnit containing an instance
// with the given typed properties. Each property is defined by a name, CIM type,
// and raw value bytes (at the correct size for that type). String values are
// written as Unicode ENCODED_STRINGs in the instance heap; the value bytes for
// string properties contain a 4-byte heap offset that is filled in automatically.
type syntheticProp struct {
	name    string
	cimType uint32
	value   []byte  // raw bytes for value table slot (nil = null)
	strVal  string  // for cimTypeString: the string value
}

func buildSyntheticEncodingUnit(className string, props []syntheticProp) []byte {
	propCount := len(props)

	// Build ClassHeap
	classHeap := make([]byte, 0, 256)
	classNameRef := uint32(len(classHeap))
	classHeap = appendEncodedString(classHeap, className)

	type pi struct {
		nameRef uint32
		infoRef uint32
	}
	infos := make([]pi, propCount)

	for i, p := range props {
		infos[i].nameRef = uint32(len(classHeap))
		classHeap = appendEncodedString(classHeap, p.name)
	}

	// Calculate value table layout
	valueTableSize := 0
	offsets := make([]int, propCount)
	for i, p := range props {
		offsets[i] = valueTableSize
		valueTableSize += cimValueSize(p.cimType)
	}

	for i, p := range props {
		infos[i].infoRef = uint32(len(classHeap))
		b := make([]byte, 18)
		le.PutUint32(b[0:4], p.cimType)
		le.PutUint16(b[4:6], uint16(i))
		le.PutUint32(b[6:10], uint32(offsets[i]))
		le.PutUint32(b[10:14], 0)
		le.PutUint32(b[14:18], 4)
		classHeap = append(classHeap, b...)
	}

	classHeapLen := uint32(len(classHeap)) | 0x80000000
	classHeapBuf := make([]byte, 4+len(classHeap))
	le.PutUint32(classHeapBuf[0:4], classHeapLen)
	copy(classHeapBuf[4:], classHeap)

	ndTableSize := (propCount + 3) / 4
	if ndTableSize == 0 {
		ndTableSize = 1
	}
	ndTableValueLength := ndTableSize + valueTableSize
	derivListLen := 4
	qualSetLen := 4
	propTableLen := 4 + propCount*8
	classPartLen := 13 + derivListLen + qualSetLen + propTableLen + ndTableValueLength + len(classHeapBuf)

	classPart := make([]byte, 0, classPartLen)
	hdr := make([]byte, 13)
	le.PutUint32(hdr[0:4], uint32(classPartLen))
	hdr[4] = 0
	le.PutUint32(hdr[5:9], classNameRef)
	le.PutUint32(hdr[9:13], uint32(ndTableValueLength))
	classPart = append(classPart, hdr...)

	b4 := [4]byte{}
	le.PutUint32(b4[:], uint32(derivListLen))
	classPart = append(classPart, b4[:]...)
	le.PutUint32(b4[:], uint32(qualSetLen))
	classPart = append(classPart, b4[:]...)

	le.PutUint32(b4[:], uint32(propCount))
	classPart = append(classPart, b4[:]...)
	for i := 0; i < propCount; i++ {
		entry := make([]byte, 8)
		le.PutUint32(entry[0:4], infos[i].nameRef)
		le.PutUint32(entry[4:8], infos[i].infoRef)
		classPart = append(classPart, entry...)
	}
	classPart = append(classPart, make([]byte, ndTableValueLength)...)
	classPart = append(classPart, classHeapBuf...)

	// Build instance
	instNdTableSize := (propCount + 3) / 4
	if instNdTableSize == 0 {
		instNdTableSize = 1
	}
	instNdTable := make([]byte, instNdTableSize)

	instHeap := make([]byte, 0, 128)
	instHeap = appendEncodedString(instHeap, className)

	instData := make([]byte, valueTableSize)
	for i, p := range props {
		if p.value == nil && p.strVal == "" {
			// null
			byteIdx := i / 4
			bitOffset := uint((i % 4) * 2)
			instNdTable[byteIdx] |= byte(3 << bitOffset)
			continue
		}

		baseType := p.cimType & 0x1FFF
		if baseType == cimTypeString {
			heapOffset := uint32(len(instHeap))
			instHeap = appendEncodedStringUnicode(instHeap, p.strVal)
			if offsets[i]+4 <= len(instData) {
				le.PutUint32(instData[offsets[i]:], heapOffset)
			}
		} else if p.value != nil {
			copy(instData[offsets[i]:], p.value)
		}
	}

	instQualSet := []byte{0x04, 0x00, 0x00, 0x00, 0x01}

	instHeapBuf := make([]byte, 4+len(instHeap))
	le.PutUint32(instHeapBuf[0:4], uint32(len(instHeap))|0x80000000)
	copy(instHeapBuf[4:], instHeap)

	currentInstance := make([]byte, 0, 1+4+instNdTableSize+len(instData)+len(instQualSet))
	currentInstance = append(currentInstance, 0x00) // InstanceFlags
	le.PutUint32(b4[:], 0)
	currentInstance = append(currentInstance, b4[:]...)
	currentInstance = append(currentInstance, instNdTable...)
	currentInstance = append(currentInstance, instData...)
	currentInstance = append(currentInstance, instQualSet...)

	encLen := uint32(4 + len(currentInstance) + len(instHeapBuf))
	instanceType := make([]byte, 0, len(classPart)+4+len(currentInstance)+len(instHeapBuf))
	instanceType = append(instanceType, classPart...)
	le.PutUint32(b4[:], encLen)
	instanceType = append(instanceType, b4[:]...)
	instanceType = append(instanceType, currentInstance...)
	instanceType = append(instanceType, instHeapBuf...)

	objBlock := make([]byte, 0, 1+len(instanceType))
	objBlock = append(objBlock, cimFlagInstance)
	objBlock = append(objBlock, instanceType...)

	encodingUnit := make([]byte, 0, 8+len(objBlock))
	le.PutUint32(b4[:], cimSignature)
	encodingUnit = append(encodingUnit, b4[:]...)
	le.PutUint32(b4[:], uint32(len(objBlock)))
	encodingUnit = append(encodingUnit, b4[:]...)
	encodingUnit = append(encodingUnit, objBlock...)

	return encodingUnit
}

func TestParseCIMInstanceAllValues(t *testing.T) {
	// Build a synthetic instance with mixed types
	uint32Val := make([]byte, 4)
	le.PutUint32(uint32Val, 42)

	int32Val := make([]byte, 4)
	le.PutUint32(int32Val, 0xFFFFFFFF) // -1 in two's complement

	boolTrue := make([]byte, 2)
	le.PutUint16(boolTrue, 0xFFFF)

	uint64Val := make([]byte, 8)
	le.PutUint64(uint64Val, 9999999999)

	uint8Val := []byte{0xFF}

	data := buildSyntheticEncodingUnit("TestObj", []syntheticProp{
		{name: "Name", cimType: cimTypeString, strVal: "hello"},
		{name: "Count", cimType: cimTypeUint32, value: uint32Val},
		{name: "Status", cimType: cimTypeSint32, value: int32Val},
		{name: "Enabled", cimType: cimTypeBoolean, value: boolTrue},
		{name: "BigNum", cimType: cimTypeUint64, value: uint64Val},
		{name: "Flags", cimType: cimTypeUint8, value: uint8Val},
		{name: "NullProp", cimType: cimTypeString}, // null
	})

	result, err := ParseCIMInstanceAllValues(data)
	if err != nil {
		t.Fatal(err)
	}

	if v, ok := result["Name"]; !ok || v != "hello" {
		t.Fatalf("Name: expected 'hello', got %v", v)
	}
	if v, ok := result["Count"]; !ok || v != uint32(42) {
		t.Fatalf("Count: expected 42, got %v", v)
	}
	if v, ok := result["Status"]; !ok || v != int32(-1) {
		t.Fatalf("Status: expected -1, got %v", v)
	}
	if v, ok := result["Enabled"]; !ok || v != true {
		t.Fatalf("Enabled: expected true, got %v", v)
	}
	if v, ok := result["BigNum"]; !ok || v != uint64(9999999999) {
		t.Fatalf("BigNum: expected 9999999999, got %v", v)
	}
	if v, ok := result["Flags"]; !ok || v != byte(0xFF) {
		t.Fatalf("Flags: expected 0xFF, got %v", v)
	}
	if _, ok := result["NullProp"]; ok {
		t.Fatalf("NullProp should not be present in results")
	}
}

func TestParseCIMInstanceAllValuesEmpty(t *testing.T) {
	data := buildSyntheticEncodingUnit("Empty", nil)
	result, err := ParseCIMInstanceAllValues(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d entries", len(result))
	}
}

func TestBuildAndParseCIMInstance(t *testing.T) {
	// Build a class definition for output params (uint32 properties)
	// We need to build a class with uint32 properties, build an instance,
	// and parse it back.

	// For this test, we manually construct the classDef and instance bytes.
	// This tests the ParseCIMInstanceValues function.

	// Build a minimal class part with uint32 properties
	propNames := []string{"ReturnValue", "ProcessId"}
	propCount := len(propNames)

	// Build ClassHeap
	heap := make([]byte, 0, 256)
	classNameRef := uint32(len(heap))
	heap = appendEncodedString(heap, "Output")

	type pi struct {
		nameRef uint32
		infoRef uint32
	}
	infos := make([]pi, propCount)

	for i, name := range propNames {
		infos[i].nameRef = uint32(len(heap))
		heap = appendEncodedString(heap, name)
	}

	for i := range propNames {
		infos[i].infoRef = uint32(len(heap))
		b := make([]byte, 18)
		le.PutUint32(b[0:4], cimTypeUint32) // CIM_UINT32
		le.PutUint16(b[4:6], uint16(i))
		le.PutUint32(b[6:10], uint32(i*4)) // ValueTableOffset
		le.PutUint32(b[10:14], 0)
		le.PutUint32(b[14:18], 4) // empty qualifier set
		heap = append(heap, b...)
	}

	heapLen := uint32(len(heap)) | 0x80000000
	heapBuf := make([]byte, 4+len(heap))
	le.PutUint32(heapBuf[0:4], heapLen)
	copy(heapBuf[4:], heap)

	ndTableSize := 1 // ceil(2/8)
	valueTableSize := 8 // 2 * 4
	ndTableValueLength := ndTableSize + valueTableSize
	derivListLen := 4
	qualSetLen := 4
	propTableLen := 4 + propCount*8
	classPartLen := 13 + derivListLen + qualSetLen + propTableLen + ndTableValueLength + len(heapBuf)

	classPart := make([]byte, 0, classPartLen)

	// ClassHeader
	hdr := make([]byte, 13)
	le.PutUint32(hdr[0:4], uint32(classPartLen)) // EncodingLength includes itself
	hdr[4] = 0
	le.PutUint32(hdr[5:9], classNameRef)
	le.PutUint32(hdr[9:13], uint32(ndTableValueLength))
	classPart = append(classPart, hdr...)

	// DerivationList
	b4 := [4]byte{}
	le.PutUint32(b4[:], uint32(derivListLen))
	classPart = append(classPart, b4[:]...)

	// QualifierSet
	le.PutUint32(b4[:], uint32(qualSetLen))
	classPart = append(classPart, b4[:]...)

	// PropertyLookupTable
	le.PutUint32(b4[:], uint32(propCount))
	classPart = append(classPart, b4[:]...)
	for i := 0; i < propCount; i++ {
		entry := make([]byte, 8)
		le.PutUint32(entry[0:4], infos[i].nameRef)
		le.PutUint32(entry[4:8], infos[i].infoRef)
		classPart = append(classPart, entry...)
	}

	// NdTable + ValueTable
	classPart = append(classPart, make([]byte, ndTableValueLength)...)

	// ClassHeap
	classPart = append(classPart, heapBuf...)

	// Build InstanceType:
	//   CurrentClass (ClassPart only, no MethodsPart) + EncodingLength + CurrentInstance + InstanceHeap

	// Instance NdTable: 2 bits per property (all non-null = 0x00)
	instNdTableSize := 1 // ceil(2/4)

	// Instance data: ReturnValue=0, ProcessId=1234
	instData := make([]byte, 8) // 2 * 4 bytes
	le.PutUint32(instData[0:4], 0)    // ReturnValue = 0
	le.PutUint32(instData[4:8], 1234) // ProcessId = 1234

	// InstanceQualifierSet: QualifierSet(EncodingLength=4) + InstancePropQualifierSetFlag(0x01)
	instQualSet := []byte{0x04, 0x00, 0x00, 0x00, 0x01}

	// Instance heap: class name
	instHeap := make([]byte, 0, 32)
	instHeap = appendEncodedString(instHeap, "Output")
	instHeapBuf := make([]byte, 4+len(instHeap))
	le.PutUint32(instHeapBuf[0:4], uint32(len(instHeap))|0x80000000)
	copy(instHeapBuf[4:], instHeap)

	// CurrentInstance
	currentInstanceLen := 1 + 4 + instNdTableSize + len(instData) + len(instQualSet)
	currentInstance := make([]byte, 0, currentInstanceLen)
	currentInstance = append(currentInstance, 0x00) // InstanceFlags
	le.PutUint32(b4[:], 0)                         // ClassNameRef
	currentInstance = append(currentInstance, b4[:]...)
	currentInstance = append(currentInstance, 0x00) // NdTable: all non-null
	currentInstance = append(currentInstance, instData...)
	currentInstance = append(currentInstance, instQualSet...)

	// InstanceType: CurrentClass (ClassPart only, no MethodsPart) + EncodingLength + CurrentInstance + InstanceHeap
	// EncodingLength includes itself (4) + currentInstance + instanceHeap
	encLen := uint32(4 + len(currentInstance) + len(instHeapBuf))
	instanceType := make([]byte, 0, len(classPart)+4+len(currentInstance)+len(instHeapBuf))
	instanceType = append(instanceType, classPart...)
	le.PutUint32(b4[:], encLen)
	instanceType = append(instanceType, b4[:]...)
	instanceType = append(instanceType, currentInstance...)
	instanceType = append(instanceType, instHeapBuf...)

	// ObjectBlock: flags + InstanceType
	objBlock := make([]byte, 0, 1+len(instanceType))
	objBlock = append(objBlock, cimFlagInstance)
	objBlock = append(objBlock, instanceType...)

	// EncodingUnit
	encodingUnit := make([]byte, 0, 8+len(objBlock))
	le.PutUint32(b4[:], cimSignature)
	encodingUnit = append(encodingUnit, b4[:]...)
	le.PutUint32(b4[:], uint32(len(objBlock)))
	encodingUnit = append(encodingUnit, b4[:]...)
	encodingUnit = append(encodingUnit, objBlock...)

	// Parse!
	values, err := ParseCIMInstanceValues(encodingUnit)
	if err != nil {
		t.Fatal(err)
	}

	if rv, ok := values["ReturnValue"]; !ok || rv != 0 {
		t.Fatalf("ReturnValue: expected 0, got %d (ok=%v)", rv, ok)
	}

	if pid, ok := values["ProcessId"]; !ok || pid != 1234 {
		t.Fatalf("ProcessId: expected 1234, got %d (ok=%v)", pid, ok)
	}
}
