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
//
// CIM binary encoding structures for WMI IWbemClassObject marshaling.
// Implements minimal parsing and construction of CIM-encoded class definitions
// and instances as defined in [MS-WMIO].

package msdcom

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
)

// CIM encoding constants
const (
	cimSignature uint32 = 0x12345678

	// ObjectBlock flags (MS-WMIO 2.2.39)
	cimFlagClass      byte = 0x01
	cimFlagInstance   byte = 0x02
	cimFlagDecoration byte = 0x04

	// CIM types (MS-WMIO 2.2.62)
	cimTypeSint16  uint32 = 2
	cimTypeSint32  uint32 = 3
	cimTypeReal32  uint32 = 4
	cimTypeReal64  uint32 = 5
	cimTypeString  uint32 = 8
	cimTypeBoolean uint32 = 11
	cimTypeObject  uint32 = 13
	cimTypeSint8   uint32 = 16
	cimTypeUint8   uint32 = 17
	cimTypeUint16  uint32 = 18
	cimTypeUint32  uint32 = 19
	cimTypeSint64  uint32 = 20
	cimTypeUint64  uint32 = 21
	cimTypeDatetime uint32 = 0x65
	cimTypeArray    uint32 = 0x2000

	// Encoded string flags (MS-WMIO 2.2.76)
	// Note: despite the spec naming, Windows servers use 0x00 for ASCII
	// and 0x01 for Unicode (UTF-16LE) in practice.
	encodedStringASCII   byte = 0x00
	encodedStringUnicode byte = 0x01
)

// cimClassDef holds a parsed CIM class definition with enough information
// to create instances and read property values.
type cimClassDef struct {
	className          string
	properties         []cimPropDef
	valueTableSize     int    // size of property value table in bytes
	classPartRaw []byte // raw ClassPart bytes for instance CurrentClass (no MethodsPart)
}

// cimPropDef describes a property in a CIM class.
type cimPropDef struct {
	name   string
	cimType uint32
	offset int // offset in value table
}

// cimValueSize returns the fixed serialized size of a CIM property value slot.
func cimValueSize(t uint32) int {
	if t&cimTypeArray != 0 {
		return 4 // HeapRef for arrays
	}
	switch t & 0x1FFF {
	case cimTypeString, cimTypeDatetime, cimTypeObject:
		return 4 // HeapRef
	case cimTypeSint8, cimTypeUint8:
		return 1
	case cimTypeSint16, cimTypeUint16, cimTypeBoolean:
		return 2
	case cimTypeSint32, cimTypeUint32, cimTypeReal32:
		return 4
	case cimTypeSint64, cimTypeUint64, cimTypeReal64:
		return 8
	default:
		return 4
	}
}

// MethodParam holds a value to set on a CIM method input parameter.
// Use the helper constructors StringParam, UintParam, IntParam, BoolParam,
// BytesParam, and StringArrayParam.
type MethodParam struct {
	strVal      string
	uintVal     uint64
	intVal      int64
	boolVal     bool
	bytesVal    []byte
	strArrayVal []string
	kind        paramKind
}

type paramKind int

const (
	paramString paramKind = iota
	paramUint
	paramInt
	paramBool
	paramBytes
	paramStringArray
)

// StringParam creates a MethodParam for a string or datetime property.
func StringParam(s string) MethodParam { return MethodParam{strVal: s, kind: paramString} }

// UintParam creates a MethodParam for an unsigned integer property (uint8/16/32/64).
func UintParam(v uint64) MethodParam { return MethodParam{uintVal: v, kind: paramUint} }

// IntParam creates a MethodParam for a signed integer property (sint8/16/32/64).
func IntParam(v int64) MethodParam { return MethodParam{intVal: v, kind: paramInt} }

// BoolParam creates a MethodParam for a boolean property.
func BoolParam(b bool) MethodParam { return MethodParam{boolVal: b, kind: paramBool} }

// BytesParam creates a MethodParam for a uint8 array property (binary data).
func BytesParam(b []byte) MethodParam { return MethodParam{bytesVal: b, kind: paramBytes} }

// StringArrayParam creates a MethodParam for a string array property.
func StringArrayParam(ss []string) MethodParam {
	return MethodParam{strArrayVal: ss, kind: paramStringArray}
}

// BuildMethodInput parses a CIM class definition (from WMIClient.GetObject),
// finds the named method's input parameters, and builds a CIM-encoded instance
// with the given properties set. Properties not in the map are left NULL.
// Returns the raw CIM EncodingUnit bytes suitable for WMIClient.ExecMethod.
func BuildMethodInput(classData []byte, methodName string, params map[string]MethodParam) ([]byte, error) {
	inParamsClass, err := getMethodInParamsClass(classData, methodName)
	if err != nil {
		return nil, fmt.Errorf("parse %s InParams: %w", methodName, err)
	}
	return buildCIMInstance(inParamsClass, params)
}

// getMethodInParamsClass parses a CIM EncodingUnit for a class, finds the
// named method, and returns the parsed class definition of the method's
// input parameters.
func getMethodInParamsClass(data []byte, methodName string) (*cimClassDef, error) {
	// Parse EncodingUnit header
	if len(data) < 8 {
		return nil, fmt.Errorf("EncodingUnit too short (%d)", len(data))
	}
	sig := le.Uint32(data[0:4])
	if sig != cimSignature {
		return nil, fmt.Errorf("invalid CIM signature 0x%08x", sig)
	}
	objLen := le.Uint32(data[4:8])
	if len(data) < 8+int(objLen) {
		return nil, fmt.Errorf("EncodingUnit: data too short for ObjectBlock")
	}
	objBlock := data[8 : 8+int(objLen)]

	// Parse ObjectBlock flags
	if len(objBlock) < 1 {
		return nil, fmt.Errorf("ObjectBlock empty")
	}
	flags := objBlock[0]
	pos := 1

	// Skip Decoration if present
	if flags&cimFlagDecoration != 0 {
		skip, err := skipDecoration(objBlock[pos:])
		if err != nil {
			return nil, fmt.Errorf("skip decoration: %w", err)
		}
		pos += skip
	}

	var currentClassData []byte

	if flags&cimFlagClass != 0 {
		// ClassType = ParentClass + CurrentClass (MS-WMIO 2.2.14)
		// Both are ClassAndMethodsPart. We need CurrentClass's MethodsPart.
		// Skip ParentClass first.
		parentData := objBlock[pos:]

		// ClassPart.EncodingLength includes itself (MS-WMIO 2.2.73)
		parentClassPartLen := int(le.Uint32(parentData[0:4]))
		if parentClassPartLen == 0 {
			// Empty parent class: just the 4-byte zero length marker, no MethodsPart
			currentClassData = parentData[4:]
		} else {
			totalLen, err := readClassAndMethodsPartLen(parentData)
			if err != nil {
				return nil, fmt.Errorf("ParentClass: %w", err)
			}
			currentClassData = parentData[totalLen:]
		}
	} else if flags&cimFlagInstance != 0 {
		return nil, fmt.Errorf("expected class ObjectBlock, got instance (methods not available)")
	} else {
		return nil, fmt.Errorf("ObjectBlock flags 0x%02x: neither class nor instance", flags)
	}

	// CurrentClass is a ClassAndMethodsPart = ClassPart + MethodsPart
	// ClassPart.EncodingLength includes itself
	if len(currentClassData) < 4 {
		return nil, fmt.Errorf("CurrentClass ClassPart too short")
	}
	classPartLen := int(le.Uint32(currentClassData[0:4]))
	if len(currentClassData) < classPartLen {
		return nil, fmt.Errorf("CurrentClass ClassPart: data too short (%d < %d)", len(currentClassData), classPartLen)
	}

	// MethodsPart starts after ClassPart
	methodsData := currentClassData[classPartLen:]

	// Parse MethodsPart to find the named method
	inParamsBlock, err := findMethodInParams(methodsData, methodName)
	if err != nil {
		return nil, err
	}

	// Parse the InParams ObjectBlock as a class definition
	return parseClassFromObjectBlock(inParamsBlock)
}

// readClassAndMethodsPartLen returns the total wire size of a ClassAndMethodsPart
// (ClassPart + MethodsPart). EncodingLength fields include themselves.
func readClassAndMethodsPartLen(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("ClassPart too short for EncodingLength")
	}
	// ClassPart: EncodingLength includes the 4-byte field itself
	classPartLen := int(le.Uint32(data[0:4]))
	if classPartLen < 4 || len(data) < classPartLen+4 {
		return 0, fmt.Errorf("data too short for ClassPart (%d) + MethodsPart header", classPartLen)
	}
	// MethodsPart: EncodingLength includes the 4-byte field itself
	methodsPartLen := int(le.Uint32(data[classPartLen : classPartLen+4]))
	total := classPartLen + methodsPartLen
	if len(data) < total {
		return 0, fmt.Errorf("data too short for ClassAndMethodsPart (%d < %d)", len(data), total)
	}
	return total, nil
}

// parseClassFromObjectBlock parses an ObjectBlock containing a class definition
// and returns a cimClassDef with the CurrentClass ClassPart bytes preserved.
// The ObjectBlock contains a ClassType = ParentClass + CurrentClass.
func parseClassFromObjectBlock(objBlock []byte) (*cimClassDef, error) {
	if len(objBlock) < 1 {
		return nil, fmt.Errorf("ObjectBlock empty")
	}
	flags := objBlock[0]
	pos := 1

	// Skip Decoration if present
	if flags&cimFlagDecoration != 0 {
		skip, err := skipDecoration(objBlock[pos:])
		if err != nil {
			return nil, fmt.Errorf("skip decoration: %w", err)
		}
		pos += skip
	}

	if flags&cimFlagClass == 0 {
		return nil, fmt.Errorf("expected class ObjectBlock, got flags 0x%02x", flags)
	}

	// ClassType = ParentClass(ClassAndMethodsPart) + CurrentClass(ClassAndMethodsPart)
	// Skip ParentClass to reach CurrentClass
	classTypeData := objBlock[pos:]
	parentPartLen := int(le.Uint32(classTypeData[0:4]))
	if parentPartLen == 0 {
		// Empty parent: just a 4-byte zero marker, no MethodsPart
		classTypeData = classTypeData[4:]
	} else {
		totalLen, err := readClassAndMethodsPartLen(classTypeData)
		if err != nil {
			return nil, fmt.Errorf("skip ParentClass: %w", err)
		}
		classTypeData = classTypeData[totalLen:]
	}

	// Now at CurrentClass ClassAndMethodsPart — parse its ClassPart
	if len(classTypeData) < 4 {
		return nil, fmt.Errorf("CurrentClass too short")
	}

	classDef, err := parseClassPart(classTypeData)
	if err != nil {
		return nil, err
	}

	// Store just the raw ClassPart for building instances
	// ClassPart.EncodingLength includes itself
	classPartSize := int(le.Uint32(classTypeData[0:4]))
	classDef.classPartRaw = make([]byte, classPartSize)
	copy(classDef.classPartRaw, classTypeData[:classPartSize])

	return classDef, nil
}

// parseClassPart parses a ClassPart (which starts with EncodingLength) and
// extracts property definitions from the PropertyLookupTable and ClassHeap.
func parseClassPart(data []byte) (*cimClassDef, error) {
	if len(data) < 13 {
		return nil, fmt.Errorf("ClassPart too short for ClassHeader")
	}

	// ClassHeader (13 bytes):
	//   EncodingLength (4): total ClassPart size (includes this field)
	//   ReservedOctet (1)
	//   ClassNameRef (4): heap offset for class name
	//   NdTableValueLength (4): combined NdTable + value table size
	classPartLen := int(le.Uint32(data[0:4]))
	if len(data) < classPartLen {
		return nil, fmt.Errorf("ClassPart: data too short (%d < %d)", len(data), classPartLen)
	}
	classNameRef := le.Uint32(data[5:9])
	ndTableValueLength := int(le.Uint32(data[9:13]))

	offset := 13

	// DerivationList: EncodingLength includes itself
	if offset+4 > classPartLen {
		return nil, fmt.Errorf("ClassPart: no room for DerivationList")
	}
	derivListLen := int(le.Uint32(data[offset:]))
	offset += derivListLen

	// ClassQualifierSet: EncodingLength includes itself
	if offset+4 > classPartLen {
		return nil, fmt.Errorf("ClassPart: no room for ClassQualifierSet")
	}
	qualSetLen := int(le.Uint32(data[offset:]))
	offset += qualSetLen

	// PropertyLookupTable: PropertyCount (4) + entries
	if offset+4 > classPartLen {
		return nil, fmt.Errorf("ClassPart: no room for PropertyLookupTable")
	}
	propCount := int(le.Uint32(data[offset:]))
	offset += 4

	type propLookup struct {
		nameRef uint32
		infoRef uint32
	}
	lookups := make([]propLookup, propCount)
	for i := 0; i < propCount; i++ {
		if offset+8 > classPartLen {
			return nil, fmt.Errorf("ClassPart: PropertyLookup %d out of bounds", i)
		}
		lookups[i] = propLookup{
			nameRef: le.Uint32(data[offset:]),
			infoRef: le.Uint32(data[offset+4:]),
		}
		offset += 8
	}

	// NdTable: 2 bits per property (MS-WMIO 2.2.19), same for class and instance
	ndTableSize := (propCount + 3) / 4
	offset += ndTableSize

	// PropertyValueList: ndTableValueLength - ndTableSize bytes
	valueTableSize := ndTableValueLength - ndTableSize
	offset += valueTableSize

	// ClassHeap: remaining bytes within ClassPart
	if offset+4 > classPartLen {
		return nil, fmt.Errorf("ClassPart: no room for ClassHeap")
	}
	heapLenRaw := le.Uint32(data[offset:])
	heapDataSize := int(heapLenRaw & 0x7FFFFFFF)
	heapStart := offset + 4
	if heapStart+heapDataSize > classPartLen {
		heapDataSize = classPartLen - heapStart
	}
	if heapDataSize < 0 {
		heapDataSize = 0
	}
	heapData := data[heapStart : heapStart+heapDataSize]

	// Resolve property definitions from heap
	classDef := &cimClassDef{
		valueTableSize: valueTableSize,
	}

	// Read class name from heap
	classDef.className = readEncodedString(heapData, classNameRef)

	// Read property info from heap
	for i := 0; i < propCount; i++ {
		name := readEncodedString(heapData, lookups[i].nameRef)

		prop := cimPropDef{name: name}

		// Parse PropertyInfo at infoRef offset in heap
		infoOffset := int(lookups[i].infoRef)
		if infoOffset+10 <= len(heapData) {
			prop.cimType = le.Uint32(heapData[infoOffset:])
			// DeclarationOrder at infoOffset+4 (2 bytes) - skip
			prop.offset = int(le.Uint32(heapData[infoOffset+6:]))
		}

		classDef.properties = append(classDef.properties, prop)
	}

	return classDef, nil
}

// findMethodInParams parses a MethodsPart to find the named method and
// returns the raw ObjectBlock bytes for its InputSignature.
//
// MethodsPart layout (MS-WMIO 2.2.38):
//   EncodingLength (4) — includes itself
//   MethodCount (2)
//   MethodCountPadding (2)
//   MethodDescription[MethodCount] — each is 24 bytes fixed:
//     MethodName (4) — HeapRef
//     MethodFlags (1)
//     MethodPadding (3)
//     MethodOrigin (4)
//     MethodQualifiers (4) — HeapRef
//     InputSignature (4) — HeapRef (0xFFFFFFFF if none)
//     OutputSignature (4) — HeapRef (0xFFFFFFFF if none)
//   MethodHeap — contains actual signature data
func findMethodInParams(data []byte, methodName string) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("MethodsPart too short")
	}

	// MethodsPart: EncodingLength includes itself
	methodsPartLen := int(le.Uint32(data[0:4]))
	if len(data) < methodsPartLen {
		return nil, fmt.Errorf("MethodsPart: data too short")
	}

	// MethodCount (2) + MethodCountPadding (2) = 4 bytes
	methodCount := int(le.Uint16(data[4:6]))
	if methodCount == 0 {
		return nil, fmt.Errorf("class has no methods")
	}

	const methodDescSize = 24 // MethodName(4) + Flags(1) + Pad(3) + Origin(4) + Qualifiers(4) + InSig(4) + OutSig(4)
	descStart := 8            // after EncodingLength(4) + MethodCount(2) + Padding(2)
	descEnd := descStart + methodCount*methodDescSize
	if descEnd > methodsPartLen {
		return nil, fmt.Errorf("MethodsPart: method descriptions overflow (%d > %d)", descEnd, methodsPartLen)
	}

	// MethodHeap follows after all method descriptions
	heapOffset := descEnd
	if heapOffset+4 > methodsPartLen {
		return nil, fmt.Errorf("MethodsPart: no MethodHeap")
	}
	heapLenRaw := le.Uint32(data[heapOffset:])
	heapDataSize := int(heapLenRaw & 0x7FFFFFFF)
	heapDataStart := heapOffset + 4
	if heapDataStart+heapDataSize > methodsPartLen {
		heapDataSize = methodsPartLen - heapDataStart
	}
	var methodHeap []byte
	if heapDataSize > 0 {
		methodHeap = data[heapDataStart : heapDataStart+heapDataSize]
	}

	// Search method descriptions for the named method
	for i := 0; i < methodCount; i++ {
		off := descStart + i*methodDescSize
		nameRef := le.Uint32(data[off:])
		// off+4: MethodFlags(1) + MethodPadding(3)
		// off+8: MethodOrigin(4)
		// off+12: MethodQualifiers(4) — HeapRef
		inputSigRef := le.Uint32(data[off+16:])
		// off+20: OutputSignature(4) — HeapRef

		name := readEncodedString(methodHeap, nameRef)
		if !strings.EqualFold(name, methodName) {
			continue
		}

		if inputSigRef == 0xFFFFFFFF {
			return nil, fmt.Errorf("method %q has no input parameters", methodName)
		}

		// InputSignature is a METHOD_SIGNATURE_BLOCK in the heap:
		//   EncodingLength (4) — does NOT include itself
		//   ObjectBlock (EncodingLength bytes)
		if int(inputSigRef) >= len(methodHeap) {
			return nil, fmt.Errorf("method %q: InputSignature ref 0x%x out of bounds (heap size %d)", methodName, inputSigRef, len(methodHeap))
		}
		sigData := methodHeap[inputSigRef:]
		if len(sigData) < 4 {
			return nil, fmt.Errorf("method %q: InputSignature too short", methodName)
		}
		sigLen := int(le.Uint32(sigData[0:4]))
		if sigLen == 0 {
			return nil, fmt.Errorf("method %q: InputSignature empty", methodName)
		}
		if len(sigData) < 4+sigLen {
			return nil, fmt.Errorf("method %q: InputSignature data too short (%d < %d)", methodName, len(sigData)-4, sigLen)
		}
		return sigData[4 : 4+sigLen], nil
	}

	return nil, fmt.Errorf("method %q not found", methodName)
}

// buildCIMInstance creates a CIM EncodingUnit containing an instance of the
// given class with the specified properties set. Properties not in the map
// are left as NULL.
func buildCIMInstance(classDef *cimClassDef, params map[string]MethodParam) ([]byte, error) {
	propCount := len(classDef.properties)

	// Instance NdTable: 2 bits per property, packed into bytes
	// Bit 0 = inherited_default, Bit 1 = null_default (MS-WMIO 2.2.27)
	ndTableSize := (propCount + 3) / 4
	ndTable := make([]byte, ndTableSize)

	// Build InstanceHeap: class name + property value strings
	heap := make([]byte, 0, 256)

	// Write class name to heap (at offset 0) using ASCII encoding
	classNameOffset := uint32(len(heap))
	heap = appendEncodedString(heap, classDef.className)

	// Determine property values and build instance data
	instanceData := make([]byte, classDef.valueTableSize)

	for i, prop := range classDef.properties {
		param, hasVal := params[prop.name]
		baseType := prop.cimType & 0x1FFF
		isArray := prop.cimType&cimTypeArray != 0

		if !hasVal {
			// Property not provided: mark as null + inherited_default
			byteIdx := i / 4
			bitOffset := uint((i % 4) * 2)
			ndTable[byteIdx] |= byte(3 << bitOffset) // 0b11 = null + inherited
			continue
		}

		// Array properties: write array data to heap, store HeapRef in value table
		if isArray {
			heapOffset := uint32(len(heap))
			var err error
			heap, err = appendArrayToHeap(heap, baseType, param)
			if err != nil {
				return nil, fmt.Errorf("property %q: %w", prop.name, err)
			}
			if prop.offset+4 <= len(instanceData) {
				le.PutUint32(instanceData[prop.offset:], heapOffset)
			}
			continue
		}

		switch baseType {
		case cimTypeString, cimTypeDatetime:
			if param.kind != paramString {
				return nil, fmt.Errorf("property %q is type string but got non-string param", prop.name)
			}
			heapOffset := uint32(len(heap))
			heap = appendEncodedStringUnicode(heap, param.strVal)
			if prop.offset+4 <= len(instanceData) {
				le.PutUint32(instanceData[prop.offset:], heapOffset)
			}

		case cimTypeUint8:
			v := paramToUint64(param)
			if prop.offset+1 <= len(instanceData) {
				instanceData[prop.offset] = byte(v)
			}
		case cimTypeSint8:
			v := paramToInt64(param)
			if prop.offset+1 <= len(instanceData) {
				instanceData[prop.offset] = byte(int8(v))
			}
		case cimTypeUint16:
			v := paramToUint64(param)
			if prop.offset+2 <= len(instanceData) {
				le.PutUint16(instanceData[prop.offset:], uint16(v))
			}
		case cimTypeSint16:
			v := paramToInt64(param)
			if prop.offset+2 <= len(instanceData) {
				le.PutUint16(instanceData[prop.offset:], uint16(int16(v)))
			}
		case cimTypeUint32:
			v := paramToUint64(param)
			if prop.offset+4 <= len(instanceData) {
				le.PutUint32(instanceData[prop.offset:], uint32(v))
			}
		case cimTypeSint32:
			v := paramToInt64(param)
			if prop.offset+4 <= len(instanceData) {
				le.PutUint32(instanceData[prop.offset:], uint32(int32(v)))
			}
		case cimTypeUint64:
			v := paramToUint64(param)
			if prop.offset+8 <= len(instanceData) {
				le.PutUint64(instanceData[prop.offset:], v)
			}
		case cimTypeSint64:
			v := paramToInt64(param)
			if prop.offset+8 <= len(instanceData) {
				le.PutUint64(instanceData[prop.offset:], uint64(v))
			}
		case cimTypeBoolean:
			var bv uint16
			if param.kind == paramBool && param.boolVal {
				bv = 0xFFFF
			} else if param.kind == paramUint && param.uintVal != 0 {
				bv = 0xFFFF
			} else if param.kind == paramInt && param.intVal != 0 {
				bv = 0xFFFF
			}
			if prop.offset+2 <= len(instanceData) {
				le.PutUint16(instanceData[prop.offset:], bv)
			}

		default:
			return nil, fmt.Errorf("property %q has unsupported CIM type 0x%x", prop.name, prop.cimType)
		}
	}

	// Build InstanceQualifierSet:
	//   QualifierSet (EncodingLength=4, empty body) + InstancePropQualifierSetFlag (0x01)
	instanceQualSet := []byte{0x04, 0x00, 0x00, 0x00, 0x01}

	// Build the instance body (everything after CurrentClass and EncodingLength):
	//   InstanceFlags (1) + ClassNameRef (4) + NdTable + InstanceData + InstanceQualifierSet
	instBody := make([]byte, 0, 1+4+len(ndTable)+len(instanceData)+len(instanceQualSet))
	instBody = append(instBody, 0x00) // InstanceFlags
	b4 := [4]byte{}
	le.PutUint32(b4[:], classNameOffset)
	instBody = append(instBody, b4[:]...) // ClassNameRef (HeapRef into InstanceHeap)
	instBody = append(instBody, ndTable...)
	instBody = append(instBody, instanceData...)
	instBody = append(instBody, instanceQualSet...)

	// Build InstanceHeap: HeapLength (with MSB set) + heap data
	heapLen := uint32(len(heap)) | 0x80000000
	instanceHeap := make([]byte, 4+len(heap))
	le.PutUint32(instanceHeap, heapLen)
	copy(instanceHeap[4:], heap)

	// InstanceType EncodingLength: includes itself (4) + instBody + instanceHeap
	// (everything in InstanceType except CurrentClass)
	encLen := uint32(4 + len(instBody) + len(instanceHeap))

	// Build InstanceType:
	//   CurrentClass (ClassPart) + EncodingLength (4) + instBody + InstanceHeap
	instanceType := make([]byte, 0, len(classDef.classPartRaw)+4+len(instBody)+len(instanceHeap))
	instanceType = append(instanceType, classDef.classPartRaw...)
	le.PutUint32(b4[:], encLen)
	instanceType = append(instanceType, b4[:]...)
	instanceType = append(instanceType, instBody...)
	instanceType = append(instanceType, instanceHeap...)

	// Build ObjectBlock: flags + InstanceType
	objBlock := make([]byte, 0, 1+len(instanceType))
	objBlock = append(objBlock, cimFlagInstance) // ObjectFlags: instance, no decoration
	objBlock = append(objBlock, instanceType...)

	// Build EncodingUnit: signature + length + ObjectBlock
	encodingUnit := make([]byte, 0, 8+len(objBlock))
	le.PutUint32(b4[:], cimSignature)
	encodingUnit = append(encodingUnit, b4[:]...)
	le.PutUint32(b4[:], uint32(len(objBlock)))
	encodingUnit = append(encodingUnit, b4[:]...)
	encodingUnit = append(encodingUnit, objBlock...)

	return encodingUnit, nil
}

// ParseCIMInstanceValues parses a CIM EncodingUnit containing an instance
// and returns the uint32 property values by name.
func ParseCIMInstanceValues(data []byte) (map[string]uint32, error) {
	// Parse EncodingUnit header
	if len(data) < 8 {
		return nil, fmt.Errorf("EncodingUnit too short")
	}
	sig := le.Uint32(data[0:4])
	if sig != cimSignature {
		return nil, fmt.Errorf("invalid CIM signature 0x%08x", sig)
	}
	objLen := int(le.Uint32(data[4:8]))
	if len(data) < 8+objLen {
		return nil, fmt.Errorf("EncodingUnit: data too short for ObjectBlock")
	}
	objBlock := data[8 : 8+objLen]

	// Parse ObjectBlock flags
	if len(objBlock) < 1 {
		return nil, fmt.Errorf("ObjectBlock empty")
	}
	flags := objBlock[0]
	pos := 1

	// Skip Decoration if present
	if flags&cimFlagDecoration != 0 {
		skip, err := skipDecoration(objBlock[pos:])
		if err != nil {
			return nil, fmt.Errorf("skip decoration: %w", err)
		}
		pos += skip
	}

	if flags&cimFlagInstance == 0 {
		return nil, fmt.Errorf("expected instance ObjectBlock, got class")
	}

	instanceData := objBlock[pos:]

	// InstanceType: CurrentClass (ClassAndMethodsPart) + EncodingLength + CurrentInstance + InstanceHeap

	// Parse CurrentClass to get property definitions
	if len(instanceData) < 4 {
		return nil, fmt.Errorf("InstanceType: too short for CurrentClass")
	}
	// ClassPart.EncodingLength includes itself
	classPartLen := int(le.Uint32(instanceData[0:4]))
	if len(instanceData) < classPartLen {
		return nil, fmt.Errorf("InstanceType: CurrentClass ClassPart too short")
	}

	classDef, err := parseClassPart(instanceData)
	if err != nil {
		return nil, fmt.Errorf("parse CurrentClass: %w", err)
	}

	// For instances, CurrentClass has no MethodsPart (MS-WMIO 2.2.5)
	classAndMethodsSize := classPartLen

	// EncodingLength: includes itself (4) + InstanceFlags + ClassNameRef +
	// NdTable_ValueTable + InstanceQualifierSet + InstanceHeap
	encLenOffset := classAndMethodsSize
	if encLenOffset+4 > len(instanceData) {
		return nil, fmt.Errorf("InstanceType: no EncodingLength")
	}
	encodingLength := int(le.Uint32(instanceData[encLenOffset:]))

	// The rest of InstanceType (after CurrentClass) spans encodingLength bytes
	// starting from the EncodingLength field itself.
	instTypeRest := instanceData[encLenOffset:]
	if len(instTypeRest) < encodingLength {
		return nil, fmt.Errorf("InstanceType: data too short (%d < %d)", len(instTypeRest), encodingLength)
	}

	// Within instTypeRest:
	//   [0:4] = EncodingLength
	//   [4]   = InstanceFlags
	//   [5:9] = InstanceClassName (HeapRef)
	//   [9:]  = NdTable + ValueTable + InstanceQualifierSet + InstanceHeap
	if encodingLength < 9 {
		return nil, fmt.Errorf("InstanceType EncodingLength too small (%d)", encodingLength)
	}

	instPos := 9 // skip EncodingLength(4) + InstanceFlags(1) + InstanceClassName(4)

	// Instance NdTable: 2 bits per property
	propCount := len(classDef.properties)
	instNdTableSize := (propCount + 3) / 4
	if instPos+instNdTableSize > encodingLength {
		return nil, fmt.Errorf("CurrentInstance: NdTable out of bounds")
	}
	instNdTable := instTypeRest[instPos : instPos+instNdTableSize]
	instPos += instNdTableSize

	// Property values follow NdTable
	propValues := instTypeRest[instPos:]

	afterValueTable := instPos + classDef.valueTableSize
	instHeapData := parseInstanceHeap(instTypeRest, afterValueTable, propCount)

	// Extract property values
	result := make(map[string]uint32)
	for i, prop := range classDef.properties {
		// Bit 0 = IsNULL (MS-WMIO 2.2.26)
		byteIdx := i / 4
		bitOffset := uint((i % 4) * 2)
		ndBits := (instNdTable[byteIdx] >> bitOffset) & 0x03
		if ndBits&0x01 != 0 {
			continue // null value
		}

		baseType := prop.cimType & 0x1FFF
		switch baseType {
		case cimTypeUint32, cimTypeSint32:
			if prop.offset+4 <= len(propValues) {
				result[prop.name] = le.Uint32(propValues[prop.offset:])
			}
		case cimTypeString:
			// String properties are HeapRefs into InstanceHeap
			// We don't return strings from this function
			_ = instHeapData // acknowledge it's available
		}
	}

	return result, nil
}

// ParseCIMInstanceAllValues parses a CIM EncodingUnit containing an instance
// and returns all property values by name. Supports all scalar CIM types.
// Array types and cimTypeObject are returned as nil with a debug log.
func ParseCIMInstanceAllValues(data []byte) (map[string]interface{}, error) {
	// Parse EncodingUnit header
	if len(data) < 8 {
		return nil, fmt.Errorf("EncodingUnit too short")
	}
	sig := le.Uint32(data[0:4])
	if sig != cimSignature {
		return nil, fmt.Errorf("invalid CIM signature 0x%08x", sig)
	}
	objLen := int(le.Uint32(data[4:8]))
	if len(data) < 8+objLen {
		return nil, fmt.Errorf("EncodingUnit: data too short for ObjectBlock")
	}
	objBlock := data[8 : 8+objLen]

	if len(objBlock) < 1 {
		return nil, fmt.Errorf("ObjectBlock empty")
	}
	flags := objBlock[0]
	pos := 1

	if flags&cimFlagDecoration != 0 {
		skip, err := skipDecoration(objBlock[pos:])
		if err != nil {
			return nil, fmt.Errorf("skip decoration: %w", err)
		}
		pos += skip
	}

	if flags&cimFlagInstance == 0 {
		return nil, fmt.Errorf("expected instance ObjectBlock, got class")
	}

	instanceData := objBlock[pos:]

	if len(instanceData) < 4 {
		return nil, fmt.Errorf("InstanceType: too short for CurrentClass")
	}
	classPartLen := int(le.Uint32(instanceData[0:4]))
	if len(instanceData) < classPartLen {
		return nil, fmt.Errorf("InstanceType: CurrentClass ClassPart too short")
	}

	classDef, err := parseClassPart(instanceData)
	if err != nil {
		return nil, fmt.Errorf("parse CurrentClass: %w", err)
	}

	classAndMethodsSize := classPartLen

	encLenOffset := classAndMethodsSize
	if encLenOffset+4 > len(instanceData) {
		return nil, fmt.Errorf("InstanceType: no EncodingLength")
	}
	encodingLength := int(le.Uint32(instanceData[encLenOffset:]))

	instTypeRest := instanceData[encLenOffset:]
	if len(instTypeRest) < encodingLength {
		return nil, fmt.Errorf("InstanceType: data too short (%d < %d)", len(instTypeRest), encodingLength)
	}

	if encodingLength < 9 {
		return nil, fmt.Errorf("InstanceType EncodingLength too small (%d)", encodingLength)
	}

	instPos := 9 // skip EncodingLength(4) + InstanceFlags(1) + InstanceClassName(4)

	propCount := len(classDef.properties)
	instNdTableSize := (propCount + 3) / 4
	if instPos+instNdTableSize > encodingLength {
		return nil, fmt.Errorf("CurrentInstance: NdTable out of bounds")
	}
	instNdTable := instTypeRest[instPos : instPos+instNdTableSize]
	instPos += instNdTableSize

	propValues := instTypeRest[instPos:]

	afterValueTable := instPos + classDef.valueTableSize
	instHeapData := parseInstanceHeap(instTypeRest, afterValueTable, propCount)

	result := make(map[string]interface{})
	for i, prop := range classDef.properties {
		byteIdx := i / 4
		bitOffset := uint((i % 4) * 2)
		ndBits := (instNdTable[byteIdx] >> bitOffset) & 0x03
		// Bit 0 = IsNULL (MS-WMIO 2.2.26), bit 1 = IsDefault/inherited
		if ndBits&0x01 != 0 {
			continue // null value
		}

		baseType := prop.cimType & 0x1FFF
		isArray := prop.cimType&cimTypeArray != 0

		if isArray {
			if prop.offset+4 <= len(propValues) {
				heapRef := le.Uint32(propValues[prop.offset:])
				result[prop.name] = readArrayFromHeap(instHeapData, heapRef, baseType)
			}
			continue
		}

		switch baseType {
		case cimTypeString, cimTypeDatetime:
			if prop.offset+4 <= len(propValues) {
				heapRef := le.Uint32(propValues[prop.offset:])
				if heapRef == 0xFFFFFFFF {
					continue
				}
				result[prop.name] = readEncodedString(instHeapData, heapRef)
			}
		case cimTypeBoolean:
			if prop.offset+2 <= len(propValues) {
				result[prop.name] = le.Uint16(propValues[prop.offset:]) != 0
			}
		case cimTypeSint8:
			if prop.offset+1 <= len(propValues) {
				result[prop.name] = int8(propValues[prop.offset])
			}
		case cimTypeUint8:
			if prop.offset+1 <= len(propValues) {
				result[prop.name] = propValues[prop.offset]
			}
		case cimTypeSint16:
			if prop.offset+2 <= len(propValues) {
				result[prop.name] = int16(le.Uint16(propValues[prop.offset:]))
			}
		case cimTypeUint16:
			if prop.offset+2 <= len(propValues) {
				result[prop.name] = le.Uint16(propValues[prop.offset:])
			}
		case cimTypeSint32:
			if prop.offset+4 <= len(propValues) {
				result[prop.name] = int32(le.Uint32(propValues[prop.offset:]))
			}
		case cimTypeUint32:
			if prop.offset+4 <= len(propValues) {
				result[prop.name] = le.Uint32(propValues[prop.offset:])
			}
		case cimTypeSint64:
			if prop.offset+8 <= len(propValues) {
				result[prop.name] = int64(le.Uint64(propValues[prop.offset:]))
			}
		case cimTypeUint64:
			if prop.offset+8 <= len(propValues) {
				result[prop.name] = le.Uint64(propValues[prop.offset:])
			}
		case cimTypeReal32:
			if prop.offset+4 <= len(propValues) {
				result[prop.name] = math.Float32frombits(le.Uint32(propValues[prop.offset:]))
			}
		case cimTypeReal64:
			if prop.offset+8 <= len(propValues) {
				result[prop.name] = math.Float64frombits(le.Uint64(propValues[prop.offset:]))
			}
		case cimTypeObject:
			log.Debugf("parseCIMInstanceAllValues: skipping object property %q", prop.name)
			result[prop.name] = nil
		default:
			log.Debugf("parseCIMInstanceAllValues: unknown type 0x%x for property %q", prop.cimType, prop.name)
		}
	}

	return result, nil
}

// parseInstanceHeap parses the InstanceQualifierSet and InstanceHeap
// sequentially from instTypeRest starting at afterValueTable.
// Layout: QualifierSet(EncodingLength includes itself) + InstPropQualSetFlag(1 byte)
// + optional per-property QualifierSets + InstanceHeap(HeapLength + HeapItem).
func parseInstanceHeap(instTypeRest []byte, afterValueTable int, propCount int) []byte {
	pos := afterValueTable

	// QualifierSet: EncodingLength (4 bytes, includes itself) + qualifier data
	if pos+4 > len(instTypeRest) {
		log.Debugf("parseInstanceHeap: no room for QualifierSet at offset %d", pos)
		return nil
	}
	qualSetLen := int(le.Uint32(instTypeRest[pos:]))
	if qualSetLen < 4 {
		qualSetLen = 4
	}
	pos += qualSetLen

	// InstancePropQualifierSet: flag byte
	if pos >= len(instTypeRest) {
		log.Debugf("parseInstanceHeap: no room for InstPropQualSetFlag at offset %d", pos)
		return nil
	}
	propQualFlag := instTypeRest[pos]
	pos++

	// If flag == 2, per-property qualifier sets follow (one QualifierSet per property)
	if propQualFlag == 2 {
		for i := 0; i < propCount; i++ {
			if pos+4 > len(instTypeRest) {
				log.Debugf("parseInstanceHeap: per-property qualifier set %d out of bounds", i)
				return nil
			}
			pqsLen := int(le.Uint32(instTypeRest[pos:]))
			if pqsLen < 4 {
				pqsLen = 4
			}
			pos += pqsLen
		}
	}

	// InstanceHeap: HeapLength (4 bytes, MSB set) + HeapItem
	if pos+4 > len(instTypeRest) {
		log.Debugf("parseInstanceHeap: no room for InstanceHeap at offset %d", pos)
		return nil
	}
	heapLenRaw := le.Uint32(instTypeRest[pos:])
	heapDataSize := int(heapLenRaw & 0x7FFFFFFF)
	pos += 4

	log.Debugf("parseInstanceHeap: heap at offset %d, heapLenRaw=0x%08x, size=%d", pos-4, heapLenRaw, heapDataSize)

	if heapDataSize == 0 {
		return nil
	}
	if pos+heapDataSize > len(instTypeRest) {
		heapDataSize = len(instTypeRest) - pos
	}
	return instTypeRest[pos : pos+heapDataSize]
}

// readArrayFromHeap reads an array value from the instance heap at the given
// offset. Array layout: numItems(uint32) + [for string arrays: numItems DWORD
// heap pointers + numItems ENCODED_STRINGs] [for scalar arrays: numItems
// values of the element type].
func readArrayFromHeap(heap []byte, offset uint32, baseType uint32) interface{} {
	off := int(offset)
	if off+4 > len(heap) {
		return nil
	}
	numItems := int(le.Uint32(heap[off:]))
	off += 4

	switch baseType {
	case cimTypeString, cimTypeDatetime:
		// Skip the DWORD heap pointers (one per item)
		off += 4 * numItems
		result := make([]string, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off >= len(heap) {
				break
			}
			sz, err := encodedStringSize(heap[off:])
			if err != nil {
				break
			}
			s := readEncodedString(heap, uint32(off))
			result = append(result, s)
			off += sz
		}
		return result
	case cimTypeSint32:
		result := make([]int32, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+4 > len(heap) {
				break
			}
			result = append(result, int32(le.Uint32(heap[off:])))
			off += 4
		}
		return result
	case cimTypeUint32:
		result := make([]uint32, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+4 > len(heap) {
				break
			}
			result = append(result, le.Uint32(heap[off:]))
			off += 4
		}
		return result
	case cimTypeSint16:
		result := make([]int16, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+2 > len(heap) {
				break
			}
			result = append(result, int16(le.Uint16(heap[off:])))
			off += 2
		}
		return result
	case cimTypeUint16:
		result := make([]uint16, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+2 > len(heap) {
				break
			}
			result = append(result, le.Uint16(heap[off:]))
			off += 2
		}
		return result
	case cimTypeUint8:
		result := make([]uint8, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off >= len(heap) {
				break
			}
			result = append(result, heap[off])
			off++
		}
		return result
	case cimTypeSint8:
		result := make([]int8, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off >= len(heap) {
				break
			}
			result = append(result, int8(heap[off]))
			off++
		}
		return result
	case cimTypeSint64:
		result := make([]int64, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+8 > len(heap) {
				break
			}
			result = append(result, int64(le.Uint64(heap[off:])))
			off += 8
		}
		return result
	case cimTypeUint64:
		result := make([]uint64, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+8 > len(heap) {
				break
			}
			result = append(result, le.Uint64(heap[off:]))
			off += 8
		}
		return result
	case cimTypeBoolean:
		result := make([]bool, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+2 > len(heap) {
				break
			}
			result = append(result, le.Uint16(heap[off:]) != 0)
			off += 2
		}
		return result
	case cimTypeReal32:
		result := make([]float32, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+4 > len(heap) {
				break
			}
			result = append(result, math.Float32frombits(le.Uint32(heap[off:])))
			off += 4
		}
		return result
	case cimTypeReal64:
		result := make([]float64, 0, numItems)
		for i := 0; i < numItems; i++ {
			if off+8 > len(heap) {
				break
			}
			result = append(result, math.Float64frombits(le.Uint64(heap[off:])))
			off += 8
		}
		return result
	default:
		log.Debugf("readArrayFromHeap: unsupported array element type 0x%x", baseType)
		return nil
	}
}

// appendArrayToHeap appends a CIM array value to the instance heap.
// Array layout in heap: numItems(uint32) + [for uint8: raw bytes]
// [for string: numItems DWORD heap pointers + numItems ENCODED_STRINGs]
func appendArrayToHeap(heap []byte, baseType uint32, param MethodParam) ([]byte, error) {
	switch baseType {
	case cimTypeUint8:
		if param.kind != paramBytes {
			return nil, fmt.Errorf("uint8 array property requires BytesParam")
		}
		heap = binary.LittleEndian.AppendUint32(heap, uint32(len(param.bytesVal)))
		heap = append(heap, param.bytesVal...)
		return heap, nil

	case cimTypeString, cimTypeDatetime:
		if param.kind != paramStringArray {
			return nil, fmt.Errorf("string array property requires StringArrayParam")
		}
		n := len(param.strArrayVal)
		heap = binary.LittleEndian.AppendUint32(heap, uint32(n))
		// Reserve space for DWORD heap pointers (one per item)
		ptrBase := len(heap)
		for i := 0; i < n; i++ {
			heap = binary.LittleEndian.AppendUint32(heap, 0) // placeholder
		}
		// Write ENCODED_STRINGs and backfill pointers
		for i, s := range param.strArrayVal {
			le.PutUint32(heap[ptrBase+i*4:], uint32(len(heap)))
			heap = appendEncodedStringUnicode(heap, s)
		}
		return heap, nil

	default:
		return nil, fmt.Errorf("unsupported array element type 0x%x", baseType)
	}
}

// paramToUint64 extracts an unsigned integer value from a MethodParam,
// converting from signed or unsigned as needed.
func paramToUint64(p MethodParam) uint64 {
	switch p.kind {
	case paramUint:
		return p.uintVal
	case paramInt:
		return uint64(p.intVal)
	case paramBool:
		if p.boolVal {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// paramToInt64 extracts a signed integer value from a MethodParam,
// converting from unsigned or signed as needed.
func paramToInt64(p MethodParam) int64 {
	switch p.kind {
	case paramInt:
		return p.intVal
	case paramUint:
		return int64(p.uintVal)
	case paramBool:
		if p.boolVal {
			return 1
		}
		return 0
	default:
		return 0
	}
}

// --- Helper functions ---

// skipDecoration skips the Decoration structure at the start of data.
// Decoration = DecServerName (ENCODED_STRING) + DecNamespace (ENCODED_STRING)
func skipDecoration(data []byte) (int, error) {
	pos := 0
	// Skip two ENCODED_STRINGs
	for i := 0; i < 2; i++ {
		n, err := encodedStringSize(data[pos:])
		if err != nil {
			return 0, fmt.Errorf("decoration string %d: %w", i, err)
		}
		pos += n
	}
	return pos, nil
}

// encodedStringSize returns the total wire size of an ENCODED_STRING starting at data.
func encodedStringSize(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("ENCODED_STRING: empty")
	}
	flags := data[0]
	pos := 1

	if flags == encodedStringUnicode {
		// UTF-16LE: null-terminated (2 bytes per char)
		for pos+1 < len(data) {
			if data[pos] == 0 && data[pos+1] == 0 {
				return pos + 2, nil
			}
			pos += 2
		}
		return 0, fmt.Errorf("ENCODED_STRING UTF-16: no null terminator")
	}

	// ASCII: null-terminated (flag == 0x00 or any other value)
	for pos < len(data) {
		if data[pos] == 0 {
			return pos + 1, nil
		}
		pos++
	}
	return 0, fmt.Errorf("ENCODED_STRING ASCII: no null terminator")
}

// readEncodedString reads an ENCODED_STRING from the heap at the given offset.
func readEncodedString(heap []byte, offset uint32) string {
	off := int(offset)
	if off >= len(heap) {
		return ""
	}

	flags := heap[off]
	off++

	if flags == encodedStringUnicode {
		// UTF-16LE: null-terminated
		var u16 []uint16
		for off+1 < len(heap) {
			ch := le.Uint16(heap[off:])
			if ch == 0 {
				break
			}
			u16 = append(u16, ch)
			off += 2
		}
		return string(utf16.Decode(u16))
	}

	// ASCII: null-terminated (flag == 0x00 or any other value)
	end := off
	for end < len(heap) && heap[end] != 0 {
		end++
	}
	return string(heap[off:end])
}

// appendEncodedString appends an ASCII-encoded ENCODED_STRING to buf.
func appendEncodedString(buf []byte, s string) []byte {
	buf = append(buf, encodedStringASCII) // ASCII flag
	buf = append(buf, []byte(s)...)
	buf = append(buf, 0) // null terminator
	return buf
}

// appendEncodedStringUnicode appends a Unicode-encoded ENCODED_STRING to buf.
// Uses flag 0x01 + UTF-16LE data + UTF-16 null terminator.
func appendEncodedStringUnicode(buf []byte, s string) []byte {
	buf = append(buf, encodedStringUnicode) // Unicode flag
	for _, ch := range utf16.Encode([]rune(s)) {
		buf = binary.LittleEndian.AppendUint16(buf, ch)
	}
	buf = binary.LittleEndian.AppendUint16(buf, 0) // UTF-16 null terminator
	return buf
}
