package utils

import (
	"reflect"
	"runtime"
	"strings"
)

func BoolToUnt8(in bool) uint8 {
	if in {
		return 1
	}

	return 0
}

func Uint8ToBool(in uint8) bool {
	if in != 0 {
		return true
	}

	return false
}

func SliceUint32(value uint32) []uint8 {
	result := make([]uint8, 4)

	result[0] = uint8(value)
	result[1] = uint8(value >> 8)
	result[2] = uint8(value >> 16)
	result[3] = uint8(value >> 24)

	return result
}

func SliceUint64(value uint64) []uint8 {
	result := make([]uint8, 8)

	result[0] = uint8(value)
	result[1] = uint8(value >> 8)
	result[2] = uint8(value >> 16)
	result[3] = uint8(value >> 24)
	result[4] = uint8(value >> 32)
	result[5] = uint8(value >> 40)
	result[6] = uint8(value >> 48)
	result[7] = uint8(value >> 56)

	return result
}

func GetFunctionName[T any](f T) string {

	fPointer := reflect.ValueOf(f).Pointer()
	symbolName := runtime.FuncForPC(fPointer).Name()
	elements := strings.Split(symbolName, "/")

	// get last element of slice
	return elements[len(elements)-1]
}
