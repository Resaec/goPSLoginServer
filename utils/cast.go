package utils

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

	result[0] = uint8(value >> 24)
	result[1] = uint8(value >> 16)
	result[2] = uint8(value >> 8)
	result[3] = uint8(value)

	return result
}

func SliceUint64(value uint64) []uint8 {
	result := make([]uint8, 8)

	result[0] = uint8(value >> 56)
	result[1] = uint8(value >> 48)
	result[2] = uint8(value >> 40)
	result[3] = uint8(value >> 32)
	result[4] = uint8(value >> 24)
	result[5] = uint8(value >> 16)
	result[6] = uint8(value >> 8)
	result[7] = uint8(value)

	return result
}
