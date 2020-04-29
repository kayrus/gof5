package utils

func ReverseByte(val byte) byte {
	var rval byte = 0
	for i := uint(0); i < 8; i++ {
		if val&(1<<i) != 0 {
			rval |= 0x80 >> i
		}
	}
	return rval
}

func ReverseUint8(val uint8) uint8 {
	return ReverseByte(val)
}

func ReverseUint16(val uint16) uint16 {
	var rval uint16 = 0
	for i := uint(0); i < 16; i++ {
		if val&(uint16(1)<<i) != 0 {
			rval |= uint16(0x8000) >> i
		}
	}
	return rval
}
