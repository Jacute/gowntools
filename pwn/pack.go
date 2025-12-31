package pwn

func P64(num int64) []byte {
	return []byte{
		byte(num >> 56),
		byte(num >> 48),
		byte(num >> 40),
		byte(num >> 32),
		byte(num >> 24),
		byte(num >> 16),
		byte(num >> 8),
		byte(num),
	}
}

func P32(num int32) []byte {
	return []byte{
		byte(num >> 24),
		byte(num >> 16),
		byte(num >> 8),
		byte(num),
	}
}

func P16(num int16) []byte {
	return []byte{
		byte(num >> 8),
		byte(num),
	}
}

func U64(data []byte) int64 {
	return int64(data[0])<<56 |
		int64(data[1])<<48 |
		int64(data[2])<<40 |
		int64(data[3])<<32 |
		int64(data[4])<<24 |
		int64(data[5])<<16 |
		int64(data[6])<<8 |
		int64(data[7])
}

func U32(data []byte) int32 {
	return int32(data[0])<<24 |
		int32(data[1])<<16 |
		int32(data[2])<<8 |
		int32(data[3])
}

func U16(data []byte) int16 {
	return int16(data[0])<<8 |
		int16(data[1])
}
