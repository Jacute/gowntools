package payload

import (
	bin "encoding/binary"

	"github.com/Jacute/gowntools/binary"
)

func P64(addr binary.Addr) []byte {
	buf := make([]byte, 8)
	bin.LittleEndian.PutUint64(buf, uint64(addr))
	return buf
}

func P32(addr binary.Addr) []byte {
	return []byte{
		byte(addr >> 24),
		byte(addr >> 16),
		byte(addr >> 8),
		byte(addr),
	}
}

func P16(addr binary.Addr) []byte {
	return []byte{
		byte(addr >> 8),
		byte(addr),
	}
}

func U64(data []byte) binary.Addr {
	return binary.Addr(uint64(data[0])<<56 |
		uint64(data[1])<<48 |
		uint64(data[2])<<40 |
		uint64(data[3])<<32 |
		uint64(data[4])<<24 |
		uint64(data[5])<<16 |
		uint64(data[6])<<8 |
		uint64(data[7]))
}

func U32(data []byte) binary.Addr {
	return binary.Addr(uint32(data[0])<<24 |
		uint32(data[1])<<16 |
		uint32(data[2])<<8 |
		uint32(data[3]))
}

func U16(data []byte) binary.Addr {
	return binary.Addr(uint16(data[0])<<8 |
		uint16(data[1]))
}
