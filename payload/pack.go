package payload

import (
	bin "encoding/binary"

	"github.com/Jacute/gowntools/binary"
)

// P64 returns the binary representation of addr as a little-endian
// uint64. The returned byte slice has a length of 8 bytes.
//
// The function is used to encode addresses in payload messages.
func P64(addr binary.Addr) []byte {
	buf := make([]byte, 8)
	bin.LittleEndian.PutUint64(buf, uint64(addr))
	return buf
}

// P32 returns the binary representation of addr as a little-endian
// uint32. The returned byte slice has a length of 4 bytes.
//
// The function is used to encode addresses in payload messages.
func P32(addr binary.Addr) []byte {
	buf := make([]byte, 4)
	bin.LittleEndian.PutUint32(buf, uint32(addr))
	return buf
}

// P16 returns the binary representation of addr as a little-endian
// uint16. The returned byte slice has a length of 2 bytes.
//
// The function is used to encode addresses in payload messages.
func P16(addr binary.Addr) []byte {
	buf := make([]byte, 2)
	bin.LittleEndian.PutUint16(buf, uint16(addr))
	return buf
}

// U64 returns the binary representation of data as a little-endian
// uint64. The function takes a byte slice of length 8 as input and returns
// the corresponding binary representation as an Addr.
//
// The function is used to decode addresses in payload messages.
func U64(data []byte) binary.Addr {
	return binary.Addr(uint64(data[7])<<56 |
		uint64(data[6])<<48 |
		uint64(data[5])<<40 |
		uint64(data[4])<<32 |
		uint64(data[3])<<24 |
		uint64(data[2])<<16 |
		uint64(data[1])<<8 |
		uint64(data[0]))
}

// U32 returns the binary representation of data as a little-endian
// uint32. The function takes a byte slice of length 4 as input and returns
// the corresponding binary representation as an Addr.
//
// The function is used to decode addresses in payload messages.
func U32(data []byte) binary.Addr {
	return binary.Addr(uint32(data[3])<<24 |
		uint32(data[2])<<16 |
		uint32(data[1])<<8 |
		uint32(data[0]))
}

// U16 returns the binary representation of data as a little-endian
// uint16. The function takes a byte slice of length 2 as input and returns
// the corresponding binary representation as an Addr.
//
// The function is used to decode addresses in payload messages.
func U16(data []byte) binary.Addr {
	return binary.Addr(uint16(data[1])<<8 |
		uint16(data[0]))
}
