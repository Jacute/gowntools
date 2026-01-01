package payload

import (
	"bytes"

	"github.com/Jacute/gowntools/binary"
)

type Builder struct {
	payload []byte
}

// NewBuilder returns a new Builder that can be used to build a payload.
// The Builder is initially empty, and you can use the various methods to
// fill the payload with different values.
func NewBuilder() *Builder {
	return &Builder{
		payload: make([]byte, 0),
	}
}

// Fill fills the payload with n bytes of value b.
// It is used to fill the payload with a certain value.
// For example, if you want to fill the payload with 10 bytes of value 0x00,
// you can call pb.Fill(0x00, 10).
func (pb *Builder) Fill(b byte, n int) {
	pb.Append(bytes.Repeat([]byte{b}, n))
}

// Addr64 appends the binary representation of addr as a little-endian
// uint64 to the payload. The function takes an Addr as input and appends
// the corresponding binary representation to the payload.
func (pb *Builder) Addr64(addr binary.Addr) {
	pb.Append(P64(addr))
}

// Addr32 appends the binary representation of addr as a little-endian
// uint32 to the payload. The function takes an Addr as input and appends
// the corresponding binary representation to the payload.
func (pb *Builder) Addr32(addr binary.Addr) {
	pb.Append(P32(addr))
}

// AppendByte appends a single byte b to the payload.
func (pb *Builder) AppendByte(b byte) {
	pb.payload = append(pb.payload, b)
}

// Append appends the given byte slice to the payload.
func (pb *Builder) Append(b []byte) {
	pb.payload = append(pb.payload, b...)
}

// Build returns the built payload.
func (pb *Builder) Build() []byte {
	return pb.payload
}

// Reset resets the payload to its initial state.
// It is used to clear the payload so that a new payload can be built.
// The function is useful when you want to build multiple payloads using the same Builder.
func (pb *Builder) Reset() {
	pb.payload = make([]byte, 0)
}

func (pb *Builder) Len() int {
	return len(pb.payload)
}

func (pb *Builder) Cap() int {
	return cap(pb.payload)
}
