package payload

import (
	"bytes"

	"github.com/Jacute/gowntools/binary"
)

type Builder struct {
	payload []byte
}

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

func (pb *Builder) Addr64(addr binary.Addr) {
	pb.Append(P64(addr))
}

func (pb *Builder) Addr32(addr binary.Addr) {
	pb.Append(P32(addr))
}

func (pb *Builder) AppendByte(b byte) {
	pb.payload = append(pb.payload, b)
}

func (pb *Builder) Append(b []byte) {
	pb.payload = append(pb.payload, b...)
}

func (pb *Builder) Build() []byte {
	return pb.payload
}

func (pb *Builder) Reset() {
	pb.payload = make([]byte, 0)
}

func (pb *Builder) Len() int {
	return len(pb.payload)
}

func (pb *Builder) Cap() int {
	return cap(pb.payload)
}
