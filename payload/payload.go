package payload

import (
	"bytes"

	"github.com/Jacute/gowntools/binary"
)

type PayloadBuilder struct {
	payload []byte
}

func NewPayloadBuilder() *PayloadBuilder {
	return &PayloadBuilder{
		payload: make([]byte, 0),
	}
}

// Fill fills the payload with n bytes of value b.
// It is used to fill the payload with a certain value.
// For example, if you want to fill the payload with 10 bytes of value 0x00,
// you can call pb.Fill(0x00, 10).
func (pb *PayloadBuilder) Fill(b byte, n int) {
	pb.Append(bytes.Repeat([]byte{b}, n))
}

func (pb *PayloadBuilder) Addr64(addr binary.Addr) {
	pb.Append(P64(addr))
}

func (pb *PayloadBuilder) Addr32(addr binary.Addr) {
	pb.Append(P32(addr))
}

func (pb *PayloadBuilder) AppendByte(b byte) {
	pb.payload = append(pb.payload, b)
}

func (pb *PayloadBuilder) Append(b []byte) {
	pb.payload = append(pb.payload, b...)
}

func (pb *PayloadBuilder) Build() []byte {
	return pb.payload
}

func (pb *PayloadBuilder) Reset() {
	pb.payload = make([]byte, 0)
}

func (pb *PayloadBuilder) Len() int {
	return len(pb.payload)
}

func (pb *PayloadBuilder) Cap() int {
	return cap(pb.payload)
}
