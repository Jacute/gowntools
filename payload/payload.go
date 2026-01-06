package payload

import (
	"bytes"
	"errors"
	"strconv"

	"encoding/binary"

	"github.com/Jacute/gowntools/binutils"
)

var (
	ErrPayloadBiggerThenPaddingLength = errors.New("payload bigger then padding length")

	fmtReadRdiBytes = []byte{'%', '1', '$', 'p'}
	fmtReadRsiBytes = []byte{'%', '2', '$', 'p'}
	fmtReadRdxBytes = []byte{'%', '3', '$', 'p'}
	fmtReadRcxBytes = []byte{'%', '4', '$', 'p'}
	fmtReadR8Bytes  = []byte{'%', '5', '$', 'p'}
	fmtReadR9Bytes  = []byte{'%', '6', '$', 'p'}
)

type Builder struct {
	arch         binutils.Arch    // binutils architecture
	order        binary.ByteOrder // binutils byte order
	payload      []byte
	fmtDelimiter byte // separates the values obtained using format string vulnerability
}

// NewBuilder returns a new Builder for constructing payloads.
//
// The builder is configured with the given CPU architecture and byte order
// and starts with an empty payload.
//
// Example:
//
//	b := payload.NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
//	b.Fill('A', 64)
//	b.Addr(0xdeadbeef)
func NewBuilder(arch binutils.Arch, order binary.ByteOrder) *Builder {
	return &Builder{
		arch:         arch,
		order:        order,
		payload:      make([]byte, 0),
		fmtDelimiter: '-',
	}
}

// Fill fills the payload with n bytes of value b.
// It is used to fill the payload with a certain value.
// For example, if you want to fill the payload with 10 bytes of value 0x00,
// you can call pb.Fill(0x00, 10).
func (pb *Builder) Fill(b byte, n int) {
	pb.Append(bytes.Repeat([]byte{b}, n))
}

// PadTo pads the payload with byte b until it reaches a length of n.
// If the payload is already bigger than n, it returns an error.
// It is used to pad the payload with a certain value until it reaches a certain length.
// For example, if you want to pad the payload with 0x00 until it reaches a length of 64,
// you can call pb.PadTo(0x00, 64).
func (pb *Builder) PadTo(b byte, n int) error {
	if pb.Len() > n {
		return ErrPayloadBiggerThenPaddingLength
	}
	pb.Fill(b, n-pb.Len())
	return nil
}

// Addr appends the binutils representation of addr to the payload.
// The function uses the configured CPU architecture and byte order to encode
// the address.
//
// The function is used to encode addresses in payload messages.
//
// Example:
//
//	b := payload.NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
//	b.Addr(0xdeadbeef)
//
// The function appends the following byte sequences to the payload:
//
//   - For 64-bit architectures, 8 bytes (uint64 in little-endian byte order)
//   - For 32-bit architectures, 4 bytes (uint32 in little-endian byte order)
//   - For 16-bit architectures, 2 bytes (uint16 in little-endian byte order)
//   - For 8-bit architectures, 1 byte (uint8 in little-endian byte order)
func (pb *Builder) Addr(addr binutils.Addr) {
	switch pb.arch.Bitness {
	case 64:
		buf := make([]byte, 8)
		pb.order.PutUint64(buf, uint64(addr))
		pb.Append(buf)
	case 32:
		buf := make([]byte, 4)
		pb.order.PutUint32(buf, uint32(addr))
		pb.Append(buf)
	case 16:
		buf := make([]byte, 2)
		pb.order.PutUint16(buf, uint16(addr))
		pb.Append(buf)
	case 8:
		pb.AppendByte(uint8(addr))
	default:
		panic("incorrect bitness")
	}
}

// AppendByte appends a single byte to the payload.
// It takes a uint8 as input and appends the corresponding byte to the payload.
func (pb *Builder) AppendByte(b uint8) {
	pb.payload = append(pb.payload, byte(b))
}

// Append appends the given byte slice to the payload.
func (pb *Builder) Append(b []byte) {
	pb.payload = append(pb.payload, b...)
}

// FmtReadRegister appends a format string payload fragment that leaks
// the value of a CPU register via a format string vulnerability.
//
// The register must be one of the integer/pointer argument registers
// defined by the System V AMD64 ABI calling convention.
//
// Supported registers (including aliases):
//   - rdi, edi, di, dil   — 1st argument (%1$p)
//   - rsi, esi, si, sil   — 2nd argument (%2$p)
//   - rdx, edx, dx, dl    — 3rd argument (%3$p)
//   - rcx, ecx, cx, cl    — 4th argument (%4$p)
//   - r8,  r8d, r8w, r8b  — 5th argument (%5$p)
//   - r9,  r9d, r9w, r9b  — 6th argument (%6$p)
//
// The appended bytes correspond to positional format specifiers (e.g. "%1$p")
// and are intended for use in exploitation scenarios where a variadic function
// such as printf is called without proper format string validation.
//
// If an unsupported register name is provided, FmtReadRegister panics.
//
// Function supports only i386 and amd64 architectures
func (pb *Builder) FmtReadRegister(register string) {
	if pb.arch != binutils.ArchAmd64 && pb.arch != binutils.ArchI386 {
		panic("FmtReadRegister supports only i386 and amd64 architectures")
	}

	switch register {
	case "rdi", "edi", "di", "dil":
		pb.Append(fmtReadRdiBytes)
	case "rsi", "esi", "si", "sil":
		pb.Append(fmtReadRsiBytes)
	case "rdx", "edx", "dx", "dl":
		pb.Append(fmtReadRdxBytes)
	case "rcx", "ecx", "cx", "cl":
		pb.Append(fmtReadRcxBytes)
	case "r8", "r8d", "r8w", "r8b":
		pb.Append(fmtReadR8Bytes)
	case "r9", "r9d", "r9w", "r9b":
		pb.Append(fmtReadR9Bytes)
	default:
		panic("Unknown register")
	}
	pb.AppendByte(pb.fmtDelimiter)
}

// FmtReadStack appends parts of a payload that use a format string vulnerability
// to leak values from the stack.
//
// stackAddr is the base address of the stack frame (typically the value of RSP/ESP
// at the moment of the vulnerable printf call).
//
// leakAddresses are absolute addresses located on the stack whose values should be
// leaked. For each address, the function calculates its positional argument index
// relative to stackAddr and appends a corresponding "%<n>$p" format specifier.
//
// The argument index is computed as:
//
//	(leakAddr - stackAddr) / (architecture bitness / 8)
//
// For amd64, the first six arguments are passed via registers (rdi, rsi, rdx, rcx,
// r8, r9) according to the System V ABI, so the index is additionally shifted by 6.
//
// Supported architectures:
//   - i386
//   - amd64
//
// The function panics if called on an unsupported architecture.
func (pb *Builder) FmtReadStack(stackAddr binutils.Addr, leakAddrs ...binutils.Addr) {
	if pb.arch != binutils.ArchAmd64 && pb.arch != binutils.ArchI386 {
		panic("FmtReadStack supports only i386 and amd64 architectures")
	}

	for _, leakAddr := range leakAddrs {
		offset := leakAddr - stackAddr
		number := uint64(offset) / uint64(pb.arch.Bitness/8)
		number += 6 // add to number the first 6 arguments for amd64 calling convention

		pb.AppendByte('%')
		pb.payload = strconv.AppendUint(pb.payload, number, 10)
		pb.Append([]byte{'$', 'p'})
		pb.AppendByte(pb.fmtDelimiter)
	}
}

// Build returns the built payload.
func (pb *Builder) Build() []byte {
	return pb.payload
}

// Delimiter returns the delimiter byte used in format string specifiers.
//
// The delimiter is used to separate format specifiers from the payload.
// By default, the delimiter is '-' (hyphen).
func (pb *Builder) Delimiter() byte {
	return pb.fmtDelimiter
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
