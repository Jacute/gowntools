package pwn

import (
	"io"
)

// Client is an interface that represents a pwn client (binary, tcp, udp, etc).
type Client interface {
	io.ReadWriteCloser

	ReadAll() (out []byte, n int, err error)
	ReadUntil(data []byte) (out []byte, err error)
	ReadLine() (out []byte, err error)

	WriteLine(b []byte) error

	Interactive()
}
