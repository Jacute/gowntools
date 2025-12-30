package pwn

import (
	"io"
)

type Client interface {
	io.ReadWriteCloser

	ReadAll() (out []byte, n int, err error)
	ReadUntil(data []byte) (out []byte, err error)
	ReadLine() (out []byte, err error)

	WriteLine(b []byte) error
}
