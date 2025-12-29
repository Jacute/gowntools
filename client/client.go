package client

import (
	"io"
)

type Client interface {
	io.ReadWriteCloser

	ReadAll() ([]byte, int, error)
}
