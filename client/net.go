package client

import (
	"io"
	"net"
)

type Conn struct {
	conn net.Conn
}

// NewTCP connects to the address on the "TCP" network
//
// Examples:
//
//	NewTCP("golang.org:http")
//	NewTCP("198.51.100.1:80")
func NewTCP(address string) (Client, error) {
	c, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn: c,
	}, nil
}

// NewUDP connects to the address on the "UDP" network
//
// Examples:
//
//	NewUDP("golang.org:http")
//	NewUDP("198.51.100.1:80")
func NewUDP(address string) (Client, error) {
	c, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	return &Conn{
		conn: c,
	}, nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.conn.Read(b)
}

func (c *Conn) ReadAll() ([]byte, int, error) {
	buf := make([]byte, 0, 64)
	for {
		_, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return buf, len(buf), nil
			}
			return nil, 0, err
		}
	}
}

// ReadUntil reads until the data is found
func (c *Conn) ReadUntil(data []byte) ([]byte, int, error) {
	return nil, 0, nil
}
