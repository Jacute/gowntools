package pwn

import (
	"bytes"
	"io"
	"net"
)

type Conn struct {
	conn io.ReadWriteCloser
}

// NewTCP connects to the address on the "TCP" network
// Function panics on error
//
// Examples:
//
//	NewTCP("golang.org:http")
//	NewTCP("198.51.100.1:80")
func NewTCP(address string) Client {
	c, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	return &Conn{
		conn: c,
	}
}

// NewUDP connects to the address on the "UDP" network
// Function panics on error
//
// Examples:
//
//	NewUDP("golang.org:http")
//	NewUDP("198.51.100.1:80")
func NewUDP(address string) Client {
	c, err := net.Dial("udp", address)
	if err != nil {
		panic(err)
	}
	return &Conn{
		conn: c,
	}
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *Conn) WriteLine(b []byte) error {
	_, err := c.conn.Write(append(b, '\n'))
	return err
}

func (c *Conn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// ReadAll reads data from the connection until it reaches the end of
// the connection (EOF). The function returns the data read from the
// connection and the number of bytes read.
func (c *Conn) ReadAll() (out []byte, n int, err error) {
	tmp := make([]byte, 64)

	var connN int
	for {
		connN, err = c.conn.Read(tmp)
		if connN > 0 {
			out = append(out, tmp[:connN]...)
			n += connN
		}
		if err != nil {
			if err == io.EOF {
				return out, n, nil
			}
			return nil, 0, err
		}

		if connN == 0 {
			return out, n, nil
		}
	}
}

// ReadUntil reads data from the connection until it finds the given data.
//
// The function returns the data read from the connection up to the given data
// and the number of bytes read. If an error occurs, the function returns nil,
// 0 and the error. If the end of the connection is reached, the function
// returns nil, 0 and io.EOF.
func (c *Conn) ReadUntil(data []byte) (out []byte, err error) {
	for !(len(out) >= len(data) && bytes.Equal(out[len(out)-len(data):], data)) {
		ch := make([]byte, 1)
		_, err = c.conn.Read(ch)
		if err != nil {
			if err == io.EOF {
				return nil, err
			}
			return nil, err
		}
		out = append(out, ch...)
	}
	return out, nil
}

// ReadLine reads data from the connection until it finds a newline character.
func (c *Conn) ReadLine() ([]byte, error) {
	out, err := c.ReadUntil([]byte("\n"))
	if err != nil {
		return nil, err
	}
	out = out[:len(out)-1]
	return out, nil
}
