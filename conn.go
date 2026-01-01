package pwn

import (
	"bytes"
	"io"
	"net"
)

// conn is a main
type conn struct {
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
	return &conn{
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
	return &conn{
		conn: c,
	}
}

func (c *conn) Close() error {
	return c.conn.Close()
}

func (c *conn) Write(b []byte) (n int, err error) {
	return c.conn.Write(b)
}

func (c *conn) WriteLine(b []byte) error {
	_, err := c.conn.Write(append(b, '\n'))
	return err
}

func (c *conn) Read(b []byte) (n int, err error) {
	return c.conn.Read(b)
}

// ReadAll reads data from the connection until it reaches the end of
// the connection (EOF). The function returns the data read from the
// connection and the number of bytes read.
func (c *conn) ReadAll() (out []byte, n int, err error) {
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
func (c *conn) ReadUntil(data []byte) (out []byte, err error) {
	buf := make([]byte, 1)
	for !(bytes.HasSuffix(out, data)) {
		n, err := c.conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				return out, err
			}
			return nil, err
		}
		if n == 0 {
			return out, nil
		}
		out = append(out, buf[:n]...)
	}
	return out, nil
}

// ReadLine reads data from the connection until it finds a newline character.
func (c *conn) ReadLine() ([]byte, error) {
	out, err := c.ReadUntil([]byte("\n"))
	if err != nil {
		if err == io.EOF {
			return out, err
		}
		return nil, err
	}
	out = out[:len(out)-1]
	return out, nil
}
