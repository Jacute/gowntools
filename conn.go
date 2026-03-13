package pwn

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
)

var (
	ErrInteractiveModeNotSupported = errors.New("interactive mode only supported for TCP or binary")
)

// conn is a wrapper around a net.Conn
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

// WriteLine writes the given byte slice to the connection, appending a newline character
// It returns an error if writing fails.
func (c *conn) WriteLine(b []byte) error {
	_, err := c.conn.Write(append(b, '\n'))
	return err
}

// WriteStringLine writes the given string to the connection, appending a newline character
// It returns an error if writing fails.
func (c *conn) WriteStringLine(s string) error {
	return c.WriteLine([]byte(s))
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

// ReadStringLine reads a line of data from the connection and returns it as a string.
// It returns an error if reading fails.
//
// Examples:
//
//	c := NewTCP("golang.org:http")
//	s, err := c.ReadStringLine()
//
//	c := NewBinary("path/to/binary")
//	s, err := c.ReadStringLine()
func (c *conn) ReadStringLine() (string, error) {
	out, err := c.ReadLine()
	return string(out), err
}

// Interactive starts an interactive session with the connection.
//
// It forwards data between stdin/stdout and the underlying connection:
//
//   - stdin  → connection
//   - connection stdout → stdout
//   - connection stderr → stdout
//
// The function blocks until the connection is closed or the underlying
// process exits.
//
// Interactive mode is only supported for TCP and binary connections.
// If the underlying connection type does not support interactive mode,
// the function panics.
//
// Panics:
//   - if interactive mode is not supported for the connection type
//   - if an I/O error occurs during the interactive session
//
// Examples:
//
//	c := NewTCP("golang.org:80")
//	c.Interactive()
//
//	c := NewBinary("path/to/binary")
//	c.Interactive()
func (c *conn) Interactive() {
	err := interactiveIO(c, os.Stdin, os.Stdout)
	if err != nil {
		panic(err)
	}
}

func interactiveIO(conn *conn, r io.Reader, w io.Writer) error {
	switch v := conn.conn.(type) {
	case *net.TCPConn:
		return interactiveTCP(v, r, w)
	case *bin:
		return interactiveBin(v, r, w)
	default:
		return ErrInteractiveModeNotSupported
	}
}

func interactiveTCP(tc *net.TCPConn, r io.Reader, w io.Writer) error {
	var wg sync.WaitGroup
	var writeErr, readErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, writeErr = io.Copy(tc, r)
		_ = tc.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, readErr = io.Copy(w, tc)
	}()
	wg.Wait()

	if writeErr != nil {
		return writeErr
	}
	return readErr
}

func interactiveBin(bn *bin, r io.Reader, w io.Writer) error {
	var wg sync.WaitGroup
	wg.Add(3)

	var writeErr, outErr, errStreamErr error

	go func() {
		defer wg.Done()
		_, writeErr = io.Copy(bn.stdin, r)
		_ = bn.stdin.Close()
	}()

	go func() {
		defer wg.Done()
		_, outErr = io.Copy(w, bn.stdout)
	}()

	go func() {
		defer wg.Done()
		_, errStreamErr = io.Copy(w, bn.stderr)
	}()

	cmdErr := bn.cmd.Wait()
	wg.Wait()

	if writeErr != nil {
		return writeErr
	}
	if outErr != nil {
		return outErr
	}
	if errStreamErr != nil {
		return errStreamErr
	}

	return cmdErr
}
