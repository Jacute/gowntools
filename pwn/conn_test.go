package pwn

import (
	"testing"

	"github.com/Jacute/gowntools/pwn/testsuite"

	"github.com/stretchr/testify/require"
)

func TestReadWrite(t *testing.T) {
	st, err := testsuite.NewTestSuite("tcp")
	require.NoError(t, err)
	t.Cleanup(func() {
		st.Close()
	})

	go st.Listen()
	c := NewTCP(st.Address())
	defer c.Close()

	// read
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	buf = buf[:n]
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(buf))
	require.Equal(t, 6, n)

	// write
	n, err = c.Write([]byte("aboba\n"))
	require.NoError(t, err)
	require.Equal(t, 6, n)

	// read until
	out, err := c.ReadUntil([]byte("echo: ab"))
	require.NoError(t, err)
	require.Equal(t, "echo: ab", string(out))

	// read
	buf = make([]byte, 64)
	n, err = c.Read(buf)
	require.NoError(t, err)
	buf = buf[:n]
	require.Equal(t, "oba\n", string(buf))
	require.Equal(t, 4, n)
}

func TestReadAll(t *testing.T) {
	st, err := testsuite.NewTestSuite("tcp")
	require.NoError(t, err)
	t.Cleanup(func() {
		st.Close()
	})

	go st.Listen()
	c := NewTCP(st.Address())
	defer c.Close()

	// write
	n, err := c.Write([]byte("aboba\n"))
	require.NoError(t, err)
	require.Equal(t, 6, n)

	// read all
	out, n, err := c.ReadAll()
	require.NoError(t, err)
	require.Equal(t, "hello\necho: aboba\n", string(out))
	require.Equal(t, 18, n)
}

func TestReadLine(t *testing.T) {
	st, err := testsuite.NewTestSuite("tcp")
	require.NoError(t, err)
	t.Cleanup(func() {
		st.Close()
	})

	go st.Listen()
	c := NewTCP(st.Address())
	defer c.Close()

	// read line
	out, err := c.ReadLine()
	require.NoError(t, err)
	require.Equal(t, "hello", string(out))
}
