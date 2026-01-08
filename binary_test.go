package pwn

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const binPath = "./testdata/readwritetest/main"

func TestExploitBinary(t *testing.T) {
	bn := NewBinary(binPath)
	defer bn.Close()

	ln, err := bn.ReadLine()
	require.NoError(t, err)
	require.Equal(t, "hello!", string(ln))

	err = bn.WriteStringLine("aboba")
	require.NoError(t, err)

	ln, err = bn.ReadLine()
	require.NoError(t, err)
	require.Equal(t, "input: aboba", string(ln))
}

func TestInteractiveBin(t *testing.T) {
	c := NewBinary(binPath)
	defer c.Close()

	ln, err := c.ReadLine()
	require.NoError(t, err)
	require.Equal(t, "hello!", string(ln))

	var b *bin
	switch v := c.(type) {
	case *conn:
		var ok bool
		b, ok = v.conn.(*bin)
		if !ok {
			t.Fatal("unexpected type")
		}
	default:
		t.Fatal("unexpected type")
	}
	go func() {
		interactiveBin(b, os.Stdin, os.Stdout)
	}()
	b.stdin.Write([]byte("aboba\n"))

	data, err := io.ReadAll(b.stdout)
	require.NoError(t, err)
	require.Equal(t, "input: aboba\n", string(data))
}
