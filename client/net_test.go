package client

import (
	"gowntools/client/testsuite"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	st, err := testsuite.NewTestSuite("tcp")
	require.NoError(t, err)
	t.Cleanup(func() {
		st.Close()
	})

	go st.Listen()
	c, err := NewTCP(st.Address())
	require.NoError(t, err)
	defer c.Close()

	buf := make([]byte, 64)
	n, err := c.Read(buf)
	buf = buf[:n]
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(buf))
}
