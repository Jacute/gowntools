package pwn

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExploitBinary(t *testing.T) {
	bn := NewBinary("./testdata/readtest/main")
	defer bn.Close()

	buf := make([]byte, 64)
	n, err := bn.Read(buf)
	buf = buf[:n]
	require.NoError(t, err)
	require.Equal(t, "hello!\r\n", string(buf))
	require.Equal(t, 8, n)
}
