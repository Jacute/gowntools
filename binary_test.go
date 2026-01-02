package pwn

import (
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
