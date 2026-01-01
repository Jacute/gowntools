package pwn

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExploitBinary(t *testing.T) {
	bn := NewBinary("./testdata/readwritetest/main")
	defer bn.Close()

	ln, err := bn.ReadLine()
	require.NoError(t, err)
	require.Equal(t, "hello!", string(ln))
}
