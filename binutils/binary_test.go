package binutils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinaryInfoString(t *testing.T) {
	bin, err := AnalyzeBinary("./testdata/linux_amd64/static_main")
	require.NoError(t, err)

	info := bin.Info()
	out := info.String()
	strs := strings.Split(out, "\n")

	require.Contains(t, strs, "OS: Linux")
	require.Contains(t, strs, "Arch: amd64")
	require.Contains(t, strs, "Compiler: GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0")
	require.Contains(t, strs, "Linking: static")
	require.Contains(t, strs, "Byte Order: LittleEndian")
	require.Contains(t, strs, "RELRO: partial")
	require.Contains(t, strs, "Canary: yes")
	require.Contains(t, strs, "PIE: no")
	require.Contains(t, strs, "NX: yes")
}
