package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInfo(t *testing.T) {
	rootCmd.AddCommand(infoCmd)
	out, _, err := executeCommand(rootCmd, "info", "../../../testdata/readwritetest/main")
	require.NoError(t, err)
	require.Equal(t, `=== BINARY INFO ===
Arch: amd64
OS: Linux
Compiler: GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0
Linking: dynamic
Byte Order: LittleEndian
=== SECURITY ===
RELRO: partial
Canary: no
PIE: no
NX: yes
`, out)
}
