package binutils

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeBinary(t *testing.T) {
	testcases := []struct {
		name                  string
		path                  string
		expectedCompiler      string
		expectedOS            OS
		expectedArch          Arch
		expectedStaticLinking bool
		expectedByteOrder     binary.ByteOrder
		expectedSecurity      *SecurityInfo
		expectedErr           error
	}{
		{
			name:                  "static linking | amd64 linux",
			path:                  "./testdata/linux_amd64/static_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: true,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoPartial,
				CanaryEnable: true,
				PIEEnable:    false,
				NXEnable:     true,
			},
		},
		{
			name:                  "dynamic linking with all defs | amd64 linux",
			path:                  "./testdata/linux_amd64/dynamic_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoEnable,
				CanaryEnable: true,
				PIEEnable:    true,
				NXEnable:     true,
			},
		},
		{
			name:                  "dynamic linking without pie | amd64 linux",
			path:                  "./testdata/linux_amd64/no_pie_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoPartial,
				CanaryEnable: true,
				PIEEnable:    false,
				NXEnable:     true,
			},
		},
		{
			name:                  "dynamic linking without defs | amd64 linux",
			path:                  "./testdata/linux_amd64/no_defs_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoDisable,
				CanaryEnable: false,
				PIEEnable:    false,
				NXEnable:     false,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			bin, err := AnalyzeBinary(tc.path)
			require.Equal(tt, tc.expectedErr, err)

			info := bin.Info()
			require.Equal(tt, tc.expectedArch, info.Arch)
			require.Equal(tt, tc.expectedOS, info.OS)
			require.Equal(tt, tc.expectedCompiler, info.Compiler)
			require.Equal(tt, tc.expectedStaticLinking, info.StaticLinking)
			require.Equal(tt, tc.expectedByteOrder, info.ByteOrder)
			require.Equal(tt, tc.expectedSecurity, info.Security)
		})
	}
}

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
