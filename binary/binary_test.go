package binary

import (
	"encoding/binary"
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
			info, err := AnalyzeBinary(tc.path)
			require.Equal(t, tc.expectedErr, err)

			require.Equal(t, tc.expectedArch, info.Arch)
			require.Equal(t, tc.expectedOS, info.OS)
			require.Equal(t, tc.expectedCompiler, info.Compiler)
			require.Equal(t, tc.expectedStaticLinking, info.StaticLinking)
			require.Equal(t, tc.expectedByteOrder, info.ByteOrder)
			require.Equal(t, tc.expectedSecurity, info.Security)
		})
	}
}

func TestGetSymbolAddr(t *testing.T) {
	testcases := []struct {
		name     string
		path     string
		expected Addr
	}{
		{
			name:     "static",
			path:     "./testdata/linux_amd64/static_main",
			expected: Addr(0x0000000000401905),
		},
		{
			name:     "dynamic",
			path:     "./testdata/linux_amd64/dynamic_main",
			expected: Addr(0x00000000000011a9),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			bn, err := AnalyzeBinary(tc.path)
			require.NoError(t, err)

			addr, err := bn.GetSymbolAddr("win")
			require.NoError(t, err)
			require.Equal(t, tc.expected, addr)
		})
	}
}
