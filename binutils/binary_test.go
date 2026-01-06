package binutils

import (
	"encoding/binary"
	"fmt"
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
			require.Equal(tt, tc.expectedErr, err)

			require.Equal(tt, tc.expectedArch, info.Arch)
			require.Equal(tt, tc.expectedOS, info.OS)
			require.Equal(tt, tc.expectedCompiler, info.Compiler)
			require.Equal(tt, tc.expectedStaticLinking, info.StaticLinking)
			require.Equal(tt, tc.expectedByteOrder, info.ByteOrder)
			require.Equal(tt, tc.expectedSecurity, info.Security)
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
			require.NoError(tt, err)

			addr, err := bn.GetSymbolAddr("win")
			require.NoError(tt, err)
			require.Equal(tt, tc.expected, addr)
		})
	}
}

func TestGetGadgetAddr(t *testing.T) {
	testcases := []struct {
		name         string
		libcPath     string
		gadget       []byte
		expectedAddr Addr
		expectedErr  error
	}{
		{
			name:         "pop rdi ; ret",
			libcPath:     "./testdata/libc/libc.so.6",
			gadget:       []byte{0x5f, 0xc3},
			expectedAddr: Addr(0x000000000002a145),
		},
		{
			name:        "not found",
			libcPath:    "./testdata/libc/libc.so.6",
			gadget:      []byte{0x12, 0x34, 0x56, 0x78},
			expectedErr: ErrGadgetNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			binInfo, err := AnalyzeBinary(tc.libcPath)
			require.NoError(tt, err)

			// binInfo.PrintGadgets()
			addrs, err := binInfo.GetGadgetAddr(tc.gadget)
			require.ErrorIs(tt, tc.expectedErr, err)

			fmt.Println(addrs)
			if tc.expectedErr == nil {
				require.Contains(tt, addrs, tc.expectedAddr)
			}
		})
	}
}
