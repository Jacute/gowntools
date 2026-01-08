package binutils

import (
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestScanELF(t *testing.T) {
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
		// AMD64
		{
			name:                  "static linking | gcc amd64 linux",
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
			name:                  "dynamic linking with all defs | gcc amd64 linux",
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
			name:                  "dynamic linking without pie | gcc amd64 linux",
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
			name:                  "dynamic linking without defs | gcc amd64 linux",
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
		// X86
		{
			name:                  "gcc x86 linux",
			path:                  "./testdata/linux_x86/x86",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchI386,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoEnable,
				CanaryEnable: true,
				PIEEnable:    true,
				NXEnable:     true,
			},
		},
		// ARM32
		{
			name:                  "gcc arm32 linux",
			path:                  "./testdata/linux_arm32/arm32",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchArm32,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoEnable,
				CanaryEnable: true,
				PIEEnable:    true,
				NXEnable:     true,
			},
		},
		// ARM64
		{
			name:                  "gcc arm64 linux",
			path:                  "./testdata/linux_arm64/arm64",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchArm64,
			expectedStaticLinking: false,
			expectedByteOrder:     binary.LittleEndian,
			expectedSecurity: &SecurityInfo{
				RelRo:        RelRoEnable,
				CanaryEnable: true,
				PIEEnable:    true,
				NXEnable:     true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			f, err := elf.Open(tc.path)
			if err != nil {
				tt.Fatalf("failed to open ELF file: %v", err)
			}

			bin, err := scanELF(f)
			require.ErrorIs(tt, err, tc.expectedErr)

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

func TestGetSymbolAddrELF(t *testing.T) {
	testcases := []struct {
		name         string
		path         string
		symbolName   string
		expectedAddr Addr
		expectedErr  error
	}{
		{
			name:         "static",
			path:         "./testdata/linux_amd64/static_main",
			symbolName:   "win",
			expectedAddr: Addr(0x0000000000401905),
		},
		{
			name:         "dynamic",
			path:         "./testdata/linux_amd64/dynamic_main",
			symbolName:   "win",
			expectedAddr: Addr(0x00000000000011a9),
		},
		{
			name:        "not found",
			path:        "./testdata/linux_amd64/dynamic_main",
			symbolName:  "dasjosojdasj",
			expectedErr: ErrSymbolNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			bn, err := AnalyzeBinary(tc.path)
			require.NoError(tt, err)

			addr, err := bn.GetSymbolAddr(tc.symbolName)
			require.ErrorIs(tt, err, tc.expectedErr)
			require.Equal(tt, tc.expectedAddr, addr)
		})
	}
}

func TestGetGadgetAddrELF(t *testing.T) {
	testcases := []struct {
		name         string
		libcPath     string
		gadget       []string
		expectedAddr Addr
		expectedErr  error
	}{
		{
			name:         "pop rdi ; ret",
			libcPath:     "./testdata/libc/libc.so.6",
			gadget:       []string{"pop rdi", "ret"},
			expectedAddr: Addr(0x000000000002a145),
		},
		{
			name:        "not found",
			libcPath:    "./testdata/libc/libc.so.6",
			gadget:      []string{"pop rdi"},
			expectedErr: ErrGadgetNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			f, err := elf.Open(tc.libcPath)
			if err != nil {
				tt.Fatalf("failed to open ELF file: %v", err)
			}
			binInfo, err := scanELF(f)
			if err != nil {
				tt.Fatalf("failed to scan ELF file: %v", err)
			}

			// binInfo.PrintGadgets()
			addrs, err := binInfo.GetGadgetAddr(tc.gadget)
			require.ErrorIs(tt, tc.expectedErr, err)

			if tc.expectedErr == nil {
				require.Contains(tt, addrs, tc.expectedAddr)
			}
		})
	}
}

func TestGetStringAddrELF(t *testing.T) {
	testcases := []struct {
		name         string
		binaryPath   string
		str          string
		expectedErr  error
		expectedAddr Addr
	}{
		{
			name:         "ok",
			binaryPath:   "./testdata/libc/libc.so.6",
			str:          "/bin/sh",
			expectedAddr: Addr(0x1a7ea4),
		},
		{
			name:        "str not found",
			binaryPath:  "./testdata/libc/libc.so.6",
			str:         "njdasnjdaldjasml",
			expectedErr: ErrStringNotFound,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			bn, err := AnalyzeBinary(tc.binaryPath)
			if err != nil {
				tt.Fatalf("failed to analyze binary: %v", err)
			}

			addr, err := bn.GetStringAddr(tc.str)
			require.ErrorIs(tt, err, tc.expectedErr)
			require.Equal(tt, tc.expectedAddr, addr)
		})
	}
}
