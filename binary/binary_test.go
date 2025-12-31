package binary

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeBinary(t *testing.T) {
	testcases := []struct {
		name            string
		path            string
		expectedBinInfo *BinaryInfo
		expectedErr     error
	}{
		{
			name: "static linking with all defs | amd64 linux",
			path: "./testdata/linux_amd64/static_main",
			expectedBinInfo: &BinaryInfo{
				Compiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
				OS:            OSLinux,
				Arch:          ArchAmd64,
				StaticLinking: true,
				ByteOrder:     binary.LittleEndian,
				Security: &SecurityInfo{
					CanaryEnable: true,
					PIEEnable:    false,
					NXEnable:     true,
				},
			},
		},
		{
			name: "dynamic linking with all defs | amd64 linux",
			path: "./testdata/linux_amd64/dynamic_main",
			expectedBinInfo: &BinaryInfo{
				Compiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
				OS:            OSLinux,
				Arch:          ArchAmd64,
				StaticLinking: false,
				ByteOrder:     binary.LittleEndian,
				Security: &SecurityInfo{
					CanaryEnable: true,
					PIEEnable:    true,
					NXEnable:     true,
				},
			},
		},
		{
			name: "dynamic linking without pie | amd64 linux",
			path: "./testdata/linux_amd64/no_pie_main",
			expectedBinInfo: &BinaryInfo{
				Compiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
				OS:            OSLinux,
				Arch:          ArchAmd64,
				StaticLinking: false,
				ByteOrder:     binary.LittleEndian,
				Security: &SecurityInfo{
					CanaryEnable: true,
					PIEEnable:    false,
					NXEnable:     true,
				},
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			info, err := AnalyzeBinary(tc.path)
			require.Equal(t, tc.expectedErr, err)
			require.Equal(t, tc.expectedBinInfo, info)
		})
	}
}
