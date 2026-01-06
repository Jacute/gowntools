package binutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetSymbolAddrELF(t *testing.T) {
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
			binInfo, err := AnalyzeBinary(tc.libcPath)
			require.NoError(tt, err)

			// binInfo.PrintGadgets()
			addrs, err := binInfo.GetGadgetAddr(tc.gadget)
			require.ErrorIs(tt, tc.expectedErr, err)

			if tc.expectedErr == nil {
				require.Contains(tt, addrs, tc.expectedAddr)
			}
		})
	}
}
