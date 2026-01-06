package binutils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadFirstInstructionsI386(t *testing.T) {
	testcases := []struct {
		name                 string
		code                 []byte
		bitness              int
		n                    int
		expectedInstructions []string
	}{
		{
			name: "ok amd64",
			code: []byte{
				0x5f, // pop rdi
				0xc3, // ret
			},
			bitness: 64,
			n:       10,
			expectedInstructions: []string{
				"POP RDI",
				"RET",
			},
		},
		{
			name: "ok i386",
			code: []byte{
				0x5f, // pop edi
				0xc3, // ret
			},
			bitness: 32,
			n:       10,
			expectedInstructions: []string{
				"POP EDI",
				"RET",
			},
		},
		{
			name: "n < len(code)",
			code: []byte{
				0x48, 0x31, 0xC0, // xor rax, rax
				0x48, 0x31, 0xDB, // xor rbx, rbx
				0x48, 0x31, 0xC9, // xor rcx, rcx
				0x48, 0x31, 0xD2, // xor rdx, rdx
			},
			bitness: 64,
			n:       2,
			expectedInstructions: []string{
				"XOR RAX, RAX",
				"XOR RBX, RBX",
			},
		},
		{
			name:                 "empty",
			code:                 []byte{},
			bitness:              64,
			n:                    10,
			expectedInstructions: []string{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := readFirstInstructionsX86(tc.code, tc.bitness, tc.n)
			for i := range b {
				require.Equal(tt, tc.expectedInstructions[i], b[i].String())
			}
		})
	}
}
