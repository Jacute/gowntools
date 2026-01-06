package payload

import (
	"testing"

	"github.com/Jacute/gowntools/binutils"
	"github.com/stretchr/testify/require"
)

func TestP64(t *testing.T) {
	testcases := []struct {
		name          string
		addr          binutils.Addr
		expectedBytes []byte
	}{
		{
			name:          "zero",
			addr:          0,
			expectedBytes: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "non-zero",
			addr: 0x1234567890abcdef,
			expectedBytes: []byte{
				0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := P64(tc.addr)
			require.Equal(tt, tc.expectedBytes, b)
		})
	}
}

func TestP32(t *testing.T) {
	testcases := []struct {
		name          string
		addr          binutils.Addr
		expectedBytes []byte
	}{
		{
			name:          "zero",
			addr:          0,
			expectedBytes: []byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "non-zero",
			addr: 0x12345678,
			expectedBytes: []byte{
				0x78, 0x56, 0x34, 0x12,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := P32(tc.addr)
			require.Equal(tt, tc.expectedBytes, b)
		})
	}
}

func TestP16(t *testing.T) {
	testcases := []struct {
		name          string
		addr          binutils.Addr
		expectedBytes []byte
	}{
		{
			name:          "zero",
			addr:          0,
			expectedBytes: []byte{0x00, 0x00},
		},
		{
			name: "non-zero",
			addr: 0x1234,
			expectedBytes: []byte{
				0x34, 0x12,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := P16(tc.addr)
			require.Equal(tt, tc.expectedBytes, b)
		})
	}
}

func TestU64(t *testing.T) {
	testcases := []struct {
		name         string
		bytes        []byte
		expectedAddr binutils.Addr
	}{
		{
			name: "zero",
			bytes: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectedAddr: 0,
		},
		{
			name: "non-zero",
			bytes: []byte{
				0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
			},
			expectedAddr: 0x1234567890abcdef,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := U64(tc.bytes)
			require.Equal(tt, tc.expectedAddr, b)
		})
	}
}

func TestU32(t *testing.T) {
	testcases := []struct {
		name         string
		bytes        []byte
		expectedAddr binutils.Addr
	}{
		{
			name: "zero",
			bytes: []byte{
				0x00, 0x00, 0x00, 0x00,
			},
			expectedAddr: 0,
		},
		{
			name: "non-zero",
			bytes: []byte{
				0x78, 0x56, 0x34, 0x12,
			},
			expectedAddr: 0x12345678,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := U32(tc.bytes)
			require.Equal(tt, tc.expectedAddr, b)
		})
	}
}

func TestU16(t *testing.T) {
	testcases := []struct {
		name         string
		bytes        []byte
		expectedAddr binutils.Addr
	}{
		{
			name: "zero",
			bytes: []byte{
				0x00, 0x00,
			},
			expectedAddr: 0,
		},
		{
			name: "non-zero",
			bytes: []byte{
				0x34, 0x12,
			},
			expectedAddr: 0x1234,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			b := U16(tc.bytes)
			require.Equal(tt, tc.expectedAddr, b)
		})
	}
}
