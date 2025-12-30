package binary

import (
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
		expectedErr           error
		expectedSecurityInfo  *SecurityInfo
	}{
		{
			name:                  "static linking amd64 linux",
			path:                  "./testdata/linux_amd64/static_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: true,
			expectedSecurityInfo: &SecurityInfo{
				CanaryEnable: true,
				PIEEnable:    false,
				NXEnable:     true,
			},
		},
		{
			name:                  "dynamic linking amd64 linux",
			path:                  "./testdata/linux_amd64/dynamic_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: false,
			expectedSecurityInfo: &SecurityInfo{
				CanaryEnable: true,
				PIEEnable:    true,
				NXEnable:     true,
			},
		},
		{
			name:                  "dynamic linking without pie amd64 linux",
			path:                  "./testdata/linux_amd64/dynamic_main",
			expectedCompiler:      "GCC: (Ubuntu 13.3.0-6ubuntu2~24.04) 13.3.0",
			expectedOS:            OSLinux,
			expectedArch:          ArchAmd64,
			expectedStaticLinking: false,
			expectedSecurityInfo: &SecurityInfo{
				CanaryEnable: true,
				PIEEnable:    false,
				NXEnable:     true,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			info, err := AnalyzeBinary(tc.path)
			require.Equal(t, tc.expectedErr, err)

			require.Equal(t, tc.expectedCompiler, info.Compiler)
			require.Equal(t, tc.expectedOS, info.OS)
			require.Equal(t, tc.expectedArch, info.Arch)
			require.Equal(t, tc.expectedStaticLinking, info.StaticLinking)
			require.Equal(t, tc.expectedSecurityInfo, info.Security)
		})
	}
}
