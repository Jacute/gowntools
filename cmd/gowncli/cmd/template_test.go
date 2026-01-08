package cmd

import (
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestGenTemplate(t *testing.T) {
	templateCmd := NewTemplateCmd("v0.0.5", "github.com/Jacute/gowntools")

	rootCmd := &cobra.Command{}
	rootCmd.AddCommand(templateCmd)

	testcases := []struct {
		name        string
		exploitName string
		binaryPath  string
		expectedErr error
	}{
		{
			name:        "ok binary",
			exploitName: "testtest123",
			binaryPath:  "../../../testdata/readwritetest/main",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			tt.Cleanup(func() {
				os.RemoveAll(tc.exploitName)
			})
			out, _, err := executeCommand(rootCmd, "template", "-n", tc.exploitName, "--binary", tc.binaryPath)

			require.ErrorIs(tt, err, tc.expectedErr)
			require.Equal(tt, fmt.Sprintf(`Generating exploit template...
Template created in directory %s
`, tc.exploitName), out)

			require.DirExists(tt, tc.exploitName)
			require.FileExists(tt, path.Join(tc.exploitName, "main.go"))
			require.FileExists(tt, path.Join(tc.exploitName, "go.mod"))
			require.FileExists(tt, path.Join(tc.exploitName, "go.sum"))
		})
	}
}
