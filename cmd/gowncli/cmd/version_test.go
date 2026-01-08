package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	rootCmd := &cobra.Command{}
	rootCmd.AddCommand(NewVersionCmd(Version, Module))
	out, _, err := executeCommand(rootCmd, "version")
	require.NoError(t, err)
	require.Equal(t, "version: (devel)\nlibrary module: github.com/Jacute/gowntools\n", out)
}

func executeCommand(cmd *cobra.Command, args ...string) (string, string, error) {
	bufOut := new(bytes.Buffer)
	bufErr := new(bytes.Buffer)

	cmd.SetOut(bufOut)
	cmd.SetErr(bufErr)
	cmd.SetArgs(args)

	err := cmd.Execute()

	return bufOut.String(), bufErr.String(), err
}
