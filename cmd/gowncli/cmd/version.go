package cmd

import (
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	Version, Module string
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Module = info.Main.Path
		Version = info.Main.Version
	} else {
		panic("error: no build info")
	}
}

func NewVersionCmd(version, module string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "print version of gowntools",
		Run: func(cmd *cobra.Command, _ []string) {
			cmd.Println("version:", version)
			cmd.Println("library module:", module)
		},
	}
	return cmd
}

func init() {
	rootCmd.AddCommand(NewVersionCmd(Version, Module))
}
