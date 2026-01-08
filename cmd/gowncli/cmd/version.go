package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var (
	Version = "dev"
	Module  = "unknown_module"
)

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		Module = info.Main.Path
		Version = info.Main.Version
	} else {
		panic("error: no build info")
	}
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version of gowntools",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Println("version:", Version)
		fmt.Println("library module:", Module)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
