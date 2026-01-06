package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gowncli",
	Short: "CLI interface for gowntools",
	Long: `gowncli is a command-line interface for gowntools.

It provides utilities for binary analysis (currently ELF),
exploit template generation, and other tasks commonly used in
CTF any binary exploitation.`,
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {

}
