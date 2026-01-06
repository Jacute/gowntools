package cmd

import (
	"fmt"

	"github.com/Jacute/gowntools/binutils"
	"github.com/spf13/cobra"
)

var infoCmd = &cobra.Command{
	Use:   "info <elf-path>",
	Short: "Print information about binary (arch, os, security mitigations)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("missing <path>")
		}

		binInfo, err := binutils.AnalyzeBinary(args[0])
		if err != nil {
			return err
		}
		fmt.Println(binInfo)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(infoCmd)
}
