package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"github.com/Jacute/gowntools/cmd/gowncli/internal/tmpl"
	"github.com/spf13/cobra"
)

var (
	templatesInput = []string{
		"templates/main.go.tmpl",
		"templates/go.mod.tmpl",
	}
)

// cli parameters
var (
	name    string
	binPath string
	host    string
	port    uint16
)

var (
	errExploitNameTooShort = errors.New("exploit name length should be longer then 2")
	errExploitNameTooLong  = errors.New("exploit name length should be less then 100")
	nameBlacklist          = "/\\:*!?\"<>| "
)

func NewTemplateCmd(version, module string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "generation of exploit templates",
		PreRunE: func(_ *cobra.Command, _ []string) error {
			return validateTargetFlags()
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := validateName(name); err != nil {
				return fmt.Errorf("error validating name: %w", err)
			}
			curDir, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("error getting current dir: %w", err)
			}

			cmd.Println("Generating exploit template...")

			exploitDir := path.Join(curDir, name)
			if _, err := os.Stat(exploitDir); os.IsNotExist(err) {
				if err := os.MkdirAll(exploitDir, 0755); err != nil {
					return fmt.Errorf("error making dir %s: %w", exploitDir, err)
				}
			}

			// prepare params
			params := tmpl.TemplateParams{
				Module:      module,
				ProjectName: name,
				Version:     version,
				BinPath:     path.Join(exploitDir, binPath),
				Host:        host,
				Port:        port,
			}
			params.IsRemote = true
			if host == "" && port == 0 {
				params.IsRemote = false
			}

			ctx := cmd.Context()
			executor := tmpl.NewExecutor(&params)

			// write templates
			templates := make([]*tmpl.Template, len(templatesInput))
			for i, pathIn := range templatesInput {
				pathOut := path.Join(
					curDir,
					name,
					strings.TrimSuffix(strings.TrimPrefix(pathIn, "templates/"), ".tmpl"),
				)
				t, err := tmpl.NewTemplateOnFiles(pathIn, pathOut)
				if err != nil {
					return fmt.Errorf("error creating template: %w", err)
				}
				templates[i] = t
			}

			err = executor.Process(ctx, templates...)
			if err != nil {
				return fmt.Errorf("error generating templates: %w", err)
			}

			modCmd := exec.CommandContext(ctx, "go", "mod", "tidy")
			modCmd.Dir = path.Join(curDir, name)

			modCmd.Stderr = os.Stderr
			modCmd.Stdout = os.Stdout

			err = modCmd.Start()
			if err != nil {
				return fmt.Errorf("error executing 'go mod tidy' in exploit directory: %w", err)
			}
			err = modCmd.Wait()
			if err != nil {
				return fmt.Errorf("error waiting 'go mod tidy': %w", err)
			}

			cmd.Printf("Template created in directory %s\n", name)

			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "exploit", "Exploit project name")
	cmd.Flags().StringVar(&binPath, "binary", "", "Path to local binary")
	cmd.Flags().StringVar(&host, "host", "", "Remote host")
	cmd.Flags().Uint16Var(&port, "port", 0, "Remote port")

	return cmd
}

func validateTargetFlags() error {
	hasBinary := binPath != ""
	hasHost := host != ""
	hasPort := port != 0

	switch {
	case hasHost && hasPort:
		return nil

	case hasBinary:
		return nil

	case hasHost || hasPort:
		return fmt.Errorf("--host and --port must be used together")

	default:
		return fmt.Errorf("you must specify either --binary or --host and --port")
	}
}

func validateName(name string) error {
	length := len(name)
	if length < 3 {
		return errExploitNameTooShort
	}
	if length > 100 {
		return errExploitNameTooLong
	}
	if strings.ContainsAny(name, nameBlacklist) {
		return fmt.Errorf("name shouldn't contain any characters in blacklist %s", nameBlacklist)
	}
	return nil
}

func init() {
	templateCmd := NewTemplateCmd(Version, Module)
	rootCmd.AddCommand(templateCmd)
}
