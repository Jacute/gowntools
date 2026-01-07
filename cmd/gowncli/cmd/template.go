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

// templateCmd represents the template command
var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "generation of exploit templates",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return validateTargetFlags()
	},
	RunE: genTemplate,
}

func genTemplate(cmd *cobra.Command, args []string) error {
	if err := validateName(name); err != nil {
		return err
	}
	curDir, err := os.Getwd()
	if err != nil {
		return err
	}

	fmt.Println("Generating exploit template...")

	// prepare params
	params := tmpl.TemplateParams{
		Module:      Module,
		ProjectName: name,
		Version:     Version,
		BinPath:     path.Join(curDir, name, binPath),
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
			return err
		}
		templates[i] = t
	}

	err = executor.Process(ctx, templates...)
	if err != nil {
		return err
	}

	modCmd := exec.CommandContext(ctx, "go", "mod", "tidy")
	modCmd.Dir = path.Join(curDir, name)

	modCmd.Stderr = os.Stderr
	modCmd.Stdout = os.Stdout

	err = modCmd.Start()
	if err != nil {
		return err
	}
	err = modCmd.Wait()
	if err != nil {
		return err
	}

	fmt.Printf("Template created in directory %s\n", name)

	return nil
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
	rootCmd.AddCommand(templateCmd)

	templateCmd.Flags().StringVarP(&name, "name", "n", "exploit", "Exploit project name")
	templateCmd.Flags().StringVar(&binPath, "binary", "", "Path to local binary")
	templateCmd.Flags().StringVar(&host, "host", "", "Remote host")
	templateCmd.Flags().Uint16Var(&port, "port", 0, "Remote port")
}
