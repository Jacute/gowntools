package cmd

import (
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"text/template"

	"github.com/spf13/cobra"
)

//go:embed templates/*
var templatesFS embed.FS

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

type templateParams struct {
	Module      string
	ProjectName string
	Version     string
	BinPath     string
	Host        string
	Port        uint16
	IsRemote    bool
}

// templateCmd represents the template command
var templateCmd = &cobra.Command{
	Use:   "template",
	Short: "generation of exploit templates",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return validateTargetFlags()
	},
	RunE: tmpl,
}

func tmpl(cmd *cobra.Command, args []string) error {
	if err := validateName(name); err != nil {
		return err
	}
	curDir, err := os.Getwd()
	if err != nil {
		return err
	}

	fmt.Println("Generating exploit template...")

	err = os.Mkdir(name, 0744)
	if err != nil && os.IsNotExist(err) {
		return err
	}

	mainFile, err := templatesFS.Open("templates/main.go.tmpl")
	if err != nil {
		return err
	}
	defer mainFile.Close()
	modFile, err := templatesFS.Open("templates/go.mod.tmpl")
	if err != nil {
		return err
	}
	defer modFile.Close()
	resultMainFile, err := os.Create(fmt.Sprintf("%s/main.go", name))
	if err != nil {
		return err
	}
	defer resultMainFile.Close()
	resultModFile, err := os.Create(fmt.Sprintf("%s/go.mod", name))
	if err != nil {
		return err
	}
	defer resultModFile.Close()

	err = execTmpl(mainFile, resultMainFile)
	if err != nil {
		return err
	}
	err = execTmpl(modFile, resultModFile)
	if err != nil {
		return err
	}

	modCmd := exec.CommandContext(cmd.Context(), "go", "mod", "tidy")
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

func execTmpl(in io.Reader, out io.Writer) error {
	data, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("error reading template: %w", err)
	}

	tmpl, err := template.New(name).Parse(string(data))
	if err != nil {
		return fmt.Errorf("error parsing template: %w", err)
	}

	isRemote := true
	if host == "" && port == 0 {
		isRemote = false
	}
	return tmpl.Execute(out, templateParams{
		Module:      Module,
		ProjectName: name,
		Version:     Version,
		BinPath:     binPath,
		Host:        host,
		Port:        port,
		IsRemote:    isRemote,
	})
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
