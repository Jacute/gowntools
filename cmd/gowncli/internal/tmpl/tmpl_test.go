package tmpl

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTemplateExecutor(t *testing.T) {
	testcases := []struct {
		name             string
		params           *templateParams
		expectedMainFile string
		expectedModFile  string
	}{
		{
			name: "ok",
			params: &templateParams{
				Module:      "github.com/Jacute/gowntools",
				ProjectName: "exploit123",
				Version:     "v1.3.3.7",
				BinPath:     "./main",
			},
			expectedMainFile: `package main

import (
	{{- if .IsRemote }}
	"encoding/binary"
	{{- end}}
	pwn "github.com/Jacute/gowntools"
	"github.com/Jacute/gowntools/binutils"
	"github.com/Jacute/gowntools/payload"
)

const binpath string = "{{.BinPath}}"

func main() {
	{{- if .IsRemote }}
	c := pwn.NewTCP("{{.Host}}:{{.Port}}")
	defer c.Close()

	exploit(c)
	{{- else }}
	c := pwn.NewBinary(binpath)
	defer c.Close()
	binInfo, err := binutils.AnalyzeBinary(binpath)
	if err != nil {
		panic(err)
	}

	exploit(c, binInfo)
	{{- end }}

	c.Interactive()
}

{{ if .IsRemote -}}
func exploit(c pwn.Client) {
	pb := payload.NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
{{- else }}
func exploit(c pwn.Client, binInfo *binutils.BinaryInfo) {
	pb := payload.NewBuilder(binInfo.Arch, binInfo.ByteOrder)
	{{- end }}
	payload := genPayload(pb)

	// exploit should be here

	// uncomment this for debug with gdb
	// pwn.Debug(bin)

	err := c.WriteLine(payload)
	if err != nil {
		panic(err)
	}
}

func genPayload(b *payload.Builder) []byte {
	// payload should be here
	// b.Fill('A', 72)
	// b.Addr(0xdeadbeefcafebabe)
	return b.Build()
}
`,
		},
	}

	mainFile, err := os.Open("templates/main.go.tmpl")
	if err != nil {
		t.Fatalf("error opening main.go.tmpl: %s", err.Error())
	}
	defer mainFile.Close()
	modFile, err := os.Open("templates/go.mod.tmpl")
	if err != nil {
		t.Fatalf("error opening go.mod.tmpl: %s", err.Error())
	}
	defer modFile.Close()

	buf := bytes.NewBuffer(nil)

	err = execTmpl(mainFile, buf)
	require.NoError(t, err)
	err = execTmpl(modFile, nil)
	require.NoError(t, err)
}
