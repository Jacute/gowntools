package tmpl

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

func TestTemplateExecutor(t *testing.T) {
	testcases := []struct {
		name             string
		params           *TemplateParams
		expectedMainFile string
		expectedModFile  string
	}{
		{
			name: "ok local",
			params: &TemplateParams{
				Module:      "github.com/Jacute/gowntools",
				ProjectName: "exploit123",
				Version:     "v1.3.3.7",
				BinPath:     "./main",
				IsRemote:    false,
			},
			expectedMainFile: `package main

import (
	pwn "github.com/Jacute/gowntools"
	"github.com/Jacute/gowntools/binutils"
	"github.com/Jacute/gowntools/payload"
)

const binpath string = "./main"

func main() {
	c := pwn.NewBinary(binpath)
	defer c.Close()
	bin, err := binutils.AnalyzeBinary(binpath)
	if err != nil {
		panic(err)
	}
	binInfo := bin.Info()

	exploit(c, binInfo)

	c.Interactive()
}

func exploit(c pwn.Client, binInfo *binutils.BinaryInfo) {
	pb := payload.NewBuilder(binInfo.Arch, binInfo.ByteOrder)
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
			expectedModFile: `module exploit123

go 1.25.5

require github.com/Jacute/gowntools v1.3.3.7
`,
		},
		{
			name: "ok remote with binary",
			params: &TemplateParams{
				Module:      "github.com/Jacute/gowntools",
				ProjectName: "exploit322",
				Version:     "v3.2.2",
				BinPath:     "./main",
				Host:        "10.10.13.37",
				Port:        1337,
				IsRemote:    true,
			},
			expectedMainFile: `package main

import (
	pwn "github.com/Jacute/gowntools"
	"github.com/Jacute/gowntools/binutils"
	"github.com/Jacute/gowntools/payload"
)

const binpath string = "./main"

func main() {
	c := pwn.NewTCP("10.10.13.37:1337")
	defer c.Close()
	bin, err := binutils.AnalyzeBinary(binpath)
	if err != nil {
		panic(err)
	}
	binInfo := bin.Info()

	exploit(c, binInfo)

	c.Interactive()
}

func exploit(c pwn.Client, binInfo *binutils.BinaryInfo) {
	pb := payload.NewBuilder(binInfo.Arch, binInfo.ByteOrder)
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
			expectedModFile: `module exploit322

go 1.25.5

require github.com/Jacute/gowntools v3.2.2
`,
		},
		{
			name: "ok remote without binary",
			params: &TemplateParams{
				Module:      "github.com/Jacute/gowntools",
				ProjectName: "exploit322",
				Version:     "v3.2.2",
				BinPath:     "",
				Host:        "10.10.13.37",
				Port:        1337,
				IsRemote:    true,
			},
			expectedMainFile: `package main

import (
	"encoding/binary"
	
	pwn "github.com/Jacute/gowntools"
	"github.com/Jacute/gowntools/binutils"
	"github.com/Jacute/gowntools/payload"
)

func main() {
	c := pwn.NewTCP("10.10.13.37:1337")
	defer c.Close()
	exploit(c)

	c.Interactive()
}

func exploit(c pwn.Client) {
	pb := payload.NewBuilder(binutils.ArchAmd64, binary.LittleEndian)
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
			expectedModFile: `module exploit322

go 1.25.5

require github.com/Jacute/gowntools v3.2.2
`,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(tt *testing.T) {
			executor := NewExecutor(tc.params)

			mainOut := bytes.NewBuffer(nil)
			modOut := bytes.NewBuffer(nil)
			templates := []*Template{
				newTestTemplate(tt, "templates/main.go.tmpl", mainOut),
				newTestTemplate(tt, "templates/go.mod.tmpl", modOut),
			}

			err := executor.Process(tt.Context(), templates...)
			require.NoError(tt, err)

			require.Equal(tt, tc.expectedMainFile, mainOut.String())
			require.Equal(tt, tc.expectedModFile, modOut.String())
		})
	}
}

func newTestTemplate(t *testing.T, inputFilePath string, out *bytes.Buffer) *Template {
	inputFile, err := templatesFS.Open(inputFilePath)
	if err != nil {
		t.Fatal("open input file error")
	}

	return &Template{
		r: inputFile,
		w: nopWriteCloser{out},
	}
}
