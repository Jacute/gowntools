package tmpl

import (
	"embed"
	"errors"
	"io"
	"os"
	"text/template"
)

//go:embed templates/*
var templatesFS embed.FS

type Template struct {
	t *template.Template
	r io.ReadCloser
	w io.WriteCloser
}

func NewTemplateOnFiles(pathIn, pathOut string) (*Template, error) {
	fIn, err := templatesFS.Open(pathIn)
	if err != nil {
		return nil, err
	}
	fOut, err := os.Create(pathOut)
	if err != nil {
		return nil, err
	}
	return &Template{r: fIn, w: fOut}, nil
}

func (tr *Template) Read(p []byte) (n int, err error) {
	return tr.r.Read(p)
}

func (tr *Template) Write(p []byte) (n int, err error) {
	return tr.w.Write(p)
}

func (tr *Template) Close() error {
	var err error

	if wErr := tr.w.Close(); wErr != nil {
		err = wErr
	}

	if rErr := tr.r.Close(); rErr != nil {
		err = errors.Join(err, rErr)
	}

	return err
}
