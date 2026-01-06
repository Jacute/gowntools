package tmpl

import (
	"io"
	"os"
	"text/template"
)

type Template struct {
	t *template.Template
	r io.Reader
	w io.Writer
}

func NewTemplateOnFiles(pathIn, pathOut string) (*Template, error) {
	fIn, err := os.Open(pathIn)
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
