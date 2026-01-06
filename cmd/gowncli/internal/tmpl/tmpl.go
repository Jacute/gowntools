package tmpl

import (
	"context"
	"fmt"
	"io"
	"text/template"
)

type TemplateParams struct {
	Module      string
	ProjectName string
	Version     string
	BinPath     string
	Host        string
	Port        uint16
	IsRemote    bool
}

type Executor struct {
	params     *TemplateParams
	templateCh chan *Template
}

func NewExecutor(params *TemplateParams) *Executor {
	return &Executor{
		params:     params,
		templateCh: make(chan *Template),
	}
}

func (e *Executor) Process(ctx context.Context, templates ...*Template) error {
	defer close(e.templateCh)

	go func() {
		err := e.Execute(ctx)
		if err != nil {
			// TODO: process err
		}
	}()

	err := e.PrepareTemplates(ctx, templates...)
	if err != nil {
		return err
	}

	return nil
}

func (e *Executor) PrepareTemplates(ctx context.Context, templates ...*Template) error {
	for _, tmpl := range templates {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := io.ReadAll(tmpl.r)
		if err != nil {
			return fmt.Errorf("error reading template: %w", err)
		}

		t, err := template.New("").Parse(string(data))
		if err != nil {
			return fmt.Errorf("error parsing template: %w", err)
		}
		tmpl.t = t

		e.templateCh <- tmpl
	}

	return nil
}

func (e *Executor) Execute(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case tmpl := <-e.templateCh:
			if tmpl == nil {
				return nil
			}
			err := tmpl.t.Execute(tmpl.w, e.params)
			if err != nil {
				return err
			}
		}
	}
}
