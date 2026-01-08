package tmpl

import (
	"context"
	"fmt"
	"io"
	"sync"
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
	params *TemplateParams
}

func NewExecutor(params *TemplateParams) *Executor {
	return &Executor{
		params: params,
	}
}

func (e *Executor) Process(ctx context.Context, templates ...*Template) error {
	execCh := make(chan *Template)
	errCh := make(chan error, 1)

	wg := &sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := e.execute(ctx, execCh)
		if err != nil {
			errCh <- err
		}
	}()

	go func() {
		defer wg.Done()
		err := e.prepareTemplates(ctx, execCh, templates...)
		if err != nil {
			errCh <- err
		}
		close(execCh)
	}()

	go func() {
		wg.Wait()
		close(errCh)
	}()

	return <-errCh
}

func (e *Executor) prepareTemplates(
	ctx context.Context,
	execCh chan *Template,
	templates ...*Template,
) error {
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

		execCh <- tmpl
	}

	return nil
}

func (e *Executor) execute(ctx context.Context, execCh chan *Template) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case tmpl, ok := <-execCh:
			if !ok {
				return nil
			}
			err := tmpl.t.Execute(tmpl.w, e.params)
			if err != nil {
				return err
			}
		}
	}
}
