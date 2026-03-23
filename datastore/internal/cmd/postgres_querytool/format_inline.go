package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/token"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"

	"golang.org/x/sync/errgroup"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var FormatInline = &analysis.Analyzer{
	Name:     "formatinline",
	Doc:      formatInlineDoc,
	Run:      formatInlineRun,
	Requires: []*analysis.Analyzer{inspect.Analyzer, FindQuery},
}

// TODO(hank) Make the formatter command configurable.

const formatInlineDoc = `TODO: write documentation`

func formatInlineRun(p *analysis.Pass) (any, error) {
	qs := p.ResultOf[FindQuery].([]Query)
	if len(qs) == 0 {
		return nil, nil
	}
	in := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	// Use an errgroup of 1 to serialize emitting edits.
	var editGroup errgroup.Group
	edit := make(chan analysis.Diagnostic)
	editGroup.Go(func() error {
		for d := range edit {
			p.Report(d)
		}
		return nil
	})
	// Use an errgroup to run the formatter processes in parallel.
	var workGroup errgroup.Group
	work := make(chan *ast.BasicLit)
	workGroup.SetLimit(8)
	for workGroup.TryGo(func() error {
		// Needs to be below PWD for wasm sandbox reasons.
		//
		// Need to use a file because stdin seems to be broken.
		f, err := os.CreateTemp(".", "formatquery.")
		if err != nil {
			return err
		}
		defer func() {
			f.Close()
			os.Remove(f.Name())
		}()
		for l := range work {
			v, err := strconv.Unquote(l.Value)
			if err != nil {
				p.ReportRangef(l, `unable to unquote string literal: %v`, err)
				return err
			}
			if err := f.Truncate(0); err != nil {
				return err
			}
			if _, err := io.WriteString(f, v); err != nil {
				return err
			}

			cmd := exec.Command(`go`, `run`,
				`github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest`,
				`--language`, `postgresql`, f.Name(),
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				p.ReportRangef(l, `unable to format SQL: %s`, string(out))
				return err
			}
			if bytes.ContainsRune(out, '`') {
				p.ReportRangef(l, `output contained backquote: %s`, string(out))
				return errors.New("output contained backquote")
			}
			out = bytes.TrimSpace(out)
			if want := string(out); v != want {
				out = slices.Concat([]byte{'`'}, out, []byte{'`'})
				edit <- formatDiagnostic(l, out)
			}
		}
		return nil
	}) {
	}

	for _, q := range qs {
		if q.Embed {
			continue
		}
		for cur := range in.At(q.Index).Preorder((*ast.BasicLit)(nil)) {
			lit := cur.Node().(*ast.BasicLit)
			if lit.Kind != token.STRING {
				p.ReportRangef(lit, `"i14n" directive on non-string literal`)
				continue
			}
			work <- lit
		}
	}
	close(work)
	err := workGroup.Wait()
	close(edit)
	if err := errors.Join(err, editGroup.Wait()); err != nil {
		return nil, err
	}

	return nil, nil
}

func formatDiagnostic(l *ast.BasicLit, newtext []byte) analysis.Diagnostic {
	return analysis.Diagnostic{
		Pos:     l.Pos(),
		End:     l.End(),
		Message: "SQL query not formatted",
		SuggestedFixes: []analysis.SuggestedFix{
			{
				Message: "Format",
				TextEdits: []analysis.TextEdit{
					{
						Pos:     l.Pos(),
						End:     l.End(),
						NewText: newtext,
					},
				},
			},
		},
	}
}
