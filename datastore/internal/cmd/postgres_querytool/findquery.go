package main

import (
	"cmp"
	"go/ast"
	"go/token"
	"reflect"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

var FindQuery = &analysis.Analyzer{
	Name:       "findquery",
	Doc:        findQueryDoc,
	Run:        findQueryRun,
	Requires:   []*analysis.Analyzer{inspect.Analyzer},
	ResultType: reflect.TypeFor[[]Query](),
}

type Query struct {
	Index int32
	Args  map[string]string
	File  string
	Embed bool
}

const findQueryDoc = `TODO: write documentation`

func findQueryRun(p *analysis.Pass) (any, error) {
	var qs []Query
	in := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	for cur := range in.Root().Preorder((*ast.GenDecl)(nil)) {
		decl := cur.Node().(*ast.GenDecl)

		if decl.Tok == token.IMPORT || decl.Tok == token.TYPE {
			continue
		}
		for cur := range cur.Preorder((*ast.ValueSpec)(nil)) {
			spec := cur.Node().(*ast.ValueSpec)

			cg := cmp.Or(spec.Doc, decl.Doc)
			if cg == nil {
				continue
			}
			args, ok := handleQueryDirective(cg)
			if !ok {
				continue
			}
			file, ok := handleEmbedDirective(p, cg)
			qs = append(qs, Query{
				Index: cur.Index(),
				Args:  args,
				File:  file,
				Embed: ok,
			})
		}
	}

	return qs, nil
}

func handleQueryDirective(cg *ast.CommentGroup) (map[string]string, bool) {
	args := make(map[string]string)
	for _, c := range cg.List {
		d, ok := ast.ParseDirective(c.Pos(), c.Text)
		if !ok || d.Tool != `i14n` {
			continue
		}
		args[d.Name] = d.Args
	}

	if len(args) == 0 {
		return nil, false
	}
	return args, true
}

func handleEmbedDirective(p *analysis.Pass, cg *ast.CommentGroup) (string, bool) {
	for _, c := range cg.List {
		d, ok := ast.ParseDirective(c.Pos(), c.Text)
		if !ok || d.Tool != `go` || d.Name != `embed` {
			continue
		}
		return d.Args, true
	}
	return "", false
}
