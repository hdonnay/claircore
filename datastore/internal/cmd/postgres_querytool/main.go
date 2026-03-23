// Postgres_querytool is a command to be used with "go generate" to generate
// SQL query metadata.
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(FindQuery, FormatInline, GenerateMetadata)
}

/*
type Options struct {
	Dir      string
	Patterns []string
}

func Main(ctx context.Context, opts Options) error {
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedDeps | packages.NeedModule | packages.NeedEmbedFiles
	cfg := &packages.Config{
		Mode:    mode,
		Context: ctx,
		Dir:     opts.Dir,
		Tests:   true,
	}
	pkgs, err := packages.Load(cfg, opts.Patterns...)
	if err != nil {
		return err
	}
	// Hack for EmbedFiles...
	for _, p := range pkgs {
		p.OtherFiles = append(p.OtherFiles, p.EmbedFiles...)
	}

	graph, err := checker.Analyze(analyzers, pkgs, nil)
	if err != nil {
		return err
	}
	errs := make([]error, 0, len(graph.Roots))
	for res := range graph.All() {
		errs = append(errs, res.Err)
	}

	return errors.Join(err)
}
*/
