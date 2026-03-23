package main_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/checker"
	"golang.org/x/tools/go/packages"

	main "github.com/quay/claircore/datastore/internal/cmd/postgres_querytool"
)

func TestAnalyzers(t *testing.T) {
	err := analysis.Validate([]*analysis.Analyzer{
		main.FindQuery,
		main.FormatInline,
		main.GenerateMetadata,
	})
	if err != nil {
		t.Error(err)
	}

	t.Run("FindQuery", func(t *testing.T) {
		t.Parallel()
		a := runOne(t, main.FindQuery, "find")
		want := []main.Query{
			{Index: 16, Args: map[string]string{"testonly": ""}},
			{Index: 46, Args: map[string]string{"testonly": ""}},
			{Index: 54, Args: map[string]string{"testonly": ""}},
			{Index: 84, Args: map[string]string{"testonly": ""}},
			{Index: 102, Args: map[string]string{"testonly": ""}, File: "g.txt", Embed: true},
			{Index: 118, Args: map[string]string{"operation": "SELECT"}},
		}
		if got := a.Result.([]main.Query); !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("FormatInline", func(t *testing.T) {
		t.Parallel()
		a := runOne(t, main.FormatInline, "format")
		if a.Err != nil {
			t.Fail()
		}
	})

	t.Run("GenerateMetadata", func(t *testing.T) {
		t.Parallel()
		output := filepath.Join(t.TempDir(), "generated.go")
		main.GenerateMetadata.Flags.Lookup("output").Value.Set(output)
		a := runOne(t, main.GenerateMetadata, "find")
		if err := a.Err; err != nil {
			t.Error(err)
		}
		b, err := os.ReadFile(output)
		if err != nil {
			t.Error(err)
		}
		t.Logf("generated output:\n%s", string(b))
	})
}

func runOne(t testing.TB, a *analysis.Analyzer, which string) *checker.Action {
	t.Helper()
	dir := `testdata/_test` + which
	mode := packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles | packages.NeedImports |
		packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedTypesInfo |
		packages.NeedDeps | packages.NeedModule | packages.NeedEmbedPatterns | packages.NeedEmbedFiles | packages.LoadAllSyntax | packages.LoadFiles
	cfg := &packages.Config{
		Mode:  mode,
		Dir:   dir,
		Tests: true,
		Env:   os.Environ(),
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatal(err)
	}
	// Hack for EmbedFiles...
	for _, p := range pkgs {
		p.OtherFiles = append(p.OtherFiles, p.EmbedFiles...)
	}

	res, err := checker.Analyze([]*analysis.Analyzer{a}, pkgs, nil)
	if err != nil {
		t.Errorf("Analyze: %v", err)
		return nil
	}
	if got, want := len(res.Roots), 1; got != want {
		t.Errorf("unexpected number of packages: got: %d, want: %d", got, want)
		return nil
	}
	return res.Roots[0]
}
