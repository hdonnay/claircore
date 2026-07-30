// Package plan ...
package plan

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/ext"

	tocv1 "github.com/quay/claircore/internal/proto/gen/toc/v1"
)

var (
	_ cel.Library          = (*planLib)(nil)
	_ cel.SingletonLibrary = (*planLib)(nil)
)

type planLib struct{}

// LibraryName implements [cel.SingletonLibrary].
func (p *planLib) LibraryName() string {
	return "claircore.cel.plan"
}

// CompileOptions implements [cel.Library].
func (p *planLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(new(tocv1.TOCEntry), new(tocv1.TOC)),
		ext.Math(ext.MathVersion(3)),
	}
}

// ProgramOptions implements [cel.Library].
func (p *planLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{cel.EvalOptions(cel.OptOptimize)}
}

func splitSels(sels map[string]string) ([]string, []string) {
	name := slices.Collect(maps.Keys(sels))
	slices.Sort(name)
	expr := make([]string, len(sels))
	for i, n := range name {
		expr[i] = sels[n]
	}
	return name, expr
}

func parseExprs(_ context.Context, env *cel.Env, exprs []string) (*cel.Ast, error) {
	// TODO(hank) It feels like there really should be a way to compose these
	// without building a giant string.
	var expr strings.Builder
	expr.WriteString("[\n")
	for i, e := range exprs {
		expr.WriteString("bool( ")
		expr.WriteString(e)
		expr.WriteString(" ) ? ")
		fmt.Fprintf(&expr, "%du", 1<<i)
		expr.WriteString(" : 0u,\n")
	}
	expr.WriteString("\n]")
	src := common.NewStringSource(expr.String(), `composed selectors`)
	ast, iss := env.CompileSource(src)
	if iss != nil {
		return nil, iss.Err()
	}
	return ast, nil
}

// TODO(hank) Find a common spot for the debug architecture.
type ctxkey struct{}

var debugRoot = ctxkey{}

func WithDebugOutput(ctx context.Context, dir *os.Root) context.Context {
	return context.WithValue(ctx, debugRoot, dir)
}

func GetDebugOutput(ctx context.Context, name string) (*os.File, bool) {
	v := ctx.Value(debugRoot)
	if v == nil {
		return nil, false
	}
	r := v.(*os.Root)
	f, err := r.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o666)
	if err != nil {
		slog.DebugContext(ctx, "unable to open debug output", "path", filepath.Join(r.Name(), name))
		return nil, false
	}
	slog.DebugContext(ctx, "additional debug output", "path", filepath.Join(r.Name(), name))
	return f, true
}
