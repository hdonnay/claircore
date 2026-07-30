package plan

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"math/bits"
	"reflect"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/interpreter"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/quay/claircore/internal/proto/delim"
	"github.com/quay/claircore/internal/proto/gen/plan"
	planv1 "github.com/quay/claircore/internal/proto/gen/plan/v1"
	tocv1 "github.com/quay/claircore/internal/proto/gen/toc/v1"
)

type EntrySelectors struct {
	name []string
	prog cel.Program
	// Selectors for the debug format.
	//
	// Created on demand. This pins the *cel.Ast
	debug func() *planv1.Selectors
}

func NewEntrySelectors(ctx context.Context, sels map[string]string) (*EntrySelectors, error) {
	if l := len(sels); l > 64 {
		return nil, fmt.Errorf("plan: too many selectors: %d (max 64)", l)
	}
	env := entryEnv()

	name, expr := splitSels(sels)
	ast, err := parseExprs(ctx, env, expr)
	if err != nil {
		return nil, err
	}
	slog.DebugContext(ctx, "composed selector", "selectors", logSels(sels), "composed", (*logAst)(ast))
	p, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize))
	if err != nil {
		return nil, err
	}

	sel := &EntrySelectors{
		name: name,
		prog: p,
		debug: sync.OnceValue(func() *planv1.Selectors {
			expr, err := cel.AstToString(ast)
			if err != nil {
				// This should never happen: we've already successfully parsed it
				// and haven't manipulated it since.
				panic("unable to stringify AST: " + err.Error())
			}
			return (planv1.Selectors_builder{
				Name:       name,
				Expression: &expr,
			}).Build()
		}),
	}
	/*
		sel := &EntrySelectors{
			name: name,
			prog: p,
			plan: sync.OnceValue(func() *planv1.Plan {
				expr, err := cel.AstToString(ast)
				if err != nil {
					panic("unable to stringify AST: " + err.Error())
				}
				return planv1.NewPlanV1((planv1.Selectors_builder{
					Name:       name,
					Expression: &expr,
				}).Build())
			}),
		}
	*/
	return sel, nil
}

var v1Header = sync.OnceValue(func() *plan.Header {
	s := new(descriptorpb.FileDescriptorSet)
	s.File = []*descriptorpb.FileDescriptorProto{
		protodesc.ToFileDescriptorProto(planv1.File_plan_v1_entry_proto),
		protodesc.ToFileDescriptorProto(planv1.File_plan_v1_selectors_proto),
	}
	return plan.Header_builder{
		DescriptorSet: s,
		Version:       plan.Version_VERSION_V1.Enum(),
	}.Build()
})

func (s *EntrySelectors) EvalEntries(ctx context.Context, seq iter.Seq[*tocv1.TOCEntry]) iter.Seq2[string, uint64] {
	return func(yield func(string, uint64) bool) {
		var m *planv1.Entry
		out, debug := GetDebugOutput(ctx, "entry_plan.binpb")
		if debug {
			defer out.Close()
			m = new(planv1.Entry)
			delim.MarshalTo(out, v1Header())
			delim.MarshalTo(out, s.debug())
		}

		for ent := range seq {
			if debug {
				m.Reset()
				m.SetEntry(ent)
			}
			if err := ctx.Err(); err != nil {
				if debug {
					m.SetError(err.Error())
					delim.MarshalTo(out, m)
				}
				return
			}
			res, err := s.EvalOne(ctx, ent)
			if debug {
				if err != nil {
					m.SetError(err.Error())
				} else {
					m.SetResult(res)
				}
				delim.MarshalTo(out, m)
			}
			if err == nil && !yield(ent.GetName(), res) {
				return
			}
		}
	}
}

func (s *EntrySelectors) EvalOne(ctx context.Context, ent *tocv1.TOCEntry) (bitset uint64, err error) {
	a := (*entry)(ent)

	res, _, err := s.prog.ContextEval(ctx, a)
	if err != nil {
		return 0, err
	}
	v, err := res.ConvertToNative(reflect.TypeFor[[]uint64]())
	if err != nil {
		panic("programmer error: " + err.Error())
	}
	for _, e := range v.([]uint64) {
		bitset |= e
	}

	return bitset, nil
}

// Names reports the names that are set in the passed bitset.
func (s *EntrySelectors) Names(bitset uint64) []string {
	res := make([]string, 0, bits.OnesCount64(bitset))
	for i := range 64 - bits.LeadingZeros64(bitset) {
		if ((1 << i) & bitset) != 0 {
			res = append(res, s.name[i])
		}
	}
	return res
}

// Result reports the status of all configured selectors, according to the
// passed bitset.
//
// If a value is not present, the selector is not present.
// Otherwise, the reported value indicates if the selector matched.
func (s *EntrySelectors) Result(bitset uint64) map[string]bool {
	out := make(map[string]bool, len(s.name))
	for i, k := range s.name {
		out[k] = ((1 << i) & bitset) != 0
	}
	return out
}

var _ cel.Activation = (*entry)(nil)

// Entry is a wrapper around [tocv1.TOCEntry] to make it easier to pass to a CEL
// invocation.
type entry tocv1.TOCEntry

// Parent implements [interpreter.Activation].
func (e *entry) Parent() interpreter.Activation {
	return nil
}

// ResolveName implements [interpreter.Activation].
func (e *entry) ResolveName(name string) (any, bool) {
	if name == "entry" {
		return (*tocv1.TOCEntry)(e), true
	}
	return nil, false
}

var (
	_ cel.Library          = (*entryLib)(nil)
	_ cel.SingletonLibrary = (*entryLib)(nil)
)

type entryLib struct{}

// LibraryName implements [cel.SingletonLibrary].
func (p *entryLib) LibraryName() string {
	return "claircore.cel.plan.entry"
}

func entryIsExecutable(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) != 1 {
		return nil, eh.NewError(target.ID(), "incorrect number of arguments")
	}
	entry := args[0]
	if k := entry.Kind(); k != ast.IdentKind {
		return nil, eh.NewError(entry.ID(), "argument of incorrect kind")
	}
	mode := eh.NewSelect(entry, "mode")
	size := eh.NewSelect(entry, "size")
	typ := eh.NewSelect(entry, "type")
	masked := eh.NewMemberCall("bitAnd", eh.NewIdent("math"), mode, eh.NewLiteral(types.Int(0o111)))

	checkmode := eh.NewCall(operators.NotEquals, masked, eh.NewLiteral(types.Int(0)))
	checksize := eh.NewCall(operators.Greater, size, eh.NewLiteral(types.Uint(0)))
	checktype := eh.NewCall(operators.Equals, typ, eh.NewLiteral(types.Int(tocv1.EntryType_ENTRY_TYPE_REG)))
	exp := eh.NewCall(operators.LogicalAnd, checktype, eh.NewCall(operators.LogicalAnd, checksize, checkmode))
	return exp, nil
}

func entryIsDir(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) != 1 {
		return nil, eh.NewError(target.ID(), "incorrect number of arguments")
	}
	entry := args[0]
	if k := entry.Kind(); k != ast.IdentKind {
		return nil, eh.NewError(entry.ID(), "argument of incorrect kind")
	}

	exp := eh.NewCall(
		operators.Equals,
		eh.NewSelect(entry, "type"),
		eh.NewLiteral(types.Int(tocv1.EntryType_ENTRY_TYPE_DIR)),
	)
	return exp, nil
}

// CompileOptions implements [cel.Library].
func (p *entryLib) CompileOptions() []cel.EnvOption {
	opts := []cel.EnvOption{
		cel.Macros(
			cel.GlobalMacro(
				"is_executable", 1, entryIsExecutable,
				cel.MacroDocs(""),
				cel.MacroExamples(""),
			),
			cel.GlobalMacro(
				"is_executable", 0,
				func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
					return entryIsExecutable(eh, target, append(args, eh.NewIdent("entry")))
				},
				cel.MacroDocs(""),
				cel.MacroExamples(""),
			),
			cel.GlobalMacro(
				"is_dir", 1, entryIsDir,
				cel.MacroDocs(""),
				cel.MacroExamples(""),
			),
			cel.GlobalMacro(
				"is_dir", 0,
				func(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
					return entryIsDir(eh, target, append(args, eh.NewIdent("entry")))
				},
				cel.MacroDocs(""),
				cel.MacroExamples(""),
			),
		),
	}
	for k, v := range tocv1.EntryType_value {
		opts = append(opts, cel.Constant(k, types.IntType, types.Int(v)))
	}
	return opts
}

// ProgramOptions implements [cel.Library].
func (p *entryLib) ProgramOptions() []cel.ProgramOption {
	return nil
}

var entryEnv = sync.OnceValue(func() *cel.Env {
	name := new(tocv1.TOCEntry).ProtoReflect().Descriptor().FullName()
	env, err := cel.NewEnv(
		cel.Lib(new(planLib)), cel.Lib(new(entryLib)),
		cel.Variable("entry", cel.ObjectType(string(name))),
	)
	// This shouldn't happen; this is effectively static initialization.
	if err != nil {
		panic(err)
	}
	return env
})
