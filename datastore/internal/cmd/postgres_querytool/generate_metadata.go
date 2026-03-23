package main

import (
	"cmp"
	_ "embed"
	"flag"
	"fmt"
	"go/ast"
	"iter"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	pganalyze "github.com/pganalyze/pg_query_go/v6"
	pg_query "github.com/wasilibs/go-pgquery"
	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var GenerateMetadata = &analysis.Analyzer{
	Name:     "generatemetadata",
	Doc:      generateMetadataDoc,
	Run:      generateMetadataRun,
	Requires: []*analysis.Analyzer{inspect.Analyzer, FindQuery},
}

func init() {
	set := &GenerateMetadata.Flags
	set.Init("generatemetadata", flag.ContinueOnError)
	set.String("package", "query", "package name for generated file")
	set.String("output", "query/generated.go", "path for generated file")
	set.Bool("debug", false, "debug output")
}

const generateMetadataDoc = `TODO: write documentation`

func generateMetadataRun(p *analysis.Pass) (any, error) {
	qs := p.ResultOf[FindQuery].([]Query)
	if len(qs) == 0 {
		return nil, nil
	}
	in := p.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	tmpl, err := template.New("metadata").Parse(metadataTemplate)
	if err != nil {
		return nil, err
	}
	debug := getBoolFlag(p, "debug")

	outdir, outfile := filepath.Split(getStringFlag(p, "output"))
	root, err := os.OpenRoot(outdir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	out, err := root.Create("_" + outfile)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	data := TemplateData{
		Package:   getStringFlag(p, "package"),
		Operation: make(map[string]string),
		Summary:   make(map[string]string),
	}

	uniq := map[string]*ast.ValueSpec{}
	for _, q := range qs {
		spec := in.At(q.Index).Node().(*ast.ValueSpec)
		input, err := getQuery(p, q, spec)
		if err != nil {
			p.ReportRangef(spec, "unable to load query: %v", err)
			return nil, err
			// continue
		}
		if debug || true {
			ast.Fprint(os.Stderr, p.Fset, spec, nil)
			fmt.Fprintln(os.Stderr, input)
		}

		tree, err := pg_query.Parse(input)
		if err != nil {
			p.ReportRangef(spec, "unable to parse query: %v", err)
			continue
		}

		id := cmp.Or(q.Args["id"], spec.Names[0].Name)
		if prev, ok := uniq[id]; ok {
			p.ReportRangef(spec, "duplicate identifier %q (previously: %v)", id, p.Fset.Position(prev.Pos()))
			continue
		}
		uniq[id] = spec
		qid := strconv.Quote(id)
		println("qid:", qid)

		if op, ok := q.Args[`operation`]; ok {
			data.Operation[qid] = strconv.Quote(op)
		} else {
			data.Operation[qid] = guessOperation(p, tree)
		}
		if op, ok := q.Args[`summary`]; ok {
			data.Summary[qid] = strconv.Quote(op)
		} else {
			data.Summary[qid] = generateSummary(p, tree)
		}
	}

	if err := tmpl.Execute(out, &data); err != nil {
		return nil, err
	}
	if err := root.Rename("_"+outfile, outfile); err != nil {
		return nil, err
	}
	return nil, nil
}

//go:embed metadata.go.tmpl
var metadataTemplate string

type TemplateData struct {
	Package   string
	Operation map[string]string
	Summary   map[string]string
}

func (d *TemplateData) Attributes() iter.Seq[AttrFuncData] {
	return func(yield func(AttrFuncData) bool) {
		if len(d.Operation) != 0 {
			if !yield(AttrFuncData{
				Name:    "Operation",
				New:     "DBOperationName",
				Default: strconv.Quote("UNKNOWN"),
				Map:     d.Operation,
			}) {
				return
			}
		}
		if len(d.Summary) != 0 {
			if !yield(AttrFuncData{
				Name: "Summary",
				New:  "DBQuerySummary",
				Map:  d.Summary,
			}) {
				return
			}
		}
	}
}

type AttrFuncData struct {
	Name    string
	New     string
	Default string
	Map     map[string]string
}

func getStringFlag(p *analysis.Pass, name string) string {
	f := p.Analyzer.Flags.Lookup(name)
	g := f.Value.(flag.Getter)
	return g.Get().(string)
}

func getBoolFlag(p *analysis.Pass, name string) bool {
	f := p.Analyzer.Flags.Lookup(name)
	g := f.Value.(flag.Getter)
	return g.Get().(bool)
}

func getQuery(p *analysis.Pass, q Query, spec *ast.ValueSpec) (string, error) {
	if !q.Embed {
		s := spec.Values[0].(*ast.BasicLit).Value
		return strconv.Unquote(s)
	}
	filename := q.File
	for _, abs := range p.OtherFiles {
		if strings.HasSuffix(abs, filename) {
			filename = abs
			break
		}
	}
	b, err := p.ReadFile(filename)
	if err != nil {
		p.ReportRangef(spec, "unable to read embed file: %v", err)
		return "", err
	}
	return string(b), nil
}

func guessOperation(_ *analysis.Pass, tree *pganalyze.ParseResult) string {
	for _, stmt := range tree.Stmts {
		for n := range findNodes(stmt, predOps) {
			return opName(n)
		}
	}
	return unknown
}

func generateSummary(_ *analysis.Pass, tree *pganalyze.ParseResult) string {
	ops := func(m proto.Message) bool {
		switch m.(type) {
		case *pganalyze.SelectStmt,
			*pganalyze.CallStmt,
			*pganalyze.DeleteStmt,
			*pganalyze.UpdateStmt,
			*pganalyze.MergeStmt,
			*pganalyze.InsertStmt:
			return true
		default:
			return false
		}
	}
	opsTables := func(m proto.Message) bool {
		switch m.(type) {
		case *pganalyze.SelectStmt,
			*pganalyze.CallStmt,
			*pganalyze.DeleteStmt,
			*pganalyze.UpdateStmt,
			*pganalyze.MergeStmt,
			*pganalyze.InsertStmt:
			return true
		case *pganalyze.TargetEntry:
			return true
		default:
			return false
		}
	}
	var b strings.Builder
	writeString := func(m proto.Message) {
		if b.Len() != 0 {
			b.WriteByte(' ')
		}
		switch m := m.(type) {
		case *pganalyze.SelectStmt:
			b.WriteString("SELECT")
			for _, n := range m.FromClause {
				var strs []string
				for n := range findNodes(n, opsTables) {
					_ = n
					strs = append(strs, "TODO") // ???
				}
				switch len(strs) {
				case 0:
				case 1:
					b.WriteByte(' ')
					b.WriteString(strs[0])
				default:
					b.WriteString(" (")
					b.WriteString(strings.Join(strs, ", "))
					b.WriteByte(')')
				}
			}
		case *pganalyze.CallStmt:
			b.WriteString("CALL")
		case *pganalyze.DeleteStmt:
			b.WriteString("DELETE")
		case *pganalyze.UpdateStmt:
			b.WriteString("UPDATE")
		case *pganalyze.MergeStmt:
			b.WriteString("MERGE")
		case *pganalyze.InsertStmt:
			b.WriteString("INSERT")
		}
	}
	for _, stmt := range tree.Stmts {
		for n := range findNodes(stmt, ops) {
			writeString(n)
		}
	}
	if b.Len() == 0 {
		return unknown
	}
	return strconv.Quote(b.String())
}

const unknown = `"UNKNOWN"`

func findNodes(m proto.Message, pred func(proto.Message) bool) iter.Seq[proto.Message] {
	return func(yield func(proto.Message) bool) {
		walkProto(m, pred, yield)
	}
}

func walkProto(m proto.Message, pred func(proto.Message) bool, yield func(proto.Message) bool) bool {
	// All "false" returns should come from a "yield" returning false.
	if pred(m) && !yield(m) {
		return false
	}
	m.ProtoReflect().Range(func(d protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		k := d.Kind()
		switch k {
		case protoreflect.MessageKind, protoreflect.GroupKind:
		default:
			// Skip
			return true
		}
		switch {
		// Lists are repeated fields, meaning this field's kind is still
		// "message".
		case d.IsList():
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				m := l.Get(i).Message().Interface()
				if !walkProto(m, pred, yield) {
					return false
				}
			}
		// Maps are repeated "{key, value}" messages, which is the code passed
		// the "kind" check.
		// Only bother walking maps that have Messages for values.
		case d.IsMap() && d.MapValue().Kind() == protoreflect.MessageKind:
			var ok bool
			v.Map().Range(func(_ protoreflect.MapKey, v protoreflect.Value) bool {
				m := v.Message().Interface()
				ok = walkProto(m, pred, yield)
				return ok
			})
			if !ok {
				return false
			}
		// Normal Message.
		default:
			m := v.Message().Interface()
			return walkProto(m, pred, yield)
		}
		return true
	})
	return true
}

func predOps(m proto.Message) bool {
	switch m.(type) {
	case *pganalyze.SelectStmt,
		*pganalyze.CallStmt,
		*pganalyze.DeleteStmt,
		*pganalyze.UpdateStmt,
		*pganalyze.MergeStmt,
		*pganalyze.InsertStmt:
		return true
	default:
		return false
	}
}

func opName(m proto.Message) string {
	switch m.(type) {
	case *pganalyze.SelectStmt:
		return `"SELECT"`
	case *pganalyze.CallStmt:
		return `"CALL"`
	case *pganalyze.DeleteStmt:
		return `"DELETE"`
	case *pganalyze.UpdateStmt:
		return `"UPDATE"`
	case *pganalyze.MergeStmt:
		return `"MERGE"`
	case *pganalyze.InsertStmt:
		return `"INSERT"`
	default:
		return unknown
	}
}
