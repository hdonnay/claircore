// Embed is a helper to automatically write embed strings.
//
// This approach is taken instead of embedding an [io/fs.FS] implementation so
// that developers can get autocompletion on query names and avoid extra
// allocations on []byte to string conversions.
//
// With [unique] being available as of go1.23.0, the reverse-lookup overhead is
// also very small.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/template"

	pganalyze "github.com/pganalyze/pg_query_go/v5"
	pg_query "github.com/wasilibs/go-pgquery"
)

func main() {
	var code int
	defer func() {
		if code != 0 {
			os.Exit(code)
		}
	}()
	outfile := flag.String("o", `query_generated.go`, `output file ("-" to write to stdout)`)
	root := flag.String("root", `query`, `root directory of files to embed`)
	pat := flag.String("pat", `*.sql`, `file pattern`)
	flag.Parse()

	var out io.Writer
	if *outfile == "-" {
		out = os.Stdout
	} else {
		f, err := os.Create(*outfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(99)
		}
		defer f.Close()
		out = f
	}

	if err := Main(out, *root, *pat); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code = 1
	}
}

// Main walks from "root" for files matching the glob "pat" and writes generated
// go code to "out".
func Main(out io.Writer, root, pat string) error {
	var data []Embed
	sys := os.DirFS(root)
	err := fs.WalkDir(sys, ".", func(p string, ent fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		n := ent.Name()
		if ok, _ := path.Match(pat, n); !ok {
			return nil
		}
		ext := path.Ext(n)
		name := strings.TrimSuffix(strings.ReplaceAll(p, "/", ""), ext)

		b, err := fs.ReadFile(sys, p)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		res, err := pg_query.Parse(string(b))
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		ts, err := getTables(res)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		var table string
		if len(ts) != 0 {
			table = strconv.Quote(ts[0].Ident)
		}
		op, err := getOperation(res)
		if err != nil {
			log.Printf("%s: %v", p, err)
		}

		data = append(data, Embed{
			File:        path.Join(root, p),
			Name:        name,
			DisplayName: strconv.Quote(strings.TrimSuffix(n, ext)),
			Table:       table,
			Operation:   op,
		})
		return nil
	})
	if err != nil {
		return err
	}

	t, err := template.New("Root").Parse(tmpl)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return err
	}
	b, err := format.Source(buf.Bytes())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, bytes.NewReader(b)); err != nil {
		return err
	}
	return nil
}

// Embed describes a file to embed.
type Embed struct {
	File        string
	Name        string
	DisplayName string
	Table       string
	Operation   string
}

// GetTables returns the referenced tables in the query.
//
// The result is sorted such that names appear in order at every parse depth.
func getTables(res *pganalyze.ParseResult) ([]foundTable, error) {
	var out []foundTable
	for _, raw := range res.Stmts {
		if err := walkNode(&out, raw.Stmt, 0); err != nil {
			return nil, err
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Depth < out[j].Depth
	})
	return out, nil
}

func walkNode(out *[]foundTable, x any, d int) error {
	if x == nil {
		return nil
	}
	t := reflect.TypeOf(x)
	v := reflect.ValueOf(x)

	if t == reflect.TypeFor[pganalyze.RangeVar]() {
		var b strings.Builder
		if s := v.FieldByName("Schemaname").String(); s != "" {
			b.WriteString(s)
			b.WriteByte('.')
		}
		b.WriteString(v.FieldByName("Relname").String())

		*out = append(*out, foundTable{
			Ident: b.String(),
			Depth: d,
		})
		return nil
	}

	switch t.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			break
		}
		if err := walkNode(out, v.Elem().Interface(), d); err != nil {
			return err
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := walkNode(out, v.Index(i).Interface(), d+1); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			if !t.Field(i).IsExported() {
				continue
			}
			if err := walkNode(out, v.Field(i).Interface(), d+1); err != nil {
				return err
			}
		}
	default:
	}
	return nil
}

type foundTable struct {
	Ident string
	Depth int
}

func getOperation(res *pganalyze.ParseResult) (op string, err error) {
	stmt := res.Stmts[0]
	switch stmt.Stmt.Node.(type) {
	case *pganalyze.Node_SelectStmt:
		op = `"SELECT"`
	case *pganalyze.Node_DeleteStmt:
		op = `"DELETE"`
	case *pganalyze.Node_InsertStmt:
		op = `"INSERT"`
	case *pganalyze.Node_UpdateStmt:
		op = `"UPDATE"`
	case *pganalyze.Node_RefreshMatViewStmt:
		op = `"REFRESH MATERIALIZED VIEW"`
	case *pganalyze.Node_CallStmt:
		op = `"CALL"`
	default:
		return op, fmt.Errorf("unimplemented: %+v", stmt.Stmt.Node)
	}
	return op, nil
}

const tmpl = `{{ define "Var" }}
	//go:embed {{ .File }}
	{{ .Name }} string
{{- end -}}
{{ define "NameEntry" }}
	unique.Make({{ .Name }}): {{ .DisplayName }},
{{- end -}}
{{ define "TableEntry" }}{{ if .Table }}
	unique.Make({{ .Name }}): {{ .Table }},
{{- else }}
	// {{ .Name }}: no obvious table
{{- end }}{{ end -}}
{{ define "OpEntry" }}{{ if .Operation }}
	unique.Make({{ .Name }}): {{ .Operation }},
{{- else }}
	// {{ .Name }}: unknown operation
{{- end }}{{ end -}}
// Autogenerated by internal/cmd/embed. DO NOT EDIT.

package postgres

import (
	_ "embed"
	"unique"
)

var (
{{- range . }}{{ template "Var" . }}{{ end }}
)

// NameLookup maps interned SQL text back to a developer-meaningful name if the
// query is an embedded string.
var NameLookup = map[unique.Handle[string]]string {
{{- range . }}{{ template "NameEntry" . }}{{ end }}
}

// TableLookup maps interned SQL text back to the "main" table affected by the
// query.
var TableLookup = map[unique.Handle[string]]string {
{{- range . }}{{ template "TableEntry" . }}{{ end }}
}

// OpLookup maps interned SQL text back to the kind of operation it is.
var OpLookup = map[unique.Handle[string]]string {
{{- range . }}{{ template "OpEntry" . }}{{ end }}
}
`
