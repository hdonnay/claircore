package testutil

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Must fails the test if passed an error.
func Must[T any](t testing.TB) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

// CountTables is a helper that logs the row count of the named tables.
func CountTables(ctx context.Context, t testing.TB, pool *pgxpool.Pool, tables ...pgx.Identifier) {
	var ct int64
	for _, n := range tables {
		q := fmt.Sprintf(`SELECT COUNT(*) FROM %s;`, n.Sanitize())
		if err := pool.QueryRow(ctx, q).Scan(&ct); err != nil {
			t.Error(err)
		}
		t.Logf("found %d rows in %s", ct, n.Sanitize())
	}
}

var prettySQL = regexp.MustCompile(`[\n\t]+`)

// PrintQueries hooks the passed [pgxpool.Config] to print all queries to "t" if
// [testing.Verbose] reports "true". Existing tracing hooks are preserved.
func PrintQueries(t testing.TB, cfg *pgxpool.Config) {
	tr := queryPrinter{
		QueryTracer: cfg.ConnConfig.Tracer,
	}
	if testing.Verbose() {
		tr.TB = t
	}
	cfg.ConnConfig.Tracer = &tr
}

var _ pgx.QueryTracer = (*queryPrinter)(nil)

// QueryPrinter is the [pgx.QueryTracer] that backs [PrintQueries].
type queryPrinter struct {
	testing.TB
	pgx.QueryTracer
}

// TraceQueryStart implements [pgx.QueryTracer].
func (p *queryPrinter) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if p.TB != nil {
		p.Logf("query:\nSQL: %s\nargs:%v",
			prettySQL.ReplaceAllLiteralString(data.SQL, " "),
			data.Args,
		)
	}
	if p.QueryTracer != nil {
		return p.QueryTracer.TraceQueryStart(ctx, conn, data)
	}
	return ctx
}

// TraceQueryEnd implements [pgx.QueryTracer].
func (p *queryPrinter) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if p.QueryTracer != nil {
		p.QueryTracer.TraceQueryEnd(ctx, conn, data)
	}
}

// DumpTable returns the contents of the table "name" as JSON objects.
func DumpTable(ctx context.Context, t testing.TB, c *pgx.Conn, name pgx.Identifier) {
	const dump = `SELECT row_to_json(res) FROM %s res;`
	var out strings.Builder
	rows, err := c.Query(ctx, fmt.Sprintf(dump, name.Sanitize()))
	if err != nil {
		t.Error(err)
		return
	}
	rs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (string, error) {
		return string(slices.Clone(row.RawValues()[0])), nil
	})
	if err != nil {
		t.Error(err)
		return
	}
	for _, r := range rs {
		fmt.Fprintln(&out, r)
	}
	t.Logf("table %s:\n%s", name.Sanitize(), out.String())
}

// CompareTable returns a function for use with [pgxpool.AcquireFunc] that compares
// named columns between the data in the table "got" and the data in "want".
//
// # Why does this use CopyFromSource?
//
// A [pgx.CopyFromSource] is used to be able to get data into the database
// completely independently of the code under test. If both the code under test
// and the code loading the fixture relied on the same encoding functions (for
// example), then an error in common code could obscure problems in the code
// under test.
func CompareTable(ctx context.Context, t *testing.T, gotSource pgx.Identifier, columns []string, wantSource pgx.CopyFromSource) func(*pgxpool.Conn) error {
	got := pgx.Identifier{"test_got"}
	want := pgx.Identifier{"test_want"}
	b := new(strings.Builder)

	return func(pc *pgxpool.Conn) error {
		// Track if "got" and "want" were populated, for error printing.
		var gotPop, wantPop bool
		// Pull the connection out of the pool and close it to make sure the
		// temporary table is cleaned up immediately.
		c := pc.Hijack()
		defer func() {
			if gotPop && t.Failed() {
				DumpTable(ctx, t, c, got)
			}
			if wantPop && t.Failed() {
				DumpTable(ctx, t, c, want)
			}
			if err := c.Close(ctx); err != nil {
				t.Errorf("closing connection: %v", err)
			}
		}()

		// Create the "got" and "want" tables.
		// The "got" table is populated here.
		if _, err := c.Exec(ctx, comparisonTables(b, gotSource, got, want, columns)); err != nil {
			return err
		}
		gotPop = true
		// Populate the "want" table.
		if _, err := c.CopyFrom(ctx, want, columns, wantSource); err != nil {
			return err
		}
		wantPop = true

		// Compare the tables, returning JSON objects.
		rows, err := c.Query(ctx, comparisonQuery(b, got, want))
		if err != nil {
			return err
		}
		defer rows.Close()

		// Just print any mismatching rows:
		for rows.Next() {
			fmt.Fprintln(b, string(rows.RawValues()[0]))
		}
		if b.Len() != 0 {
			t.Errorf("mismatched rows:\n%s", b.String())
		} else {
			t.Logf("OK")
		}
		if err := rows.Err(); err != nil {
			return err
		}

		return nil
	}
}

// ComparisonTables returns SQL that creates two tables, "got" and "want", with
// columns "columns". These columns must exist in "gotSource". The table named by
// "got" is populated from "gotSource".
func comparisonTables(b *strings.Builder, gotSource, got, want pgx.Identifier, columns []string) string {
	defer b.Reset()
	// "got" table:
	fmt.Fprintf(b, `CREATE TEMPORARY TABLE %s AS SELECT `, got.Sanitize())
	for i, col := range columns {
		if i != 0 {
			b.WriteString(`, `)
		}
		b.WriteString(pgx.Identifier(strings.Split(col, ".")).Sanitize())
	}
	fmt.Fprintf(b, " FROM %s;\n", gotSource.Sanitize())
	// "want" table:
	fmt.Fprintf(b, "CREATE TEMPORARY TABLE %s (LIKE %s);", want.Sanitize(), got.Sanitize())
	return b.String()
}

// ComparisonQuery returns SQL that compares the tables "got" and "want",
// returning rows with one extra column named "cmp", which contains "+" if the
// row exists only in "got" or "-" if the row exists only in "want".
func comparisonQuery(b *strings.Builder, got, want pgx.Identifier) string {
	const except = "SELECT '%s' cmp, * FROM (SELECT * FROM %s EXCEPT ALL SELECT * FROM %s)"
	defer b.Reset()
	b.WriteString("SELECT row_to_json(res) FROM (")
	fmt.Fprintf(b, except, "+", got.Sanitize(), want.Sanitize())
	b.WriteString(" UNION ")
	fmt.Fprintf(b, except, "-", want.Sanitize(), got.Sanitize())
	b.WriteString(") res;")
	return b.String()
}
