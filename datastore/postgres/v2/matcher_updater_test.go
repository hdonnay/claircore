package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/datastore/postgres/v2/internal/testutil"
	"github.com/quay/claircore/updater/driver/v2"
)

func (*matcherSuite) Updater(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	m := mkMatcher(ctx, t, pool)

	t.Run("Delta", func(t *testing.T) {
		start := time.Now()
		wantOps := []driver.UpdateOperation{}
		checkOps := func(ctx context.Context) func(*testing.T) {
			return func(t *testing.T) {
				t.Helper()
				seq, _ := m.GetUpdateOperations(ctx, "")
				got := slices.Collect(testutil.FilterErrs(t, seq))
				var b strings.Builder
				for _, op := range got {
					fmt.Fprintf(&b, "%s/%s@+%.4f: ", op.Updater, op.Ref, op.Date.Sub(start).Seconds())
					if op.Success {
						b.WriteString("OK:  ")
						b.WriteString(strconv.Quote(string(op.Fingerprint)))
					} else {
						b.WriteString("ERR: ")
						b.WriteString(op.Error.Error())
					}
					b.WriteByte('\n')
				}
				t.Logf("got:\n%s", b.String())
				if want := wantOps; !cmp.Equal(got, want, testutil.CmpOpts) {
					t.Fatal(cmp.Diff(got, want, testutil.CmpOpts))
				}
			}
		}
		resetOps := func(ctx context.Context) func(*testing.T) {
			return func(t *testing.T) {
				err := pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
					if _, err := c.Exec(ctx, `TRUNCATE matcher_v2.run RESTART IDENTITY CASCADE;`); err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
				wantOps = wantOps[:0]
				t.Log("resetting database")
			}
		}

		for tc := range tescasesFromGlob(m, "testdata/matcher/*.txtar") {
			tc.RunFixture(ctx, t, &wantOps)
			checkOps(ctx)(t)
		}

		t.Run("Multiple", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			resetOps(ctx)(t)
			for tc := range tescasesFromGlob(m, "testdata/matcher/multiple/*.txtar") {
				tc.RunFixture(ctx, t, &wantOps)
			}
			checkOps(ctx)(t)
		})
	})
}

func tescasesFromGlob(m *Matcher, glob string) iter.Seq[deltaMatcherTestcase] {
	ms, err := filepath.Glob(glob)
	if err != nil {
		panic(err)
	}
	return func(yield func(deltaMatcherTestcase) bool) {
		for _, name := range ms {
			tc := deltaMatcherTestcase{
				Matcher: m,
				Fixture: name,
			}
			if !yield(tc) {
				return
			}
		}
	}
}

type deltaMatcherTestcase struct {
	Matcher *Matcher

	// Optional, will be populated if not provided:
	Name        string
	UpdaterName string

	// Populate one of these:
	Fixture string

	// Populated during the testcase:
	RunRef      uuid.UUID
	DeltaRunRef uuid.UUID
}

var caser = sync.OnceValue(func() cases.Caser {
	return cases.Title(language.English)
})

func (tc *deltaMatcherTestcase) RunFixture(ctx context.Context, t *testing.T, wantOps *[]driver.UpdateOperation) {
	if tc.Fixture == "" {
		t.Fatalf("no fixture supplied in testcase definition")
	}
	if tc.Name == "" {
		tc.Name = caser().String(strings.TrimSuffix(path.Base(tc.Fixture), path.Ext(tc.Fixture)))
	}
	if tc.UpdaterName == "" {
		tc.UpdaterName = `test-updater-delta`
	}
	t.Run(tc.Name, func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		ar, err := txtar.ParseFile(tc.Fixture)
		if err != nil {
			t.Fatalf("unable to load fixture %q: %v", tc.Fixture, err)
		}
		tc.RunRef = testutil.MakeUUID(t)
		tc.DeltaRunRef = testutil.MakeUUID(t)
		hdr := testutil.LoadHeaders(t, ar)

		run := okAndCleanup[*Run](t)(tc.Matcher.UpdatersRun(ctx, tc.RunRef))
		defer func() {
			if err := run.Complete(ctx); err != nil {
				t.Errorf("unable to complete run: %v", err)
			}
		}()
		dr := okAndCleanup[*UpdaterDeltaRun](t)(run.NewDelta(ctx, tc.DeltaRunRef, tc.UpdaterName))

		fp := driver.Fingerprint(`{}`)
		if v := hdr.Get("fingerprint"); v != "" {
			fp = driver.Fingerprint(v)
		}
		var runErr error = nil
		if v := hdr.Get("error"); v != "" {
			runErr = errors.New(v)
		}
		if wantOps != nil {
			*wantOps = append(*wantOps, driver.UpdateOperation{
				Date:        time.Now(),
				Updater:     tc.UpdaterName,
				Ref:         tc.DeltaRunRef,
				Fingerprint: fp,
				Success:     runErr == nil,
				Error:       runErr,
			})
		}

		applyUpdaterRun(ctx, t, dr, ar)(fp, runErr)

		if hdr.Get("check-tables") == "" {
			return
		}

		// If we have the magic headers, check the specified parts.
		tables := strings.FieldsFunc(hdr.Get("check-tables"), splitItem)
		t.Logf("checking tables: %q", tables)
		for _, table := range tables {
			t.Run(table[strings.LastIndexByte(table, '.')+1:], func(t *testing.T) {
				tn := path.Base(t.Name())
				columns := strings.FieldsFunc(hdr.Get(tn+"-columns"), splitItem)
				t.Logf("table: %q", table)
				t.Logf("columns: %q", columns)

				name := strings.ToLower(path.Join("check", tn))
				var f *txtar.File
				for _, af := range ar.Files {
					if strings.ToLower(af.Name) == name {
						f = &af
						break
					}
				}
				if f == nil {
					t.Fatalf("no such file in txtar: %q", name)
				}

				var wantVals []any
				if err := json.Unmarshal(f.Data, &wantVals); err != nil {
					t.Fatalf("unable to construct json row source: %v", err)
				}

				nf := func(_ int) ([]any, error) { return nil, nil }
				if len(wantVals) != 0 {
					switch wantVals[0].(type) {
					case []any:
						nf = func(i int) ([]any, error) {
							return wantVals[i].([]any), nil
						}
					case map[string]any:
						nf = func(i int) ([]any, error) {
							m := wantVals[i].(map[string]any)
							v := make([]any, len(m))
							for i, n := range columns {
								v[i] = m[n]
							}
							return v, nil
						}
					default:
						t.Fatalf("unable to construct json row source: unknown type: %T", wantVals[0])
					}
				}
				src := pgx.CopyFromSlice(len(wantVals), nf)
				acqFunc := cmpTable(ctx, t, table, columns, src)
				if err := tc.Matcher.pool.AcquireFunc(ctx, acqFunc); err != nil {
					t.Error(err)
				}
			})
		}
	})
}

func applyUpdaterRun(ctx context.Context, t *testing.T, dr *UpdaterDeltaRun, ar *txtar.Archive) func(driver.Fingerprint, error) {
	var addTodo AddSeq
	var remTodo RemSeq
	for _, f := range ar.Files {
		switch strings.ToLower(f.Name) {
		case "add":
			addTodo = toAdvisories(testutil.LoadJSON[testAdvisory](t, bytes.NewReader(f.Data)))
		case "remove":
			remTodo = testutil.LoadJSON[driver.NamespacedAdvisory[driver.AdvisoryName]](t, bytes.NewReader(f.Data))
		}
	}
	runErr := errors.Join(dr.Add(ctx, addTodo), dr.Remove(ctx, remTodo))
	if runErr != nil {
		t.Errorf("unable to import advisories: %v", runErr)
	}

	return func(fp driver.Fingerprint, err error) {
		e := errors.Join(runErr, err)
		if err := dr.Finish(ctx, fp, e); err != nil {
			t.Errorf("unable to finish update run: %v", err)
		}
	}
}

// TestAdvisory is a wrapper that populates the iterators on a
// [driver.NamespacedAdvisory[driver.Advisory]] using slices in the incoming
// JSON.
type testAdvisory struct {
	driver.NamespacedAdvisory[driver.Advisory]
}

func (adv *testAdvisory) UnmarshalJSON(b []byte) error {
	var other struct {
		Refs     []driver.Reference
		Packages []driver.Package
		Attrs    []driver.Attr
	}
	err := errors.Join(
		json.Unmarshal(b, &adv.NamespacedAdvisory),
		json.Unmarshal(b, &other))
	if err != nil {
		return fmt.Errorf("unmarshaling advisories: %v", err)
	}
	adv.Advisory.Refs = dummyAdvisorySeq(other.Refs)
	adv.Advisory.Packages = dummyAdvisorySeq(other.Packages)
	adv.Advisory.Attrs = dummyAdvisorySeq(other.Attrs)
	return nil
}

// ToAdvisories maps [testAdvisory] to the underlying
// [driver.NamespacedAdvisory[driver.Advisory]].
func toAdvisories(seq iter.Seq2[testAdvisory, error]) iter.Seq2[driver.NamespacedAdvisory[driver.Advisory], error] {
	return func(yield func(driver.NamespacedAdvisory[driver.Advisory], error) bool) {
		for ta, err := range seq {
			if err != nil {
				yield(driver.NamespacedAdvisory[driver.Advisory]{}, err)
				return
			}
			if !yield(ta.NamespacedAdvisory, nil) {
				return
			}
		}
	}
}

// DummyAdvisorySeq adapts a slice of elements into the function signature
// expected for the functions on a [driver.Advisory].
func dummyAdvisorySeq[T any, S ~[]T](s S) func(context.Context) (iter.Seq2[T, error], error) {
	return func(context.Context) (iter.Seq2[T, error], error) {
		return testutil.ValuesErr(s), nil
	}
}

// SplitItem is for use with [strings.FieldsFunc].
// Reports if the rune is whitespace or ",".
func splitItem(r rune) bool { return r == ',' || unicode.IsSpace(r) }

// CmpTable returns a function for use with [pgxpool.AcquireFunc] that compares
// columns "columns" between the data in "table" and the data in "src".
func cmpTable(ctx context.Context, t *testing.T, table string, columns []string, src pgx.CopyFromSource) func(*pgxpool.Conn) error {
	srcTable := pgx.Identifier(strings.Split(table, "."))
	got := pgx.Identifier{"test_got"}
	want := pgx.Identifier{"test_want"}
	b := &strings.Builder{}

	return func(pc *pgxpool.Conn) error {
		// Track if "got" and "want" were populated, for error printing.
		var gotPop, wantPop bool
		// Pull the connection out of the pool and close it to make sure the
		// temporary table is cleaned up immediately.
		c := pc.Hijack()
		defer func() {
			if gotPop && t.Failed() {
				dumpTable(ctx, t, c, got)
			}
			if wantPop && t.Failed() {
				dumpTable(ctx, t, c, want)
			}
			if err := c.Close(ctx); err != nil {
				t.Errorf("closing connection: %v", err)
			}
		}()

		// Create the "got" and "want" tables.
		// The "got" table is populated here.
		if _, err := c.Exec(ctx, comparisonTables(b, srcTable, got, want, columns)); err != nil {
			return err
		}
		// Populate the "want" table.
		if _, err := c.CopyFrom(ctx, want, columns, src); err != nil {
			return err
		}

		// Compare the tables, returning JSON objects.
		rows, err := c.Query(ctx, comparisonQuery(b, got, want))
		if err != nil {
			return err
		}
		defer rows.Close()

		// Just print any mismatching rows:
		var out strings.Builder
		for rows.Next() {
			fmt.Fprintln(&out, string(rows.RawValues()[0]))
		}
		if out.Len() != 0 {
			t.Errorf("mismatched rows:\n%s", out.String())
		} else {
			t.Logf("OK")
		}
		if err := rows.Err(); err != nil {
			return err
		}

		return nil
	}
}

// DumpTable returns the contents of the table "name" as JSON objects.
func dumpTable(ctx context.Context, t *testing.T, c *pgx.Conn, name pgx.Identifier) {
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

// ComparisonTables returns SQL that creates two tables, "got" and "want", with
// columns "columns". These columns must exist in "src". The table named by
// "got" is populated from "src".
func comparisonTables(b *strings.Builder, src, got, want pgx.Identifier, columns []string) string {
	if b == nil {
		b = new(strings.Builder)
	}
	defer b.Reset()
	// "got" table:
	fmt.Fprintf(b, `CREATE TEMPORARY TABLE %s AS SELECT `, got.Sanitize())
	for i, col := range columns {
		if i != 0 {
			b.WriteString(`, `)
		}
		b.WriteString(pgx.Identifier(strings.Split(col, ".")).Sanitize())
	}
	fmt.Fprintf(b, " FROM %s;\n", src.Sanitize())
	// "want" table:
	fmt.Fprintf(b, "CREATE TEMPORARY TABLE %s (LIKE %s);", want.Sanitize(), got.Sanitize())
	return b.String()
}

// ComparisonQuery returns SQL that compares the tables "got" and "want",
// returning rows with one extra column named "cmp", which contains "+" if the
// row exists only in "got" or "-" if the row exists only in "want".
func comparisonQuery(b *strings.Builder, got, want pgx.Identifier) string {
	const except = "SELECT '%s' cmp, * FROM (SELECT * FROM %s EXCEPT ALL SELECT * FROM %s)"
	if b == nil {
		b = new(strings.Builder)
	}
	defer b.Reset()
	b.WriteString("SELECT row_to_json(res) FROM (")
	fmt.Fprintf(b, except, "+", got.Sanitize(), want.Sanitize())
	b.WriteString(" UNION ")
	fmt.Fprintf(b, except, "-", want.Sanitize(), got.Sanitize())
	b.WriteString(") res;")
	return b.String()
}
