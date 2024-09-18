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

// Updater runs the updater-related tests.
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

func tescasesFromGlob(m *Matcher, glob string) iter.Seq[DeltaUpdaterTestcase] {
	ms, err := filepath.Glob(glob)
	if err != nil {
		panic(err)
	}
	return func(yield func(DeltaUpdaterTestcase) bool) {
		for _, name := range ms {
			tc := DeltaUpdaterTestcase{
				Matcher: m,
				Fixture: name,
			}
			if !yield(tc) {
				return
			}
		}
	}
}

// DeltaUpdaterTestcase describes a subtest for the Delta Updater subsystem.
type DeltaUpdaterTestcase struct {
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

// Caser returns a lazily constructed [cases.Caser].
var caser = sync.OnceValue(func() cases.Caser {
	return cases.Title(language.English)
})

// RunFixture runs a subtest created from the fixture specified in the
// [deltaMatcherTestcase].
func (tc *DeltaUpdaterTestcase) RunFixture(ctx context.Context, t *testing.T, wantOps *[]driver.UpdateOperation) {
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
		var runErr error
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
			// Nothing to check; done.
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
				wantSource := pgx.CopyFromSlice(len(wantVals), nf)
				gotSource := pgx.Identifier(strings.Split(table, "."))
				acqFunc := testutil.CompareTable(ctx, t, gotSource, columns, wantSource)
				if err := tc.Matcher.pool.AcquireFunc(ctx, acqFunc); err != nil {
					t.Error(err)
				}
			})
		}
	})
}

// ApplyUpdaterRun loads an [UpdaterDeltaRun] as described in the provided
// [txtar.Archive] and returns a function to apply it to the provided
// [UpdaterDeltaRun].
//
// The returned function must be called to finish the UpdaterDeltaRun.
// See also [testutil.LoadJSON].
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

// ToAdvisories maps the sequence of [testAdvisory] to the underlying
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
