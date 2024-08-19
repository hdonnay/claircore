package postgres

import (
	"bufio"
	"context"
	"encoding/json"
	"iter"
	"os"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test"
	"github.com/quay/claircore/updater/driver/v2"
)

func (*matcherSuite) Updater(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	const (
		deltaUpdater = `test-updater-delta`
	)
	var (
		runRef   = uuid.MustParse(`0e9f9c9f-c11a-486f-9d11-99c7de4d62b5`)
		deltaRef = uuid.MustParse(`806e02ea-758f-4aa7-a177-c8b3ff391ffc`)
	)

	addAdvisories := func(t *testing.T, adv *driver.NamespacedAdvisory[driver.Advisory], b []byte) {
		var other struct {
			Refs     []driver.Reference
			Packages []driver.Package
			Attrs    []driver.Attr
		}
		if err := json.Unmarshal(b, &other); err != nil {
			t.Errorf("unmarshaling advisories: %v", err)
		}
		adv.Advisory.Refs = dummyAdvisorySeq(other.Refs)
		adv.Advisory.Packages = dummyAdvisorySeq(other.Packages)
		adv.Advisory.Attrs = dummyAdvisorySeq(other.Attrs)
	}

	m := mkMatcher(ctx, t, pool)

	t.Run("Delta", func(t *testing.T) {
		t.Run("Run", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			run := okAndCleanup[*Run](t)(m.UpdatersRun(ctx, runRef))
			defer func() {
				if err := run.Complete(ctx); err != nil {
					t.Errorf("unable to complete run: %v", err)
				}
			}()
			dr := okAndCleanup[*UpdaterDeltaRun](t)(run.NewDelta(ctx, deltaRef, deltaUpdater))

			addTodo := loadJSONSeq(t, "testdata/matcher/delta.jsonseq", addAdvisories)
			if err := dr.Add(ctx, addTodo); err != nil {
				t.Errorf("unable to import advisories: %v", err)
			}
			remTodo := loadJSONSeq[driver.NamespacedAdvisory[driver.AdvisoryName]](t, "testdata/matcher/remove.jsonseq", nil)
			if err := dr.Remove(ctx, remTodo); err != nil {
				t.Errorf("unable to import advisories: %v", err)
			}

			if err := dr.Finish(ctx, driver.Fingerprint(`{}`)); err != nil {
				t.Errorf("unable to finish update run: %v", err)
			}
		})
		skip := t.Failed()

		t.Run("Check", func(t *testing.T) {
			if skip {
				t.Skip("previous test failed")
			}
			ctx := zlog.Test(ctx, t)

			seq, _ := m.GetUpdateOperations(ctx, "")
			got := slices.Collect(catchErrs(t, seq))
			t.Logf("got:\n%#v", got)
		})
	})
}

func catchErrs[E any](t testing.TB, seq iter.Seq2[E, error]) iter.Seq[E] {
	t.Helper()
	return func(yield func(E) bool) {
		t.Helper()
		i := -1
		for v, err := range seq {
			i++
			if err != nil {
				t.Errorf("%d'th element: %v", i, err)
				continue
			}
			if !yield(v) {
				return
			}
		}
	}
}

func loadJSONSeq[T any](t *testing.T, filename string, mod func(*testing.T, *T, []byte)) iter.Seq2[T, error] {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("opening json-seq file: %v", err)
	}
	s := bufio.NewScanner(f)
	s.Split(test.SplitJSONSeq)

	return func(yield func(T, error) bool) {
		defer func() {
			if err := s.Err(); err != nil {
				var zero T
				yield(zero, err)
			}
			if err := f.Close(); err != nil {
				t.Errorf("closing json-seq file: %v", err)
			}
		}()
		for s.Scan() {
			var ret T
			err := json.Unmarshal(s.Bytes(), &ret)
			if mod != nil {
				mod(t, &ret, s.Bytes())
			}
			if !yield(ret, err) {
				return
			}
		}
	}
}

func dummyAdvisorySeq[T any, S ~[]T](s S) func(context.Context) (iter.Seq2[T, error], error) {
	seq := func(yield func(T, error) bool) {
		for _, t := range s {
			if !yield(t, nil) {
				return
			}
		}
	}
	return func(context.Context) (iter.Seq2[T, error], error) {
		return seq, nil
	}
}
