package postgres

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/updater/driver/v2"
)

func TestMatcher(t *testing.T) {
	t.Parallel()
	RunSuite(t, "matcher", new(matcherSuite))
}

type matcherSuite struct{}

// Initialized checks that [Matcher.Initialized] behaves as expected.
func (*matcherSuite) Initialized(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	inner := func(ctx context.Context, t *testing.T, m *Matcher, strict bool, create string) {
		const teardown = `DELETE FROM matcher_v2.run WHERE ref = $1::UUID;`

		n := 0
		call := func(want bool) {
			n++
			initd, err := m.Initialized(ctx, strict)
			if err != nil {
				t.Errorf("Initialized call #%d: %v", n, err)
			} else {
				t.Logf("Initialized call #%d: %v", n, initd)
			}
			if initd != want {
				t.Errorf(`expected %v`, want)
			}
			if t.Failed() {
				t.FailNow()
			}
		}
		runid := uuid.New()

		call(false)
		if _, err := pool.Exec(ctx, create, runid); err != nil {
			t.Fatal(err)
		}
		t.Logf("created run: %v", runid)
		defer func() {
			if _, err := pool.Exec(ctx, teardown, runid); err != nil {
				t.Error(err)
			}
		}()
		call(true)
	}
	m := mkMatcher(ctx, t, pool)

	t.Run("Lax", func(t *testing.T) {
		const create = `INSERT INTO matcher_v2.run (ref, complete) VALUES ($1, TRUE);`
		t.Helper()
		inner(zlog.Test(ctx, t), t, m, false, create)
	})
	// t.Run("Strict", func(t *testing.T) {
	// 	const create = `INSERT INTO matcher_v2.run (ref, complete) VALUES ($1, TRUE);`
	// 	t.Helper()
	// 	inner(zlog.Test(ctx, t), t, m, true, create)
	// })
}

// GetUpdateOperations tests [Matcher.GetUpdateOperations].
//
// The test creates some bogus updates (and defers their removal), reads them
// back, then partially reads and restarts the sequence and compares the
// results.
func (*matcherSuite) GetUpdateOperations(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	m := mkMatcher(ctx, t, pool)
	const (
		setup    = `CALL create_updates(10);`
		teardown = `TRUNCATE matcher_v2.updater_run, matcher_v2.updater, matcher_v2.run RESTART IDENTITY CASCADE;`
	)

	if _, err := pool.Exec(ctx, setup); err != nil {
		t.Fatalf("unable to create test data: %v", err)
	}
	defer func() {
		if _, err := pool.Exec(ctx, teardown); err != nil {
			t.Errorf("error cleaning up: %v", err)
		}
	}()
	countTable(ctx, t, pool, `matcher_v2`, `updater`, `run`, `updater_run`)

	seq, _ := m.GetUpdateOperations(ctx, "")
	var want []driver.UpdateOperation
	for op, err := range seq {
		if err != nil {
			t.Error(err)
			continue
		}
		t.Logf("op: %v", op.Ref)
		want = append(want, op)
	}
	if t.Failed() {
		return
	}
	if len(want) == 0 {
		t.Fatal("no update operations populated")
	}

	half := len(want) / 2

	var got []driver.UpdateOperation
	var tok string
	i := 0
	seq, gettok := m.GetUpdateOperations(ctx, "")
	for op, err := range seq {
		if err != nil {
			t.Error(err)
			break
		}
		got = append(got, op)
		i++
		if i == half {
			tok = gettok()
			break
		}
	}

	seq, _ = m.GetUpdateOperations(ctx, tok)
	for op, err := range seq {
		if err != nil {
			t.Error(err)
			break
		}
		got = append(got, op)
	}

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
