package postgres

import (
	"context"
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"golang.org/x/tools/txtar"

	"github.com/quay/claircore/datastore/postgres/v2/internal/testutil"
	"github.com/quay/claircore/updater/driver/v2"
)

func TestMatcher(t *testing.T) {
	t.Parallel()
	RunSuite(t, "matcher", new(matcherSuite))
}

// MatcherSuite exists to hang methods off of.
//
// This is done to allow proper grouping while enabling reasonably-sized test
// files.
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
	t.Run("Strict", func(t *testing.T) {
		t.Skip("TODO")
		/*
			const create = `INSERT INTO matcher_v2.run (ref, complete) VALUES ($1, TRUE);`
			t.Helper()
			inner(zlog.Test(ctx, t), t, m, true, create)
		*/
	})
}

func (*matcherSuite) CollectGarbage(ctx context.Context, t *testing.T, pool *pgxpool.Pool) {
	openArchive := func(t testing.TB) *txtar.Archive {
		t.Helper()
		arFile := filepath.Join(`testdata/matcher/gc`, strings.ToLower(path.Base(t.Name()))+".txtar")
		t.Logf("opening archive: %q", arFile)
		ar, err := txtar.ParseFile(arFile)
		if err != nil {
			t.Fatalf("opening archive: %v", err)
		}
		return ar
	}

	t.Run("Empty", func(t *testing.T) {
		ctx := zlog.Test(ctx, t)
		m := mkMatcher(ctx, t, pool)
		if err := m.CollectGarbage(ctx); err != nil {
			t.Error(err)
		}
	})
	t.Run("Synthetic", func(t *testing.T) {
		t.Run("Dangling", func(t *testing.T) {
			countTable := func(t *testing.T, table string, want int) func(*pgxpool.Conn) error {
				q := fmt.Sprintf(`SELECT COUNT(id) FROM "matcher_v2".%q;`, table)
				return func(c *pgxpool.Conn) error {
					t.Helper()
					var got int
					err := c.QueryRow(ctx, q).
						Scan(&got)
					if err != nil {
						return err
					}
					t.Logf("%s count: %d", table, got)
					if got != want {
						t.Errorf("bad count: got: %d, want: %d", got, want)
					}
					return nil
				}
			}

			runOne := func(ctx context.Context, t *testing.T, ct int, name string, init func(*pgxpool.Conn) error) {
				t.Helper()
				ctx = zlog.Test(ctx, t)
				m := mkMatcher(ctx, t, pool)
				if err := pool.AcquireFunc(ctx, init); err != nil {
					t.Fatal(err)
				}
				if err := pool.AcquireFunc(ctx, countTable(t, name, ct)); err != nil {
					t.Fatal(err)
				}
				if err := m.CollectGarbage(ctx); err != nil {
					t.Error(err)
				}
				if err := pool.AcquireFunc(ctx, countTable(t, name, 0)); err != nil {
					t.Fatal(err)
				}
			}

			t.Run("Names", func(t *testing.T) {
				ct := 10
				runOne(ctx, t, ct, `package_name`, func(c *pgxpool.Conn) error {
					names := make([]string, ct)
					for i := range names {
						names[i] = fmt.Sprintf("test%02d", i)
					}

					_, err := c.Exec(ctx,
						`INSERT INTO matcher_v2.package_name (name) SELECT UNNEST($1::TEXT[]);`,
						names)
					return err
				})
			})
			t.Run("Refs", func(t *testing.T) {
				ct := 10
				runOne(ctx, t, ct, `reference`, func(c *pgxpool.Conn) error {
					names := make([]string, ct)
					for i := range names {
						names[i] = fmt.Sprintf("%04d", i)
					}

					_, err := c.Exec(ctx,
						`INSERT INTO matcher_v2.reference (namespace, name) SELECT 'TEST', UNNEST($1::TEXT[]);`,
						names)
					return err
				})
			})
			t.Run("Attrs", func(t *testing.T) {
				ct := 1
				runOne(ctx, t, ct, `attr`, func(c *pgxpool.Conn) error {
					txOptions := pgx.TxOptions{
						IsoLevel:       pgx.RepeatableRead,
						AccessMode:     pgx.ReadWrite,
						DeferrableMode: pgx.Deferrable,
					}
					tx, err := c.BeginTx(ctx, txOptions)
					if err != nil {
						return err
					}
					defer func() {
						err := tx.Rollback(ctx)
						switch {
						case errors.Is(err, nil):
						case errors.Is(err, pgx.ErrTxClosed): // OK
						default:
							t.Error(err)
						}
					}()
					var typeID int64
					err = tx.QueryRow(ctx,
						`INSERT INTO matcher_v2.mediatype (mediatype) VALUES ('application/vnd.claircore.test') RETURNING id;`).
						Scan(&typeID)
					if err != nil {
						return err
					}

					_, err = tx.Exec(ctx,
						`INSERT INTO matcher_v2.attr (mediatype, data) VALUES ($1, $2::JSONB);`,
						typeID, `{"some_json": "goes here"}`)
					if err != nil {
						return err
					}
					return tx.Commit(ctx)
				})
				if err := pool.AcquireFunc(ctx, countTable(t, `mediatype`, 0)); err != nil {
					t.Fatal(err)
				}
			})
		})
	})

	t.Run("Simple", func(t *testing.T) {
		openArchive(t)
		// - create some Updates
		// - age them out
		// - make sure they're deleted.
		t.Skip("TODO")
	})

	t.Run("Complex", func(t *testing.T) {
		openArchive(t)
		// - create some Updates
		// - age out some portion of the underlying objects
		// - make sure they're deleted.
		t.Skip("TODO")
	})
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
	testutil.CountTables(ctx, t, pool,
		pgx.Identifier{`matcher_v2`, `updater`},
		pgx.Identifier{`matcher_v2`, `run`},
		pgx.Identifier{`matcher_v2`, `updater_run`},
	)

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
