package postgres

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"testing"

	v4pool "github.com/jackc/pgx/v4/pgxpool"
	v5pool "github.com/jackc/pgx/v5/pgxpool"
)

// MinVersion is minimum needed PostgreSQL version, in the integer format.
const MinVersion uint64 = 150000

type dbFlavor uint

const (
	dbNone dbFlavor = iota
	dbMatcher
	dbIndexer
)

// TODO(hank) refactor all these helpers to just work on a single connection.

type (
	poolv4Func[R any] func(context.Context, testing.TB, *v4pool.Pool) R
	poolv5Func[R any] func(context.Context, testing.TB, *v5pool.Pool) R
)

// PoolVerisonSwitch is a bad (only) way to do a sum type.
func poolVersionSwitch[p anyPool, R any](ctx context.Context, t testing.TB, pool p, v4 poolv4Func[R], v5 poolv5Func[R]) R {
	t.Helper()
	switch p := any(pool).(type) {
	case *v4pool.Pool:
		return v4(ctx, t, p)
	case *v5pool.Pool:
		return v5(ctx, t, p)
	default:
		t.Fatalf("unexpected type passed in: %T", pool)
	}
	panic("unreachable")
}

type anyPool interface {
	*v4pool.Pool | *v5pool.Pool
}

func checkVersion[p anyPool](ctx context.Context, t testing.TB, pool p) {
	t.Helper()
	var vs string

	const query = `SELECT current_setting('server_version_num');`
	err := poolVersionSwitch(ctx, t, pool,
		func(ctx context.Context, t testing.TB, pool *v4pool.Pool) error {
			return pool.QueryRow(ctx, `SELECT current_setting('server_version_num');`).Scan(&vs)
		},
		func(ctx context.Context, t testing.TB, pool *v5pool.Pool) error {
			return pool.QueryRow(ctx, `SELECT current_setting('server_version_num');`).Scan(&vs)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	v, err := strconv.ParseUint(vs, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if v < MinVersion {
		t.Fatalf("PostgreSQL version too old: %d < %d", v, MinVersion)
	}
	t.Logf("PostgreSQL version: %d", v)
}

//go:embed sql
var extraSQL embed.FS

// LoadHelpers loads extra SQL from both the "sql" directory in this package and
// the test package's "testdata" directory.
//
// The "flavor" argument selects which prefix is added onto the file glob.
func loadHelpers[p anyPool](ctx context.Context, t testing.TB, pool p, flavor dbFlavor) {
	t.Helper()
	logprefix := [...]string{"global", "local"}
	var look []fs.FS
	if sys, err := fs.Sub(extraSQL, "sql"); err != nil {
		t.Fatalf("unexpected error from embed.FS: %v", err)
	} else {
		look = append(look, sys)
	}
	// NB This is relative to the test being run, _not_ this file. Because this
	// is a helper library, this is different than you may expect.
	if sys, err := fs.Sub(os.DirFS("."), "testdata"); err != nil {
		t.Log("no testdata directory, skipping local loading")
	} else {
		look = append(look, sys)
	}

	var exec func(context.Context, testing.TB, []byte)
	var done func()
	err := poolVersionSwitch(ctx, t, pool,
		func(ctx context.Context, t testing.TB, pool *v4pool.Pool) error {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			done = conn.Release
			exec = func(ctx context.Context, t testing.TB, b []byte) {
				if _, err := conn.Exec(ctx, string(b)); err != nil {
					t.Error(err)
				}
			}
			return nil
		},
		func(ctx context.Context, t testing.TB, pool *v5pool.Pool) error {
			conn, err := pool.Acquire(ctx)
			if err != nil {
				return err
			}
			done = conn.Release
			exec = func(ctx context.Context, t testing.TB, b []byte) {
				if _, err := conn.Exec(ctx, string(b)); err != nil {
					t.Error(err)
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("unable to acquire connection: %v", err)
	}
	defer done()
	glob := []string{"all_*.psql"}
	switch flavor {
	case dbMatcher:
		glob = append(glob, "matcher_*.psql")
	case dbIndexer:
		glob = append(glob, "indexer_*.psql")
	}
	for i, sys := range look {
		for _, g := range glob {
			ms, err := fs.Glob(sys, g)
			if err != nil {
				panic(fmt.Sprintf("programmer error: %v", err))
			}
			for _, f := range ms {
				b, err := fs.ReadFile(sys, f)
				if err != nil {
					t.Error(err)
					continue
				}
				t.Logf("loading %s %q", logprefix[i], path.Base(f))
				exec(ctx, t, b)
			}
		}
	}
}
