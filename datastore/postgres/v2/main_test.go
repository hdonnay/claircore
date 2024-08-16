package postgres

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestMain(m *testing.M) {
	var c int
	defer func() { os.Exit(c) }()
	defer integration.DBSetup()()
	c = m.Run()
}

// RunSuite runs a test suite.
//
// Subtests are created for all exported methods matching [Subtest] or [IsolatedSubtest].
func RunSuite(t *testing.T, which string, suite any) {
	t.Helper()
	integration.NeedDB(t)
	ctx := zlog.Test(context.Background(), t)

	mkCfg := func(t *testing.T) (cfg *pgxpool.Config) {
		switch which {
		case "matcher":
			cfg = pgtest.TestMatcherDBv5(ctx, t)
		default:
			t.Fatalf("unknown database: %q", which)
		}
		cfg = Configure(ctx, cfg)
		t.Log("created shared database")
		return cfg
	}
	shared := sync.OnceValue(func() *pgxpool.Pool {
		pool, err := pgxpool.NewWithConfig(ctx, mkCfg(t))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pool.Close)
		return pool
	})

	v := reflect.ValueOf(suite)
	typ := reflect.TypeOf(suite)
	for i := 0; i < v.NumMethod(); i++ {
		typ := typ.Method(i)
		if !typ.IsExported() {
			continue
		}
		f := v.Method(i)
		switch f := f.Interface().(type) {
		case IsolatedSubtest:
			t.Run(typ.Name, func(t *testing.T) {
				t.Helper()
				t.Parallel()
				ctx, done := context.WithCancel(zlog.Test(ctx, t))
				defer done()
				f(ctx, t, mkCfg(t))
			})
		case Subtest:
			t.Run(typ.Name, func(t *testing.T) {
				t.Helper()
				ctx, done := context.WithCancel(zlog.Test(ctx, t))
				defer done()
				f(ctx, t, shared())
			})
		default:
			t.Logf("skipping method %q: unknown signature: %T", typ.Name, f)
		}
	}
}

// Subtest is a test using a database shared across tests.
type Subtest = func(context.Context, *testing.T, *pgxpool.Pool)

// IsolatedSubtest is a test using a database that's created for it and torn
// down afterwards.
type IsolatedSubtest = func(context.Context, *testing.T, *pgxpool.Config)

// Some misc helper functions:

func mkMatcher(ctx context.Context, t *testing.T, pool *pgxpool.Pool) *Matcher {
	t.Helper()
	m, err := NewMatcherV2(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func countTable(ctx context.Context, t *testing.T, pool *pgxpool.Pool, schema string, ts ...string) {
	var ct int64
	for _, i := range ts {
		n := pgx.Identifier{schema, i}
		q := fmt.Sprintf(`SELECT COUNT(*) FROM %s;`, n.Sanitize())
		if err := pool.QueryRow(ctx, q).Scan(&ct); err != nil {
			t.Error(err)
		}
		t.Logf("found %d rows in %q", ct, n[1])
	}
}

func testingHooks(t *testing.T, cfg *pgxpool.Config) {
	pretty, err := regexp.Compile(`[\n\t]+`)
	if err != nil {
		t.Fatal(err)
	}
	tr := queryPrinter{
		QueryTracer: cfg.ConnConfig.Tracer,
		pretty:      pretty,
	}
	cfg.ConnConfig.Tracer = &tr
}

type queryPrinter struct {
	pgx.QueryTracer
	pretty *regexp.Regexp
}

func (p *queryPrinter) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	zlog.Debug(ctx).
		Str("query", p.pretty.ReplaceAllLiteralString(data.SQL, " ")).
		Interface("args[1:]", data.Args[1:]).
		Msg("database call")
	return p.QueryTracer.TraceQueryStart(ctx, conn, data)
}
