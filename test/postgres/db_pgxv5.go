package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/log/testingadapter"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/pgx/v5/tracelog"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/test/integration"
)

// TestMatcherDBv5 returns a [pgxpool.Pool] connected to a started and configured
// for a Matcher database.
//
// If any errors are encountered, the test is failed and exited.
func TestMatcherDBv5(ctx context.Context, t testing.TB) *pgxpool.Config {
	return testDBv5(ctx, t, dbMatcher)
}

// TestIndexerDBv5 returns a [pgxpool.Pool] connected to a started and configured
// for a Indexer database.
//
// If any errors are encountered, the test is failed and exited.
func TestIndexerDBv5(ctx context.Context, t testing.TB) *pgxpool.Config {
	return testDBv5(ctx, t, dbIndexer)
}

// TestDBv5 returns a [pgxpool.Pool] connected to a started and configured
// database that has not had any migrations run.
//
// If any errors are encountered, the test is failed and exited.
func TestDBv5(ctx context.Context, t testing.TB) *pgxpool.Config {
	return testDBv5(ctx, t, dbNone)
}

func testDBv5(ctx context.Context, t testing.TB, which dbFlavor) *pgxpool.Config {
	t.Helper()
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	cfg := db.V5Config()
	cfg.ConnConfig.Tracer = &tracelog.TraceLog{
		Logger:   testingadapter.NewLogger(t),
		LogLevel: tracelog.LogLevelError,
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer pool.Close()
	checkVersion(ctx, t, pool)
	runMigrations(t, *cfg.ConnConfig, which)
	loadHelpers(ctx, t, pool, which)

	t.Cleanup(func() {
		db.Close(context.WithoutCancel(ctx), t)
	})
	return cfg
}

func runMigrations(t testing.TB, cfg pgx.ConnConfig, which dbFlavor) {
	mdb := stdlib.OpenDB(cfg)
	defer mdb.Close()
	migrator := migrate.NewPostgresMigrator(mdb)

	var err error
	switch which {
	case dbMatcher:
		migrator.Table = migrations.MatcherMigrationTable
		err = migrator.Exec(migrate.Up, migrations.MatcherMigrations...)
	case dbIndexer:
		migrator.Table = migrations.IndexerMigrationTable
		err = migrator.Exec(migrate.Up, migrations.IndexerMigrations...)
	case dbNone:
	default:
		err = fmt.Errorf("unknown flavor: %v", which)
	}
	if err != nil {
		t.Fatalf("failed to perform migrations: %v", err)
	}
}
