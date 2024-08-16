package postgres

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/log/testingadapter"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4/stdlib"
	"github.com/remind101/migrate"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/test/integration"
)

// TestMatcherDB returns a [pgxpool.Pool] connected to a started and configured
// for a Matcher database.
//
// If any errors are encountered, the test is failed and exited.
func TestMatcherDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDBv4(ctx, t, dbMatcher)
}

// TestIndexerDB returns a [pgxpool.Pool] connected to a started and configured
// for a Indexer database.
//
// If any errors are encountered, the test is failed and exited.
func TestIndexerDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDBv4(ctx, t, dbIndexer)
}

// TestDB returns a [pgxpool.Pool] connected to a started and configured
// database that has not had any migrations run.
//
// If any errors are encountered, the test is failed and exited.
func TestDB(ctx context.Context, t testing.TB) *pgxpool.Pool {
	return testDBv4(ctx, t, dbNone)
}

func testDBv4(ctx context.Context, t testing.TB, which dbFlavor) *pgxpool.Pool {
	t.Helper()
	db, err := integration.NewDB(ctx, t)
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	cfg := db.Config()
	cfg.ConnConfig.LogLevel = pgx.LogLevelError
	cfg.ConnConfig.Logger = testingadapter.NewLogger(t)
	pool, err := pgxpool.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	checkVersion(ctx, t, pool)

	mdb := stdlib.OpenDB(*cfg.ConnConfig)
	defer mdb.Close()
	// run migrations
	migrator := migrate.NewPostgresMigrator(mdb)
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
	loadHelpers(ctx, t, pool, which)

	// BUG(hank) The Test*DB functions close over the passed-in Context and use
	// it for the Cleanup method. Because Cleanup functions are earlier in the
	// stack than any defers inside the test, make sure the Context isn't one
	// that's deferred to be canceled.
	t.Cleanup(func() {
		pool.Close()
		db.Close(ctx, t)
	})
	return pool
}
