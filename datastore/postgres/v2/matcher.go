package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/updater/driver/v2"
)

type Matcher struct {
	pool *pgxpool.Pool

	queries map[string]struct{}
	workMem int
}

const minMatcherMigration = 13

func NewMatcherV2(ctx context.Context, matcher *pgxpool.Pool) (*Matcher, error) {
	var workMem int
	err := matcher.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		var version int
		q := fmt.Sprintf(`SELECT MAX(version) FROM %s;`, pgx.Identifier{migrations.MatcherMigrationTable})
		if err := conn.QueryRow(ctx, q).Scan(&version); err != nil {
			return fmt.Errorf("postgres: unable to determine version: %w", err)
		}
		if got, want := version, minMatcherMigration; got < want {
			return fmt.Errorf("postgres: matcher database version too low: %d < %d (do you need to run migrations?)", got, want)
		}
		const selectWorkMem = `SELECT setting FROM pg_settings WHERE name = 'work_mem';`
		if err := conn.QueryRow(ctx, selectWorkMem).Scan(&workMem); err != nil {
			return fmt.Errorf("postgres: unable to determine work_mem: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	u := Matcher{
		pool:    matcher,
		queries: make(map[string]struct{}),
		workMem: workMem,
	}
	return &u, nil
}

// var _ datastore.UpdaterNG = (*MatcherV2)(nil)

func (u *Matcher) CollectGarbage(ctx context.Context, dur time.Duration) error {
	// For updaters in the work set, return the ones that have successful
	// runs outside the work set
	//
	// TODO(hank) Move to embed.
	const query = `
WITH work_set AS (SELECT id, updater FROM updater_v1.run WHERE run.date < (now() - interval $1)),
     recent AS (SELECT updater, bool_or(success) AS success FROM updater_v1.run GROUP BY updater)
	DELETE FROM run WHERE id IN (SELECT id FROM work_set JOIN recent USING updater WHERE success = TRUE);
	`
	return u.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		tag, err := c.Exec(ctx, query, dur)
		if err != nil {
			return err
		}
		ct := tag.RowsAffected()
		zlog.Debug(ctx).
			Int64("rows", ct).
			Msg("garbage collected runs")
		return nil
	})
}

func (u *Matcher) Initialized(ctx context.Context, expr string) (bool, error) {
	var out bool
	return out, u.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		// TODO(hank) Move to embed.
		const query = `SELECT NOT EXISTS(SELECT updater.name FROM updater LEFT OUTER JOIN (SELECT updater, bool_or(success) AS success FROM run GROUP BY updater) AS run ON updater.id = run.updater WHERE updater.name ~ $1::lquery AND run.success = FALSE);`
		return c.QueryRow(ctx, query, expr).Scan(&out)
	})
}

func (u *Matcher) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return nil, nil
}
