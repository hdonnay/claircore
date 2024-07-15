//go:build go1.23 || (go1.22 && goexperiment.rangefunc)

package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/updater/driver/v1"
)

type Matcher struct {
	pool *pgxpool.Pool

	workMem int
	queries map[string]struct{}
}

const minMatcherMigration = 13

func NewMatcherV2(ctx context.Context, matcher *pgxpool.Pool) (*Matcher, error) {
	var workMem int
	matcher.AcquireFunc(ctx, func(conn *pgxpool.Conn) error {
		var version int
		err := conn.QueryRow(ctx, fmt.Sprintf(`SELECT MAX(version) FROM %s;`, migrations.MatcherMigrationTable)).Scan(&version)
		if err != nil {
			return fmt.Errorf("postgres: unable to determine version: %w", err)
		}
		if got, want := version, minMatcherMigration; got < want {
			return fmt.Errorf("postgres: matcher database version too low: %d < %d (do you need to run migrations?)", got, want)
		}
		err = conn.QueryRow(ctx, `SELECT setting FROM pg_settings WHERE name = 'work_mem';`).Scan(&workMem)
		if err != nil {
			return fmt.Errorf("postgres: unable to determine work_mem: %w", err)
		}
		return nil
	})
	u := Matcher{
		pool:    matcher,
		workMem: workMem,
		queries: make(map[string]struct{}),
	}
	return &u, nil
}

// Style tip: use the "Func" methods on the Pool to get a scope for
// metrics/tracing for "free."

//var _ datastore.UpdaterNG = (*MatcherV2)(nil)

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

func (u *Matcher) GetUpdateOperations(ctx context.Context) ([]driver.UpdateOperation, error) {
	var out []driver.UpdateOperation
	return out, u.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		// TODO(hank) Move to embed.
		const query = `SELECT name, ref, date, success, fingerprint::TEXT, error FROM updater_v1.run JOIN updater_v1.updater ON updater.id = run.updater ORDER BY date ASC;`
		rows, err := c.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			i := len(out)
			out = append(out, driver.UpdateOperation{})
			op := &out[i]
			var errstr sql.NullString
			if err := rows.Scan(&op.Updater, &op.Ref, &op.Date, &op.Success, &op.Fingerprint, &errstr); err != nil {
				return err
			}
			if errstr.Valid {
				op.Error = errors.New(errstr.String)
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
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
