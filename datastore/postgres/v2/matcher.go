package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/metric"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/datastore/postgres/v2/internal/o11y"
	"github.com/quay/claircore/updater/driver/v2"
)

type Matcher struct {
	pool *pgxpool.Pool

	reg     metric.Registration
	queries map[string]struct{}
	// TODO(hank) Do something smart with this.
	workMem int64
}

const minMatcherMigration = 13

func NewMatcherV2(ctx context.Context, matcher *pgxpool.Pool) (*Matcher, error) {
	reg, err := o11y.CollectStats(matcher)
	if err != nil {
		return nil, fmt.Errorf(errPre+"unable to register metrics collection: %w", err)
	}
	var ok bool
	defer func() {
		if !ok {
			reg.Unregister()
		}
	}()
	m := Matcher{
		pool:    matcher,
		reg:     reg,
		queries: make(map[string]struct{}),
	}

	err = matcher.AcquireFunc(ctx, sanityCheck(ctx, &m.workMem, migrations.MatcherMigrationTable, minMatcherMigration))
	if err != nil {
		return nil, fmt.Errorf(errPre+"%w", err)
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&m, func(m *Matcher) {
		panic(fmt.Sprintf("%s:%d: postgres/v2.Matcher not closed", file, line))
	})
	ok = true
	return &m, nil
}

func (m *Matcher) Close() error {
	runtime.SetFinalizer(m, nil)
	return m.reg.Unregister()
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

// Initialized reports if any [Run] has completed.
//
// If "strict" is true, the method reports if the latest completed run finished
// without errors and with the currently configured set of Updaters.
func (u *Matcher) Initialized(ctx context.Context, strict bool) (out bool, err error) {
	if strict {
		return false, errors.ErrUnsupported
	}
	return out, u.pool.
		QueryRow(ctx, matcherInitialized).
		Scan(&out)
}

func (u *Matcher) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error) {
	return nil, nil
}
