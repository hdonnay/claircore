package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/metric"

	"github.com/quay/claircore/datastore/postgres/migrations"
	"github.com/quay/claircore/datastore/postgres/v2/internal/o11y"
	"github.com/quay/claircore/updater/driver/v2"
)

// Matcher is the component that interacts with the database containing flaw
// advisories.
type Matcher struct {
	pool *pgxpool.Pool

	reg     metric.Registration
	queries map[string]struct{}
	// TODO(hank) Do something smart with this.
	workMem int64
}

const minMatcherMigration = 13

// NewMatcherV2 constructs a [Matcher].
//
// The "V2" signifies that this implements the relevant "V2" of the
// [github.com/quay/claircore/datastore] interfaces.
//
// The returned [Matcher] does not close the [pgxpool.Pool] when closed.
// If [Matcher.Close] is not called, the program may panic.
func NewMatcherV2(ctx context.Context, matcher *pgxpool.Pool) (*Matcher, error) {
	reg, err := o11y.CollectStats(matcher)
	if err != nil {
		return nil, errorf("unable to register metrics collection: %w", err)
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
		return nil, errorf("%w", err)
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&m, func(_ *Matcher) {
		panic(fmt.Sprintf("%s:%d: postgres/v2.Matcher not closed", file, line))
	})
	ok = true
	return &m, nil
}

// Close releases any held resources.
//
// The program may panic if not called.
func (m *Matcher) Close() error {
	runtime.SetFinalizer(m, nil)
	return m.reg.Unregister()
}

// CollectGarbage removes all [Run]s beyond the configured number to keep.
//
// BUG(hank) [Matcher.CollectGarbage] has no API to configure the retention
// lifetime.
func (m *Matcher) CollectGarbage(ctx context.Context) error {
	return m.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
		tag, err := c.Exec(ctx, `CALL matcher_v2.run_gc();`)
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
//
// BUG(hank) [Matcher.Initialized] does not implement "strict" mode.
func (m *Matcher) Initialized(ctx context.Context, strict bool) (out bool, err error) {
	if strict {
		return false, errors.ErrUnsupported
	}
	return out, m.pool.
		QueryRow(ctx, matcherInitialized).
		Scan(&out)
}

// GetUpdateDiff ...
//
// The returned [driver.UpdateDifference] claims a database connection from the
// pool, so a long-lived caller may cause resource exhaustion.
//
// BUG(hank) [Matcher.GetUpdateDiff] is not implemented.
func (m *Matcher) GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (driver.UpdateDifference, error) {
	ct := -1
	err := m.pool.
		QueryRow(ctx, matcherCheckRetentionCount).
		Scan(&ct)
	if err != nil {
		return nil, errorf("unable to check retention count: %w", err)
	}
	switch {
	case ct < 1:
		return nil, errorf(`database configuration for "retain_runs" is malformed: %w`, ErrDatabaseAppConfig)
	case ct == 1:
		return nil, ErrNoHistory
	default:
	}

	// type UpdateDiff struct {
	// 	Added, Removed iter.Seq2[Advisory, error]
	// 	Prev, Cur      UpdateOperation
	// }

	return nil, errors.ErrUnsupported
}

var _ driver.UpdateDifference = (*updateDiffer)(nil)

type updateDiffer struct {
	matcher *Matcher
	tx      pgx.Tx
}

// Added implements [driver.UpdateDifference].
func (u *updateDiffer) Added(context.Context) (iter.Seq2[driver.Advisory, error], error) {
	panic("unimplemented")
}

// Operations implements [driver.UpdateDifference].
func (u *updateDiffer) Operations(context.Context) (prev driver.UpdateOperation, cur driver.UpdateOperation, err error) {
	panic("unimplemented")
}

// Removed implements [driver.UpdateDifference].
func (u *updateDiffer) Removed(context.Context) (iter.Seq2[driver.Advisory, error], error) {
	panic("unimplemented")
}

// Close implements [driver.UpdateDifference].
func (u *updateDiffer) Close() error {
	switch s := u.tx.Conn().PgConn().TxStatus(); s {
	case 'T': // OK
	case 'I': // WTF
	case 'E': // Errored
	default: // WTF
		panic("wtf")
	}
	panic("unimplemented")
}
