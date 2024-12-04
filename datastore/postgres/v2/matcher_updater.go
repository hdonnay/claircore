package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"runtime"
	"time"
	"unique"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/datastore/postgres/v2/internal/cursor"
	"github.com/quay/claircore/datastore/postgres/v2/internal/ringbuf"
	"github.com/quay/claircore/updater/driver/v2"
	"github.com/quay/zlog"
)

// BUG(hank) The [UpdaterSnapshotRun] and [UpdaterDeltaRun] objects can
// probably share most of their initialization code if the common parts are
// refactored and embedded.

// GetUpdateOperations returns an iterator and [TokenFunc] over
// the [driver.UpdateOperation] in the database.
func (m *Matcher) GetUpdateOperations(ctx context.Context, token string) (iter.Seq2[driver.UpdateOperation, error], TokenFunc) {
	const method = `Matcher.GetUpdateOperations`

	fill := func(
		ctx context.Context,
		ids *ringbuf.Buf[pgtype.Int8],
		ring *ringbuf.Buf[driver.UpdateOperation],
		last pgtype.Int8,
	) func(*pgxpool.Conn) error {
		return func(c *pgxpool.Conn) error {
			ctx, span := tracer.Start(ctx, method+".fill", trace.WithSpanKind(trace.SpanKindInternal))
			defer span.End()
			rows, err := c.Query(ctx, matcherGetUpdateOperations, ring.Size(), &last)
			if err != nil {
				return fmt.Errorf("%v: %w", NameLookup[unique.Make(matcherGetUpdateOperations)], err)
			}
			defer rows.Close()
			for rows.Next() {
				op, _ := ring.Alloc()
				id, _ := ids.Alloc()
				var fp []byte
				if err := rows.Scan(
					id,
					&op.Updater,
					&op.Ref,
					&op.Date,
					&op.Success,
					&fp,
					&op.Error,
				); err != nil {
					ring.Pop()
					ids.Pop()
					return err
				}
				op.Fingerprint = driver.Fingerprint(fp)
			}
			return rows.Err()
		}
	}
	c := cursor.New(fill, token)

	return c.All(ctx, m.pool), c.PaginationToken
}

// UpdatersRun creates a new [Run], which is a single execution of all the
// updaters in the system.
func (m *Matcher) UpdatersRun(ctx context.Context, ref uuid.UUID) (*Run, error) {
	const method = "Matcher.UpdaterRun"
	errorf := prefixedErr(method)
	r := Run{
		pool: m.pool,
		link: trace.LinkFromContext(ctx, attrRunRef.String(ref.String())),
	}
	ctx, r.span = tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))

	err := m.pool.QueryRow(ctx, matcherCreateRun, ref).Scan(&r.runid)
	if err != nil {
		return nil, errorf(`unable to create run: %w`, err)
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&r, func(_ *Run) {
		panic(fmt.Sprintf("%s:%d: postgres/v2.Run not closed", file, line))
	})
	return &r, nil
}

// AddSeq is an iterator of objects needed to add Advisories.
type AddSeq = iter.Seq2[driver.NamespacedAdvisory[driver.Advisory], error]

// RemSeq is an iterator of objects needed to remove Advisories.
type RemSeq = iter.Seq2[driver.NamespacedAdvisory[driver.AdvisoryName], error]

// Run is a single run of all the updaters in the system.
type Run struct {
	pool  *pgxpool.Pool
	span  trace.Span
	link  trace.Link
	runid int64
}

// Complete marks the [Run] as completed.
func (r *Run) Complete(ctx context.Context) (err error) {
	const method = "Matcher.Complete"
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))
	defer span.End()
	_, err = r.pool.Exec(ctx, matcherCompleteRun, r.runid)
	return err
}

// Close releases resources associated with the [Run].
func (r *Run) Close() error {
	r.span.End()
	runtime.SetFinalizer(r, nil)
	r.pool = nil
	r.runid = -1
	return nil
}

func advisoryMetaCopySource(seq AddSeq) *copyAdapter[driver.NamespacedAdvisory[driver.Advisory]] {
	return newCopyAdapter(9, seq, func(row []any, val driver.NamespacedAdvisory[driver.Advisory]) error {
		row[1] = val.Updater
		return nil
	})
}

var advisoryMetaNames = []string{"generation", "namespace", "name"}

// UpdaterRun is a helper object meant to be embedded in [UpdaterDeltaRun] and
// [UpdaterSnapshotRun].
type updaterRun struct {
	tx          pgx.Tx
	err         error
	span        trace.Span
	updaterName string
	link        []trace.Link

	runID     int64
	updaterID int64
	updRunID  int64
}

// Init holds common initialization code.
func (u *updaterRun) init(ctx context.Context, r *Run, ref uuid.UUID, updater string) error {
	u.runID = r.runid
	u.updaterName = updater

	opt := pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadWrite,
	}
	err := pgx.BeginTxFunc(ctx, r.pool, opt, func(tx pgx.Tx) (err error) {
		// NB these are all write queries.
		err = tx.QueryRow(ctx, matcherGetUpdaterID, u.updaterName).
			Scan(&u.updaterID)
		if err != nil {
			return fmt.Errorf("updater ID: %w", err)
		}
		err = tx.QueryRow(ctx, matcherCreateUpdaterRun, ref, u.updaterID, u.runID).
			Scan(&u.updRunID)
		if err != nil {
			return fmt.Errorf("updater_run ID: %w", err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("discovering updater IDs: %w", err)
	}

	u.tx, err = r.pool.BeginTx(ctx, opt)
	if err != nil {
		return fmt.Errorf("beginning tx: %w", err)
	}

	if _, err := u.tx.Exec(ctx, `CALL matcher_v2_import.stage();`); err != nil {
		return fmt.Errorf("staging import: %w", errors.Join(err, u.tx.Rollback(ctx)))
	}
	return nil
}

// Finish holds common application logic finalization code.
func (u *updaterRun) finish(ctx context.Context, fp driver.Fingerprint, err error) error {
	defer func() { u.tx = nil }()
	status := u.tx.Conn().PgConn().TxStatus()
	zlog.Debug(ctx).
		Str("status", string(status)).
		Msg("tx status")
	switch status {
	case 'E': // In failed transaction
		// TODO(hank) Pull a new connection and update the status.
		return fmt.Errorf("tx in failed status: %w", errors.Join(u.tx.Rollback(ctx), err, u.err))
	case 'T': // In transaction
	case 'I': // Idle -- how?
		err = errors.Join(err, errors.New("connection idle; extremely weird, please file a bug"))
	default:
		return fmt.Errorf("unknown tx status: %c", status)
	}

	var runErr, txErr error
	_, runErr = u.tx.Exec(ctx, matcherUpdaterRunFinish,
		u.updRunID, fp, errors.Join(u.err, err))
	if runErr != nil {
		txErr = u.tx.Rollback(ctx)
	} else {
		txErr = u.tx.Commit(ctx)
	}

	if err := errors.Join(runErr, txErr); err != nil {
		return err
	}
	return nil
}

// Finish holds common resource finalization code.
func (u *updaterRun) close() error {
	defer u.span.End()
	u.updaterID = -1
	u.updRunID = -1
	u.runID = -1
	if u.tx != nil {
		ctx, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		return errors.Join(u.err, u.tx.Rollback(ctx))
	}
	return u.err
}
