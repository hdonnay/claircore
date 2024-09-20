package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
	"github.com/quay/zlog"
)

// UpdaterSnapshotRun is a single updater doing a snapshot update.
type UpdaterSnapshotRun struct {
	tx          pgx.Tx
	err         error
	span        trace.Span
	updaterName string
	link        []trace.Link

	fp        driver.Fingerprint
	runID     int64
	updaterID int64
	updRunID  int64
}

// NewSnapshot starts a "snapshot" updater run.
func (r *Run) NewSnapshot(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterSnapshotRun, error) {
	u := UpdaterSnapshotRun{
		runID:       r.runid,
		updaterName: updater,
		fp:          fp,
	}
	ctx, u.span = tracer.Start(ctx, "UpdaterRun.NewSnapshot", trace.WithLinks(r.link))
	u.link = []trace.Link{
		r.link,
		trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String())),
	}

	opt := pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadWrite,
	}

	err := pgx.BeginTxFunc(ctx, r.pool, opt, func(tx pgx.Tx) (err error) {
		// NB these are all write queries.
		err = tx.QueryRow(ctx, matcherGetUpdaterID, updater).
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
		return nil, err
	}

	u.tx, err = r.pool.BeginTx(ctx, opt)
	if err != nil {
		return nil, err
	}

	if _, err := u.tx.Exec(ctx, `CALL matcher_v2_import.stage();`); err != nil {
		return nil, err
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&u, func(u *UpdaterSnapshotRun) {
		panic(fmt.Sprintf("%s:%d: %T not closed", file, line, u))
	})
	return &u, nil
}

// Previous returns the previous [driver.UpdateOperation] for this updater.
func (u *UpdaterSnapshotRun) Previous(ctx context.Context) (op driver.UpdateOperation, ok bool, err error) {
	// TODO(hank) This should probably be some sort of query API or iter.Seq
	// instead of just the UpdateOperation.
	const method = `UpdaterSnapshotRun.Previous`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "")
		}
		span.End()
	}()

	err = u.tx.QueryRow(ctx, matcherGetPreviousUpdateOperation, u.updaterID, u.updRunID).
		Scan(&op)
	if err != nil {
		return driver.UpdateOperation{},
			false,
			fmt.Errorf(errPre+"UpdaterSnapshotRun: %w", err)
	}

	return op, false, nil
}

// Set consumes the passed iterator and writes provided advisories into the next
// advisory database state.
//
// Any advisories not contained in the iterator will be removed from the
// visible advisories in the database.
func (u *UpdaterSnapshotRun) Set(ctx context.Context, vs AddSeq) (err error) {
	const method = `UpdaterSnapshotRun.Set`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer func() {
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "")
		}
		span.End()
	}()

	src := advisoryCopySource(ctx, vs)
	ct, err := u.tx.CopyFrom(ctx, pgx.Identifier{`advisory_import`}, src.Names(), src)
	if err != nil {
		return fmt.Errorf(errPre+method+": %w", err)
	}
	zlog.Debug(ctx).
		Int64("count", ct).
		Msg("copied snapshot contents")

	_, err = u.tx.Exec(ctx, matcherUpdaterSnapshotRunSet, u.runID, u.updaterID, u.updRunID)
	if err != nil {
		return fmt.Errorf(errPre+method+": %w", err)
	}
	return nil
}

// Finish finalizes the accumulated advisory database state.
func (u *UpdaterSnapshotRun) Finish(ctx context.Context, err error) error {
	const method = `UpdaterSnapshotRun.Finish`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer span.End()
	defer func() { u.tx = nil }()
	status := u.tx.Conn().PgConn().TxStatus()
	zlog.Debug(ctx).
		Str("status", string(status)).
		Msg("tx status")
	switch status {
	case 'E': // In failed transaction
		// TODO(hank) Pull a new connection and update the status.
		return errors.Join(u.tx.Rollback(ctx), err, u.err)
	case 'T': // In transaction
	case 'I': // Idle -- how?
		err = errors.Join(err, errors.New("connection idle; extremely weird, please file a bug"))
	default:
		return fmt.Errorf(errPre+method+": unknown tx status: %c", status)
	}

	ret := make([]error, 2)

	_, ret[0] = u.tx.Exec(ctx, matcherUpdaterRunFinish,
		u.updRunID, u.fp, errors.Join(u.err, err))
	if ret[0] != nil {
		ret[1] = u.tx.Rollback(ctx)
	} else {
		ret[1] = u.tx.Commit(ctx)
	}

	return nil
}

// Close releases associated resources.
//
// If not called, the process may panic.
func (u *UpdaterSnapshotRun) Close() error {
	defer u.span.End()
	runtime.SetFinalizer(u, nil)
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
