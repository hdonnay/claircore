package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
	"github.com/quay/zlog"
)

// UpdaterDeltaRun is a single updater doing a delta update.
//
// Creating an UpdaterDeltaRun via [Run.NewDelta] logically creates a
// copy-on-write snapshot of the previous state of the advisory database for a
// given updater.
//
// UpdaterDeltaRun is not safe for concurrent use.
type UpdaterDeltaRun struct {
	tx          pgx.Tx
	err         error
	span        trace.Span
	updaterName string
	link        []trace.Link

	runID     int64
	updaterID int64
	updRunID  int64
}

// NewDelta starts a "delta" updater run.
//
// The returned object holds a connection from the underlying pool until
// [UpdaterDeltaRun.Close] is called.
func (r *Run) NewDelta(ctx context.Context, ref uuid.UUID, updater string) (*UpdaterDeltaRun, error) {
	const method = `Run.NewDelta`
	u := UpdaterDeltaRun{
		runID:       r.runid,
		updaterName: updater,
	}
	ctx, u.span = tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))
	u.link = []trace.Link{
		r.link,
		trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String())),
	}
	var ok bool
	var err error
	defer func() {
		if ok {
			return
		}
		u.span.RecordError(err)
		u.span.SetStatus(codes.Error, err.Error())
		u.span.End()
		if u.tx != nil {
			err = errors.Join(err, u.tx.Rollback(ctx))
		}
		err = fmt.Errorf(errPre+method+": unable to create run: %w", err)
	}()

	opt := pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadWrite,
	}
	err = pgx.BeginTxFunc(ctx, r.pool, opt, func(tx pgx.Tx) (err error) {
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
	runtime.SetFinalizer(&u, func(u *UpdaterDeltaRun) {
		panic(fmt.Sprintf("%s:%d: %T not closed", file, line, u))
	})
	ok = true
	return &u, nil
}

// It might be OK to call Add and Remove multiple times?

// Add consumes the passed iterator and writes provided advisories into the next
// advisory database state.
func (u *UpdaterDeltaRun) Add(ctx context.Context, vs AddSeq) (err error) {
	const method = `UpdaterDeltaRun.Add`
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
		Msg("copied delta additions")

	var tag pgconn.CommandTag
	// TODO(hank) move to embed
	tag, err = u.tx.Exec(ctx, `CALL matcher_v2_import.commit_add($1,$2,$3);`, u.runID, u.updaterID, u.updRunID)
	// TODO(hank) Metrics
	_ = tag
	if err != nil {
		return fmt.Errorf(errPre+method+": %w", err)
	}
	return nil
}

// Remove consumes the passed iterator and removes the described advisories from
// the next advisory database state.
func (u *UpdaterDeltaRun) Remove(ctx context.Context, vs RemSeq) (err error) {
	const method = `UpdaterDeltaRun.Remove`
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

	src := removeCopySource(ctx, vs)
	ct, err := u.tx.CopyFrom(ctx, pgx.Identifier{`advisory_import`}, src.Names(), src)
	if err != nil {
		return fmt.Errorf(errPre+method+": %w", err)
	}
	zlog.Debug(ctx).
		Int64("count", ct).
		Msg("copied delta removals")

	var tag pgconn.CommandTag
	// TODO(hank) move to embed
	tag, err = u.tx.Exec(ctx, `CALL matcher_v2_import.commit_remove($1,$2,$3);`, u.runID, u.updaterID, u.updRunID)
	// TODO(hank) Metrics
	_ = tag
	if err != nil {
		return fmt.Errorf(errPre+method+": %w", err)
	}
	return nil
}

// Finish finalizes the accumulated advisory database state.
func (u *UpdaterDeltaRun) Finish(ctx context.Context, fp driver.Fingerprint) error {
	const method = `UpdaterDeltaRun.Finish`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer span.End()
	defer func() { u.tx = nil }()
	switch s := u.tx.Conn().PgConn().TxStatus(); s {
	case 'E':
		return u.tx.Rollback(ctx)
	case 'T':
	default:
		return fmt.Errorf(errPre+method+": unknown tx status: %c", s)
	}

	errs := make([]error, 2)
	_, errs[0] = u.tx.Exec(ctx, `SELECT matcher_v2_import.finish_updater_run($1::BIGINT, $2::JSONB, $3::TEXT);`, u.updRunID, fp, u.err)
	if errs[0] != nil {
		errs[1] = u.tx.Rollback(ctx)
	} else {
		errs[1] = u.tx.Commit(ctx)
	}
	return errors.Join(errs...)
}

// Close releases associated resources.
//
// If not called, the process may panic.
func (u *UpdaterDeltaRun) Close() error {
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
