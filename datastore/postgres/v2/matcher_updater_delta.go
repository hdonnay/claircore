package postgres

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
)

// UpdaterDeltaRun is a single updater doing a delta update.
//
// Creating an UpdaterDeltaRun via [Run.NewDelta] logically creates a
// copy-on-write snapshot of the previous state of the advisory database for a
// given updater.
//
// UpdaterDeltaRun is not safe for concurrent use.
//
// BUG(hank) It might be OK to call [UpdaterDeltaRun.Add] and
// [UpdaterDeltaRun.Remove] multiple times? The API needs to have an opinion on
// this.
type UpdaterDeltaRun struct {
	updaterRun
}

// NewDelta starts a "delta" updater run.
//
// The returned object holds a connection from the underlying pool until
// [UpdaterDeltaRun.Close] is called.
func (r *Run) NewDelta(ctx context.Context, ref uuid.UUID, updater string) (*UpdaterDeltaRun, error) {
	const method = `Run.NewDelta`
	var u UpdaterDeltaRun
	ctx, u.span = tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))
	defer u.span.End()
	u.link = []trace.Link{
		r.link,
		trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String())),
	}

	if err := u.init(ctx, r, ref, updater); err != nil {
		err = prefixedErr(method)("unable to create run: %w", err)
		u.span.RecordError(err)
		u.span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&u, func(u *UpdaterDeltaRun) {
		panic(fmt.Sprintf("%s:%d: %T not closed", file, line, u))
	})
	u.span.SetStatus(codes.Ok, "")
	return &u, nil
}

// Add consumes the passed iterator and writes provided advisories into the next
// advisory database state.
func (u *UpdaterDeltaRun) Add(ctx context.Context, vs AddSeq) (err error) {
	const method = `UpdaterDeltaRun.Add`
	errorf := prefixedErr(method)
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
		return errorf("copying: %w", err)
	}
	zlog.Debug(ctx).
		Int64("count", ct).
		Msg("copied delta additions")

	_, err = u.tx.Exec(ctx, matcherUpdaterDeltaRunAdd, u.runID, u.updaterID, u.updRunID)
	if err != nil {
		return errorf("adding: %w", err)
	}
	return nil
}

// Remove consumes the passed iterator and removes the described advisories from
// the next advisory database state.
func (u *UpdaterDeltaRun) Remove(ctx context.Context, vs RemSeq) (err error) {
	const method = `UpdaterDeltaRun.Remove`
	errorf := prefixedErr(method)
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
		return errorf("copying: %w", err)
	}
	zlog.Debug(ctx).
		Int64("count", ct).
		Msg("copied delta removals")

	_, err = u.tx.Exec(ctx, matcherUpdaterDeltaRunRemove, u.runID, u.updaterID, u.updRunID)
	if err != nil {
		return errorf("removing: %w", err)
	}
	return nil
}

// Finish finalizes the accumulated advisory database state.
func (u *UpdaterDeltaRun) Finish(ctx context.Context, fp driver.Fingerprint, err error) error {
	const method = `UpdaterDeltaRun.Finish`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer span.End()
	if err := u.finish(ctx, fp, err); err != nil {
		return prefixedErr(method)("%w", err)
	}
	return nil
}

// Close releases associated resources.
//
// If not called, the process may panic.
func (u *UpdaterDeltaRun) Close() error {
	runtime.SetFinalizer(u, nil)
	return u.close()
}
