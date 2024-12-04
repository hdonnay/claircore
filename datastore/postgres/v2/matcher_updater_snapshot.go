package postgres

import (
	"context"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
	"github.com/quay/zlog"
)

// UpdaterSnapshotRun is a single updater doing a snapshot update.
type UpdaterSnapshotRun struct {
	fp driver.Fingerprint
	updaterRun
}

// NewSnapshot starts a "snapshot" updater run.
func (r *Run) NewSnapshot(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterSnapshotRun, error) {
	const method = `Run.NewSnapshot`
	var u UpdaterSnapshotRun
	ctx, u.span = tracer.Start(ctx, method, trace.WithLinks(r.link))
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
	u.fp = fp

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&u, func(u *UpdaterSnapshotRun) {
		panic(fmt.Sprintf("%s:%d: %T not closed", file, line, u))
	})
	return &u, nil
}

// Previous returns the previous [driver.UpdateOperation] for this updater.
func (u *UpdaterSnapshotRun) Previous(ctx context.Context) (op driver.UpdateOperation, ok bool, err error) {
	// TODO(hank) This should probably be some sort of query API or [iter.Seq]
	// instead of just the [driver.UpdateOperation].
	const method = `UpdaterSnapshotRun.Previous`
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

	err = u.tx.QueryRow(ctx, matcherGetPreviousUpdateOperation, u.updaterID, u.updRunID).
		Scan(&op)
	if err != nil {
		return driver.UpdateOperation{},
			false,
			errorf("reading UpdateOperation: %w", err)
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
		Msg("copied snapshot contents")

	_, err = u.tx.Exec(ctx, matcherUpdaterSnapshotRunSet, u.runID, u.updaterID, u.updRunID)
	if err != nil {
		return errorf("setting: %w", err)
	}
	return nil
}

// Finish finalizes the accumulated advisory database state.
func (u *UpdaterSnapshotRun) Finish(ctx context.Context, err error) error {
	const method = `UpdaterSnapshotRun.Finish`
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(u.link...))
	defer span.End()
	if err := u.finish(ctx, u.fp, err); err != nil {
		return prefixedErr(method)("%w", err)
	}
	return nil
}

// Close releases associated resources.
//
// If not called, the process may panic.
func (u *UpdaterSnapshotRun) Close() error {
	runtime.SetFinalizer(u, nil)
	return u.close()
}
