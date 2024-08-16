package postgres

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
)

// UpdaterSnapshotRun is a single updater doing a snapshot update.
type UpdaterSnapshotRun struct {
	pool *pgxpool.Pool
	err  error
	span trace.Span
	link []trace.Link

	id  int64
	gen int64
}

// NewSnapshot starts a "snapshot" updater run.
func (r *Run) NewSnapshot(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterSnapshotRun, error) {
	u := UpdaterSnapshotRun{
		pool: r.pool,
	}
	ctx, u.span = tracer.Start(ctx, "UpdaterRun.NewSnapshot", trace.WithLinks(r.link))
	u.link = []trace.Link{
		r.link,
		trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String())),
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&u, func(u *UpdaterSnapshotRun) {
		panic(fmt.Sprintf("%s:%d: %T not closed", file, line, u))
	})
	return &u, nil
}

func (u *UpdaterSnapshotRun) Previous(ctx context.Context) (driver.UpdateOperation, bool, error) {
	const method = `UpdaterSnapshotRun.Previous`
	var span trace.Span
	ctx, span = tracer.Start(ctx, method, trace.WithLinks(u.link...))
	defer span.End()

	var op driver.UpdateOperation
	return op, false, nil
}

func (u *UpdaterSnapshotRun) Set(ctx context.Context, vs AddSeq) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterSnapshotRun.Set", trace.WithLinks(u.link...))
	defer span.End()

	opts := pgx.TxOptions{}

	err := pgx.BeginTxFunc(ctx, u.pool, opts, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_import LIKE matcher_v2.advisory_import_template ON COMMIT DROP;`)
		_ = tag // TODO(hank) Metrics
		if err != nil {
			return err
		}
		src := advisoryMetaCopySource(vs)
		// src := advisoryCopySource(ctx, vs)
		ct, err := tx.CopyFrom(ctx, pgx.Identifier{"advisory_import"}, []string{}, src)
		_ = ct // TODO(hank) Metrics
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (u *UpdaterSnapshotRun) Close(ctx context.Context) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterSnapshotRun.Close", trace.WithLinks(u.link...))
	defer span.End()
	runtime.SetFinalizer(u, nil)
	// Flush/merge?
	if u.err != nil {
		err := u.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
			tag, err := c.Exec(ctx, matcherMarkUpdaterError, u.id, u.err.Error())
			_ = tag // TODO(hank) Metrics
			return err
		})

		return errors.Join(err, u.err)
	}

	return nil
}
