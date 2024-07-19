package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/updater/driver/v2"
)

func (u *Matcher) GetUpdateOperations(ctx context.Context, opts ...TODO) iter.Seq2[driver.UpdateOperation, error] {
	// This function delays all setup until the iterator is used.
	//
	// It's possible (although I can't think of a scenario at present) to create
	// an iterator on the off-chance it'll be needed and only pay the allocation
	// costs.
	return func(yield func(driver.UpdateOperation, error) bool) {
		ctx, span := tracer.Start(ctx, "Matcher.GetUpdateOperations")
		defer span.End()

		// TODO(hank) Move to embedded SQL.
		const query = `SELECT "id", "name", "ref", "date", "success", "fingerprint"::BYTEA, "error"
		FROM updater_v1.run
			JOIN updater_v1.updater ON updater.id = run.updater
		WHERE
			id > $2
		LIMIT $1
		ORDER BY (date, id) ASC;`

		// Use a ring buffer to request batches of rows. This is an attempt to
		// balance network round-trips (and query overhead) with buffering the
		// entire result set in the process' memory.
		ring := getRing[driver.UpdateOperation](0)
		defer putRing(ring)
		// Pagination token.
		var last pgtype.Int8
		// Last database fetch contained the last page of results.
		done := false

		for {
			switch {
			case ring.Empty() && done:
				return
			case ring.Empty(): // Pull rows.
			default:
				op, _ := ring.Shift()
				if !yield(op, nil) {
					return
				}
				continue
			}

			// Use [pgxpool.AcquireFunc] to create a nice, contained scope.
			err := u.pool.AcquireFunc(ctx, func(c *pgxpool.Conn) error {
				// TODO(hank) Per-request metrics?
				rows, err := c.Query(ctx, query, ring.Size(), &last)
				if err != nil {
					return err
				}
				defer rows.Close()
				for rows.Next() {
					op, _ := ring.Alloc()
					if err := rows.Scan(&last, &op.Updater, &op.Ref, &op.Date, &op.Success, &op.Fingerprint, &op.Error); err != nil {
						ring.Pop()
						return err
					}
				}
				// Done if the page was not full.
				done = !ring.Full()
				switch err := rows.Err(); {
				case err == nil:
				case errors.Is(err, pgx.ErrNoRows):
					// Empty page; "done" will be set and the switch in the
					// yield loop will exit the function.
				default:
					return err
				}
				return nil
			})
			if err != nil {
				yield(driver.UpdateOperation{}, err)
				return
			}
		}
	}
}

// Some type aliases to make the signatures shorter.
type (
	AddSeq = iter.Seq2[driver.NamespacedAdvisory[driver.Advisory], error]
	RemSeq = iter.Seq2[driver.NamespacedAdvisory[driver.AdvisoryName], error]
)

func (m *Matcher) UpdaterRun(ctx context.Context, updater string, ref uuid.UUID) (*UpdaterRun, error) {
	link := trace.LinkFromContext(ctx, attrRunRef.String(ref.String()))
	var span trace.Span
	ctx, span = tracer.Start(ctx, "Matcher.UpdaterRun", trace.WithLinks(link))
	defer span.End()

	const query = `WITH
	u AS (SELECT id FROM updater_v1.updater WHERE name = $2)
	INSERT INTO updater_v1.run (ref, updater, fingerprint) VALUES ($1, u.id, $3::jsonb) RETURNING id;`

	var runid int64
	err := m.pool.QueryRow(ctx, query, ref, updater, nil).Scan(&runid)
	if err != nil {
		return nil, fmt.Errorf(`postgres/v2: Matcher: unable to create run: %w`, err)
	}

	return &UpdaterRun{
		pool: m.pool,
		link: link,
	}, nil
}

type UpdaterRun struct {
	pool *pgxpool.Pool
	link trace.Link
}

func (r *UpdaterRun) NewSnapshot(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterSnapshotRun, error) {
	link := trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String()))
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterRun.NewSnapshot", trace.WithLinks(r.link))
	defer span.End()

	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	return &UpdaterSnapshotRun{
		link: []trace.Link{r.link, link},
		conn: conn,
	}, nil
}

func (r *UpdaterRun) NewDelta(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterDeltaRun, error) {
	link := trace.LinkFromContext(ctx, attrUpdRunName.String(updater), attrUpdRunRef.String(ref.String()))
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterRun.NewDelta", trace.WithLinks(r.link))
	defer span.End()

	conn, err := r.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	return &UpdaterDeltaRun{
		link: []trace.Link{r.link, link},
		conn: conn,
	}, nil
}

func (r *UpdaterRun) Close() error {
	return nil
}

type UpdaterDeltaRun struct {
	conn *pgxpool.Conn
	err  error
	link []trace.Link

	id  int64
	gen int64
}

func (u *UpdaterDeltaRun) Add(ctx context.Context, vs AddSeq) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterDeltaRun.Add", trace.WithLinks(u.link...))
	defer span.End()

	return nil
}

func (u *UpdaterDeltaRun) Remove(ctx context.Context, vs RemSeq) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterDeltaRun.Remove", trace.WithLinks(u.link...))
	defer span.End()

	return nil
}

func (u *UpdaterDeltaRun) Close(ctx context.Context) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterDeltaRun.Close", trace.WithLinks(u.link...))
	defer span.End()
	defer u.conn.Release()
	// Flush/merge?
	if u.err != nil {
		// TODO(hank) embed
		const markError = `UPDATE matcher_v2.updater_run SET error = $2 WHERE id = $1`
		tag, err := u.conn.Exec(ctx, markError, u.id, u.err.Error())
		_ = tag // TODO(hank) Metrics

		return errors.Join(err, u.err)
	}

	return nil
}

type UpdaterSnapshotRun struct {
	conn *pgxpool.Conn
	err  error
	link []trace.Link

	id  int64
	gen int64
}

func (u *UpdaterSnapshotRun) Previous(ctx context.Context) (driver.UpdateOperation, bool, error) {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterSnapshotRun.Previous", trace.WithLinks(u.link...))
	defer span.End()

	var op driver.UpdateOperation
	return op, false, nil
}

func (u *UpdaterSnapshotRun) Set(ctx context.Context, vs AddSeq) error {
	var span trace.Span
	ctx, span = tracer.Start(ctx, "UpdaterSnapshotRun.Set", trace.WithLinks(u.link...))
	defer span.End()

	opts := pgx.TxOptions{}

	err := beginTxFunc(ctx, u.conn, opts, func(ctx context.Context, tx pgx.Tx) error {
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
	defer u.conn.Release()
	// Flush/merge?
	if u.err != nil {
		// TODO(hank) embed
		const markError = `UPDATE matcher_v2.updater_run SET error = $2 WHERE id = $1`
		tag, err := u.conn.Exec(ctx, markError, u.id, u.err.Error())
		_ = tag // TODO(hank) Metrics

		return errors.Join(err, u.err)
	}

	return nil
}

/*
Previous attempt:

func (u *Matcher) UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs driver.ParsedVulnerabilities) error {
	opts := pgx.TxOptions{}
	tx, err := u.pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to start transaction: %w", err)
	}
	defer func() {
		switch err := tx.Rollback(ctx); {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrTxClosed):
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("error rolling back transaction")
		}
	}()
	//
	// Create a run:
	var runid int64
	err = tx.QueryRow(ctx, `
		WITH u AS (SELECT id FROM updater_v1.updater WHERE name = $2)
		INSERT INTO updater_v1.run ( ref, updater, fingerprint) VALUES ($1, u.id, $3::jsonb) RETURNING id;`, ref, updater, string(fp)).Scan(&runid)
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create run: %w", err)
	}

	// Bulk load advisories:
	tag, err := tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_new LIKE updater_v1.advisory ON COMMIT DROP;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("temporary table creation")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create temporary advisory table: %w", err)
	}
	src := advisoryCopySource(ctx, runid, vs)
	nrow, err := tx.CopyFrom(ctx, pgx.Identifier([]string{"advisory_new"}), src.Names(), src)
	zlog.Debug(ctx).
		Int64("count", nrow).
		Msg("temporary advisory copy")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to populate temporary advisory table: %w", err)
	}
	tag, err = tx.Exec(ctx, `MERGE INTO updater_v1.advisory a USING advisory_new n ON a.namespace = n.namespace AND a.name = n.name
	WHEN MATCHED THEN UPDATE SET a.generation = n.generation
	WHEN NOT MATCHED THEN INSERT (added, generation, namespace, name) VALUES
		(n.generation, n.generation, n.namespace, n.name)
	;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("advisory merge")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to merge into advisory table: %w", err)
	}

	// Bulk load metadata:
	tag, err = tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_meta_load (
		namespace TEXT,
		name TEXT,
		issued TIMESTAMPTZ,
		summary TEXT NOT NULL,
		description TEXT NOT NULL,
		uri TEXT,
		severity TEXT,
		normalized_severity TEXT,
		cvss3 TEXT
	) ON COMMIT DROP;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("temporary table creation")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create temporary table: %w", err)
	}
	msrc := advisoryMetaCopySource(&vs)
	nrow, err = tx.CopyFrom(ctx, pgx.Identifier([]string{"advisory_meta_load"}), msrc.Names(), msrc)
	zlog.Debug(ctx).
		Int64("count", nrow).
		Msg("temporary advisory copy")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to populate temporary advisory table: %w", err)
	}

	tag, err = tx.Exec(ctx, `MERGE INTO updater_v1.advisory_meta a
	USING
		(SELECT a.id, n.* FROM advisory_meta_load n JOIN advisory a ON a.namespace = n.namespace AND a.name = n.name) n
		ON a.id = n.id
	WHEN MATCHED THEN UPDATE SET (issued, summary, description, uri, severity, normalized_severity) =
		(n.issued, n.summary, n.description, n.uri, n.severity, n.normalized_severity)
	WHEN NOT MATCHED THEN INSERT (advisory, issued, summary, description, uri, severity, normalized_severity) VALUES
		(n.id, n.issued, n.summary, n.description, n.uri, n.severity, n.normalized_severity)
	;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("advisory merge")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to merge into advisory_meta table: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		// TODO(hank) Remove log-and-return.
		zlog.Warn(ctx).
			Err(err).
			Msg("error committing transaction")
		return fmt.Errorf("postgres: UpdaterV1: unable to commit transaction: %w", err)
	}
	return nil
}
*/

func advisoryMetaCopySource(seq AddSeq) *copyAdapter[driver.NamespacedAdvisory[driver.Advisory]] {
	return newCopyAdapter(9, seq, func(row []any, val driver.NamespacedAdvisory[driver.Advisory]) error {
		row[1] = val.Updater
		return nil
	})
}

var advisoryMetaNames = []string{"generation", "namespace", "name"}
