package postgres

import (
	"context"
	"fmt"
	"iter"
	"runtime"
	"unique"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/trace"

	"github.com/quay/claircore/datastore/postgres/v2/internal/cursor"
	"github.com/quay/claircore/datastore/postgres/v2/internal/ringbuf"
	"github.com/quay/claircore/updater/driver/v2"
)

func (u *Matcher) GetUpdateOperations(ctx context.Context, token string) (iter.Seq2[driver.UpdateOperation, error], func() string) {
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

func (m *Matcher) UpdatersRun(ctx context.Context, ref uuid.UUID) (*Run, error) {
	const method = "Matcher.UpdaterRun"
	r := Run{
		pool: m.pool,
		link: trace.LinkFromContext(ctx, attrRunRef.String(ref.String())),
	}
	ctx, r.span = tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))

	err := m.pool.QueryRow(ctx, matcherCreateRun, ref).Scan(&r.runid)
	if err != nil {
		return nil, fmt.Errorf(errPre+`Matcher: unable to create run: %w`, err)
	}

	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(&r, func(r *Run) {
		panic(fmt.Sprintf("%s:%d: postgres/v2.UpdaterRun not closed", file, line))
	})
	return &r, nil
}

// Some type aliases to make the signatures shorter.
type (
	AddSeq = iter.Seq2[driver.NamespacedAdvisory[driver.Advisory], error]
	RemSeq = iter.Seq2[driver.NamespacedAdvisory[driver.AdvisoryName], error]
)

// Run is a single run of all the updaters in the system.
type Run struct {
	pool  *pgxpool.Pool
	span  trace.Span
	link  trace.Link
	runid int64
}

// Complete marks the Run as completed.
func (r *Run) Complete(ctx context.Context) (err error) {
	const method = "Matcher.Complete"
	ctx, span := tracer.Start(ctx, method, trace.WithSpanKind(trace.SpanKindInternal), trace.WithLinks(r.link))
	defer span.End()
	_, err = r.pool.Exec(ctx, matcherCompleteRun, r.runid)
	return err
}

// Close releases resources associated with the Run.
func (r *Run) Close() error {
	r.span.End()
	runtime.SetFinalizer(r, nil)
	r.pool = nil
	r.runid = -1
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
