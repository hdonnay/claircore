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
	runtime.SetFinalizer(&r, func(_ *Run) {
		panic(fmt.Sprintf("%s:%d: postgres/v2.UpdaterRun not closed", file, line))
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
