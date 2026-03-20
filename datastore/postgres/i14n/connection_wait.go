package i14n

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

var _ pgxpool.AcquireTracer = (*ConnectionWaitTracer)(nil)

// ConnectionWaitTracer records pool wait time metrics.
type ConnectionWaitTracer struct {
	name string
}

// TraceAcquireStart implements [pgxpool.AcquireTracer].
func (*ConnectionWaitTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return withDurationStart(ctx, connectAcquireTiming)
}

// TraceAcquireEnd implements [pgxpool.AcquireTracer].
func (t *ConnectionWaitTracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if data.Err == nil {
		return
	}
	connWaitTime.Record(ctx, durationFromContext(ctx, connectAcquireTiming).Seconds(), t.name)
}
