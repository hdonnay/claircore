package i14n

import (
	"context"

	"github.com/jackc/pgx/v5"
)

var _ pgx.ConnectTracer = (*ConnectionCreateTracer)(nil)

// ConnectionCreateTracer records connection creation time metrics.
type ConnectionCreateTracer struct {
	name string
}

// TraceConnectStart implements [pgx.ConnectTracer].
func (t *ConnectionCreateTracer) TraceConnectStart(ctx context.Context, _ pgx.TraceConnectStartData) context.Context {
	return withDurationStart(ctx, connectCreateTiming)
}

// TraceConnectEnd implements [pgx.ConnectTracer].
func (t *ConnectionCreateTracer) TraceConnectEnd(ctx context.Context, data pgx.TraceConnectEndData) {
	if data.Err == nil {
		return
	}
	connCreateTime.Record(ctx, durationFromContext(ctx, connectCreateTiming).Seconds(), t.name)
}
