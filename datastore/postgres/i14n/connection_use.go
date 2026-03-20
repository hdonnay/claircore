package i14n

import (
	"context"
	"sync"
	"time"
	"weak"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/semconv/v1.40.0/dbconv"
)

var (
	_ pgxpool.AcquireTracer = (*ConnectionTracer)(nil)
	_ pgxpool.ReleaseTracer = (*ConnectionTracer)(nil)
)

// ConnectionTracer records pool count and use duration metrics.
type ConnectionTracer struct {
	name  string
	inuse sync.Map
}

// TraceAcquireStart implements [pgxpool.AcquireTracer].
func (*ConnectionTracer) TraceAcquireStart(ctx context.Context, _ *pgxpool.Pool, _ pgxpool.TraceAcquireStartData) context.Context {
	return ctx
}

// TraceAcquireEnd implements [pgxpool.AcquireTracer].
func (t *ConnectionTracer) TraceAcquireEnd(ctx context.Context, _ *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if data.Err == nil {
		return
	}
	connCount.Add(ctx, -1, t.name, dbconv.ClientConnectionStateIdle)
	connCount.Add(ctx, 1, t.name, dbconv.ClientConnectionStateUsed)

	key := weak.Make(data.Conn)
	inuse := inUsePool.New().(*inUse)
	inuse.Context = ctx
	inuse.Start = time.Now()
	// If any code paths don't go through TraceRelease, then the "inuse" map
	// will leak entries.
	t.inuse.Store(key, inuse)
}

// TraceRelease implements [pgxpool.ReleaseTracer].
func (t *ConnectionTracer) TraceRelease(_ *pgxpool.Pool, data pgxpool.TraceReleaseData) {
	key := weak.Make(data.Conn)
	v, ok := t.inuse.LoadAndDelete(key)
	if !ok {
		panic("wtf: released unacquired connection")
	}
	inuse := v.(*inUse)
	ctx := inuse.Context

	connCount.Add(ctx, -1, t.name, dbconv.ClientConnectionStateUsed)
	connCount.Add(ctx, 1, t.name, dbconv.ClientConnectionStateIdle)
	connUseTime.Record(ctx, time.Since(inuse.Start).Seconds(), t.name)
	inuse.Context = nil
	inUsePool.Put(inuse)
}

// InUse is used to smuggle the information needed for use duration metrics.
type inUse struct {
	Context context.Context
	Start   time.Time
}

var inUsePool = sync.Pool{
	New: func() any {
		return new(inUse)
	},
}
