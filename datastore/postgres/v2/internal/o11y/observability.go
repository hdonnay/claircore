// Package o11y is OpenTelemetry observability integration for pgx.
package o11y

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unique"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var (
	_ pgx.BatchTracer    = (*Tracer)(nil)
	_ pgx.ConnectTracer  = (*Tracer)(nil)
	_ pgx.CopyFromTracer = (*Tracer)(nil)
	_ pgx.PrepareTracer  = (*Tracer)(nil)
	_ pgx.QueryTracer    = (*Tracer)(nil)

	_ pgxpool.AcquireTracer = (*Tracer)(nil)
	_ pgxpool.ReleaseTracer = (*Tracer)(nil)
)

func setErr(span trace.Span, err error) {
	if err == nil || errors.Is(err, pgx.ErrNoRows) {
		return
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		span.SetAttributes(semconv.ErrorTypeKey.String(pgErr.Code))
	}
}

func connectionAttrs(conn *pgx.Conn) trace.SpanStartEventOption {
	return trace.WithAttributes(
		PostgresqlPID(conn.PgConn().PID()),
	)
}

func getPoolName(conn *pgx.Conn) attribute.KeyValue {
	m := conn.PgConn().CustomData()
	name, ok := m[poolName].(attribute.KeyValue)
	if !ok {
		name = DBPoolName(conn.Config())
		m[poolName] = name
	}
	return name
}

// SetTracer modifies the passed config, adding a tracer satisfying the [pgx]
// and [pgxpool] tracing interfaces:
//
// - [pgx.BatchTracer]
// - [pgx.ConnectTracer]
// - [pgx.CopyFromTracer]
// - [pgx.PrepareTracer]
// - [pgx.QueryTracer]
// - [pgxpool.AcquireTracer]
// - [pgxpool.ReleaseTracer]
//
// If the [pgxpool.Config] already has a tracer set, it will be called after the
// tracing hooks installed by this function.
func SetTracer(cfg *pgxpool.Config) {
	t := Tracer{
		attrs: []attribute.KeyValue{
			semconv.DBSystemPostgreSQL,
			semconv.ServerAddress(cfg.ConnConfig.Host),
			semconv.ServerPort(int(cfg.ConnConfig.Port)),
			semconv.DBNamespace(cfg.ConnConfig.Database),
			DBUser(cfg.ConnConfig.User),
			DBPoolName(cfg.ConnConfig),
		},
		prev: cfg.ConnConfig.Tracer,
	}
	cfg.ConnConfig.Tracer = &t
}

const (
	poolName = `pool_name`
	useStart = `use_start`
)

// Tracer is the concrete implementation of the [pgx] and [pgxpool] tracing
// interfaces.
type Tracer struct {
	prev  pgx.QueryTracer
	attrs []attribute.KeyValue
}

// TraceAcquireEnd - TraceAcquireStart == wait_time.

// TraceAcquireStart implements [pgxpool.AcquireTracer].
func (t *Tracer) TraceAcquireStart(ctx context.Context, pool *pgxpool.Pool, data pgxpool.TraceAcquireStartData) context.Context {
	ctx = context.WithValue(ctx, timingStart, time.Now())
	ctx, _ = tracer.Start(ctx, "Acquire", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...))
	if at, ok := t.prev.(pgxpool.AcquireTracer); ok {
		ctx = at.TraceAcquireStart(ctx, pool, data)
	}
	return ctx
}

// TraceAcquireEnd implements [pgxpool.AcquireTracer].
func (t *Tracer) TraceAcquireEnd(ctx context.Context, pool *pgxpool.Pool, data pgxpool.TraceAcquireEndData) {
	if data.Err != nil {
		// TODO(hank) Log?
		return
	}

	data.Conn.PgConn().CustomData()[useStart] = time.Now()

	if t, ok := ctx.Value(timingStart).(time.Time); ok {
		dur := time.Since(t)
		dbClientConnectionWaitTime.Record(ctx,
			dur.Seconds(),
			metric.WithAttributes(getPoolName(data.Conn)))
	}

	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)
	if c := data.Conn; c != nil {
		span.SetAttributes(PostgresqlPID(c.PgConn().PID()))
	}
	span.End()
	if at, ok := t.prev.(pgxpool.AcquireTracer); ok {
		at.TraceAcquireEnd(ctx, pool, data)
	}
}

// TraceRelease - TraceAcquireEnd == use_time.

// TraceRelease implements [pgxpool.ReleaseTracer].
func (t *Tracer) TraceRelease(pool *pgxpool.Pool, data pgxpool.TraceReleaseData) {
	// End pool span
	ctx := context.Background() // ???

	m := data.Conn.PgConn().CustomData()
	name, ok := m[poolName].(attribute.KeyValue)
	if !ok {
		name = DBPoolName(pool.Config().ConnConfig)
		m[poolName] = name
	}
	if v, ok := m[useStart]; ok {
		dur := time.Since(v.(time.Time))
		dbClientConnectionUseTime.Record(ctx,
			dur.Seconds(),
			metric.WithAttributes(name))
		delete(m, useStart)
	}
	if rt, ok := t.prev.(pgxpool.ReleaseTracer); ok {
		rt.TraceRelease(pool, data)
	}
}

// TraceConnectEnd - TraceConnectStart == create_time

// TraceConnectStart implements [pgx.ConnectTracer].
func (t *Tracer) TraceConnectStart(ctx context.Context, data pgx.TraceConnectStartData) context.Context {
	ctx = context.WithValue(ctx, timingStart, time.Now())
	ctx, _ = tracer.Start(ctx, "Connect", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...))
	if ct, ok := t.prev.(pgx.ConnectTracer); ok {
		ctx = ct.TraceConnectStart(ctx, data)
	}
	return ctx
}

type timeout interface {
	Timeout() bool
}

// TraceConnectEnd implements [pgx.ConnectTracer].
func (t *Tracer) TraceConnectEnd(ctx context.Context, data pgx.TraceConnectEndData) {
	// Record connection timeout metric
	if o, ok := data.Err.(timeout); o != nil && ok && o.Timeout() {
		dbClientConnectionTimeouts.Add(ctx, 1, metric.WithAttributes(t.attrs...))
	}
	// Record creation time metric
	if data.Conn != nil {
		name := DBPoolName(data.Conn.Config())
		if t, ok := ctx.Value(timingStart).(time.Time); ok {
			dur := time.Since(t)
			dbClientConnectionCreateTime.Record(ctx,
				dur.Seconds(),
				metric.WithAttributes(name))
		}
		m := data.Conn.PgConn().CustomData()
		m[poolName] = name
	}

	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)
	if c := data.Conn; c != nil {
		span.SetAttributes(PostgresqlPID(c.PgConn().PID()))
	}
	span.End()
	if ct, ok := t.prev.(pgx.ConnectTracer); ok {
		ct.TraceConnectEnd(ctx, data)
	}
}

// TraceBatchStart implements [pgx.BatchTracer].
func (t *Tracer) TraceBatchStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	ctx, _ = tracer.Start(ctx, "Batch", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...),
		connectionAttrs(conn),
	)
	if bt, ok := t.prev.(pgx.BatchTracer); ok {
		ctx = bt.TraceBatchStart(ctx, conn, data)
	}
	return ctx
}

// TraceBatchQuery implements [pgx.BatchTracer].
func (t *Tracer) TraceBatchQuery(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchQueryData) {
	span := trace.SpanFromContext(ctx)
	// TODO(hank) Flesh this out
	span.AddEvent("Query", connectionAttrs(conn))
	if bt, ok := t.prev.(pgx.BatchTracer); ok {
		bt.TraceBatchQuery(ctx, conn, data)
	}
}

// TraceBatchEnd implements [pgx.BatchTracer].
func (t *Tracer) TraceBatchEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceBatchEndData) {
	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)
	span.End()
	if bt, ok := t.prev.(pgx.BatchTracer); ok {
		bt.TraceBatchEnd(ctx, conn, data)
	}
}

// TraceCopyFromStart implements [pgx.CopyFromTracer].
func (t *Tracer) TraceCopyFromStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	ctx, _ = tracer.Start(ctx, "CopyFrom", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...),
		connectionAttrs(conn),
		trace.WithAttributes(
			PostgresqlCopyFromTable(data.TableName.Sanitize()),
		),
	)
	if ct, ok := t.prev.(pgx.CopyFromTracer); ok {
		ctx = ct.TraceCopyFromStart(ctx, conn, data)
	}
	return ctx
}

// TraceCopyFromEnd implements [pgx.CopyFromTracer].
func (t *Tracer) TraceCopyFromEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceCopyFromEndData) {
	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)

	if data.Err == nil {
		span.SetAttributes(PostgresqlRowsAffected(data.CommandTag.RowsAffected()))
	}

	span.End()
	if ct, ok := t.prev.(pgx.CopyFromTracer); ok {
		ct.TraceCopyFromEnd(ctx, conn, data)
	}
}

// TracePrepareStart implements [pgx.PrepareTracer].
func (t *Tracer) TracePrepareStart(ctx context.Context, conn *pgx.Conn, data pgx.TracePrepareStartData) context.Context {
	ctx, _ = tracer.Start(ctx, "Prepare", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...),
		connectionAttrs(conn),
		trace.WithAttributes(DBQueryAttr(data.SQL)),
	)
	if ct, ok := t.prev.(pgx.PrepareTracer); ok {
		ctx = ct.TracePrepareStart(ctx, conn, data)
	}
	return ctx
}

// TracePrepareEnd implements [pgx.PrepareTracer].
func (t *Tracer) TracePrepareEnd(ctx context.Context, conn *pgx.Conn, data pgx.TracePrepareEndData) {
	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)
	span.End()
	if ct, ok := t.prev.(pgx.PrepareTracer); ok {
		ct.TracePrepareEnd(ctx, conn, data)
	}
}

// TraceQueryStart implements [pgx.QueryTracer].
func (t *Tracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	attrs := []attribute.KeyValue{DBQueryAttr(data.SQL)}
	for n, arg := range data.Args {
		key := fmt.Sprintf("db.query.parameter.%d", n)
		var v string
		switch arg := arg.(type) {
		case fmt.GoStringer:
			v = arg.GoString()
		case fmt.Stringer:
			v = arg.String()
		default:
			v = fmt.Sprint(arg)
		}
		attrs = append(attrs, attribute.Key(key).String(v))
	}

	if name, ok := nameLookup[unique.Make(data.SQL)]; ok {
		ctx = context.WithValue(ctx, queryName, name)
	}

	ctx, _ = tracer.Start(ctx, "Query", trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(t.attrs...),
		connectionAttrs(conn),
		trace.WithAttributes(attrs...),
	)

	if t.prev != nil {
		ctx = t.prev.TraceQueryStart(ctx, conn, data)
	}
	return ctx
}

// TraceQueryEnd implements [pgx.QueryTracer].
func (t *Tracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	span := trace.SpanFromContext(ctx)
	setErr(span, data.Err)

	if data.Err == nil {
		span.SetAttributes(PostgresqlRowsAffected(data.CommandTag.RowsAffected()))
	}

	span.End()
	if t.prev != nil {
		t.prev.TraceQueryEnd(ctx, conn, data)
	}
}

type ctxKey struct{}

var (
	connectKey  ctxKey
	poolnameKey ctxKey
	timingStart ctxKey
	queryName   ctxKey
)
