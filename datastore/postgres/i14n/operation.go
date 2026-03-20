package i14n

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"
)

var _ pgx.QueryTracer = (*OperationTracer)(nil)

// OperationTracer records query timing and response metrics.
type OperationTracer struct {
	name  string
	attrs []attribute.KeyValue
}

// TraceQueryStart implements [pgx.QueryTracer].
func (m *OperationTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	ctx, _ = tracer.Start(ctx, "TODO",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(semconv.DBQueryText(data.SQL)),
	)
	if span := trace.SpanFromContext(ctx); span.IsRecording() {
		span.SetAttributes(
			semconv.DBQueryText(data.SQL),
		)
	}
	return withDurationStart(ctx, operationTiming)
}

// TraceQueryEnd implements [pgx.QueryTracer].
func (m *OperationTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	span := trace.SpanFromContext(ctx)
	if !opDuration.Enabled(ctx) && !responseRows.Enabled(ctx) && !span.IsRecording() {
		span.End()
		return
	}
	tag := &data.CommandTag
	attrs := append(m.attrs,
		semconv.DBOperationName(strings.Fields(tag.String())[0]),
	)
	statusCode := "0000"
	stackTrace := false
	if err := data.Err; err != nil {
		stackTrace = true
		var pgErr *pgconn.PgError
		var desc string
		if errors.As(err, &pgErr) {
			attrs = append(attrs,
				errorType(pgErr.Code),
				semconv.DBCollectionName(pgx.Identifier{pgErr.SchemaName, pgErr.TableName}.Sanitize()),
			)
			statusCode = pgErr.Code
			desc = pgErr.Message
		} else {
			attrs = append(attrs, semconv.ErrorTypeOther)
			span.RecordError(err)
		}
		span.SetStatus(codes.Error, desc)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	attrs = append(attrs, semconv.DBResponseStatusCode(statusCode))
	addr := conn.PgConn().Conn().RemoteAddr()
	switch addr.Network() {
	case "tcp", "tcp4", "tcp6":
		host, portStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			break
		}
		attrs = append(attrs, semconv.NetworkPeerAddress(host))
		port := 5432
		if portStr != "" {
			port, err = strconv.Atoi(portStr)
			if err != nil {
				break
			}
		}
		attrs = append(attrs, semconv.NetworkPeerPort(port))
	default:
		attrs = append(attrs, semconv.NetworkPeerAddress(addr.String()))
	}
	set := attribute.NewSet(attrs...)

	end := durationFromContext(ctx, operationTiming)
	opDuration.RecordSet(ctx, end.Seconds(), set)
	responseRows.RecordSet(ctx, tag.RowsAffected(), set)
	span.SetAttributes(attrs...)
	span.End(trace.WithStackTrace(stackTrace))
}
