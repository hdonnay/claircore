package postgres

import (
	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// TelemetrySchemaVersion is the OpenTelemetry "telemetry schema" version for this package.
// See the [Telemetry Schemas] documentation for more information.
//
// BUG(hank) The telemetry exported by this package does not have a schema yet.
//
// TODO(hank) Export this name when we have something set up for this.
//
// [Telemetry Schemas]: https://opentelemetry.io/docs/specs/otel/schemas/
const telemetrySchemaVersion = `0.1.0`

// Tracer and Meter singletons for this package.
var (
	tracer trace.Tracer
	meter  metric.Meter
)

// The instruments used in this package.
var (
	methodCount    metric.Int64Counter
	methodDuration metric.Int64Histogram
	callCounter    metric.Int64Counter
	callDuration   metric.Int64Histogram

	// These are as specified in
	// https://opentelemetry.io/docs/specs/semconv/database/database-metrics/.
	poolUsage      metric.Int64ObservableUpDownCounter
	poolIdleMax    metric.Int64UpDownCounter
	poolIdleMin    metric.Int64UpDownCounter
	poolMax        metric.Int64UpDownCounter
	poolPending    metric.Int64ObservableUpDownCounter
	poolTimeout    metric.Int64ObservableCounter
	poolCreateTime metric.Int64Histogram
	poolWaitTime   metric.Int64Histogram
	poolUseTime    metric.Int64Histogram
)

// Must is a panic-or-return helper for [init].
func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func init() {
	const name = `github.com/quay/claircore/datastore/postgres/v2`
	tracer = otel.Tracer(name, trace.WithInstrumentationVersion(telemetrySchemaVersion))
	meter = otel.Meter(name, metric.WithInstrumentationVersion(telemetrySchemaVersion))

	methodCount = must(meter.Int64Counter("method.calls",
		metric.WithDescription("The number of calls for the method described by the method attribute."),
		metric.WithUnit("{call}"),
	))
	methodDuration = must(meter.Int64Histogram("method.call_time",
		metric.WithDescription("The duration of calls for the method described by the method attribute."),
		metric.WithUnit("ms"),
	))

	poolUsage = must(meter.Int64ObservableUpDownCounter("db.client.connections.usage",
		metric.WithDescription("The number of connections that are currently in state described by the state attribute."),
		metric.WithUnit("{connection}"),
	))
	poolIdleMax = must(meter.Int64UpDownCounter("db.client.connections.idle.max",
		metric.WithDescription("The maximum number of idle open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolIdleMin = must(meter.Int64UpDownCounter("db.client.connections.idle.min",
		metric.WithDescription("The minimum number of idle open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolMax = must(meter.Int64UpDownCounter("db.client.connections.max",
		metric.WithDescription("The maximum number of open connections allowed."),
		metric.WithUnit("{connection}"),
	))
	poolPending = must(meter.Int64ObservableUpDownCounter("db.client.connections.pending_requests",
		metric.WithDescription("The number of pending requests for an open connection, cumulative for the entire pool."),
		metric.WithUnit("{request}"),
	))
	poolTimeout = must(meter.Int64ObservableCounter("db.client.connections.timeouts",
		metric.WithDescription("The number of connection timeouts that have occurred trying to obtain a connection from the pool."),
		metric.WithUnit("{timeout}"),
	))
	poolCreateTime = must(meter.Int64Histogram("db.client.connections.create_time",
		metric.WithDescription("The time it took to create a new connection."),
		metric.WithUnit("ms"),
	))
	poolWaitTime = must(meter.Int64Histogram("db.client.connections.wait_time",
		metric.WithDescription("The time it took to obtain an open connection from the pool."),
		metric.WithUnit("ms"),
	))
	poolUseTime = must(meter.Int64Histogram("db.client.connections.use_time",
		metric.WithDescription("The time between borrowing a connection and returning it to the pool."),
		metric.WithUnit("ms"),
	))
}

// PgpidAttr is a helper for constructing an attribute for the provided
// connection's server PID.
func pgpidAttr(c *pgx.Conn) attribute.KeyValue {
	return attribute.Int("postgresql.pid", int(c.PgConn().PID()))
}

// Attributes used in this package.
var (
	attrRunRef     = attribute.Key("run.ref")
	attrUpdRunRef  = attribute.Key("run.updater.ref")
	attrUpdRunName = attribute.Key("run.updater.name")
)
