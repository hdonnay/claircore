package postgres

import (
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
}

// Attributes used in this package.
var (
	attrRunRef     = attribute.Key("run.ref")
	attrUpdRunRef  = attribute.Key("run.updater.ref")
	attrUpdRunName = attribute.Key("run.updater.name")
)
