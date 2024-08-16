package o11y

import (
	"runtime/debug"
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	instName = `github.com/quay/claircore/datastore/postgres/v2`
	modName  = `github.com/quay/claircore`
)

var (
	tracer = otel.Tracer(instName, trace.WithInstrumentationVersion(findVersion()))
	meter  = otel.Meter(instName, metric.WithInstrumentationVersion(findVersion()))
)

var findVersion = sync.OnceValue(func() string {
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range buildInfo.Deps {
			if dep.Path == modName {
				return dep.Version
			}
		}
	}
	return "???"
})

// Recorded asynchronously, see [CollectStats].
var (
	dbClientConnectionCount           metric.Int64ObservableUpDownCounter
	dbClientConnectionMax             metric.Int64ObservableUpDownCounter
	dbClientConnectionPendingRequests metric.Int64ObservableUpDownCounter
)

// Recorded synchronously, see [Tracer].
var (
	dbClientConnectionTimeouts   metric.Int64Counter
	dbClientConnectionCreateTime metric.Float64Histogram // TODO
	dbClientConnectionWaitTime   metric.Float64Histogram // TODO
	dbClientConnectionUseTime    metric.Float64Histogram // TODO
)

func init() {
	var err error

	dbClientConnectionCount, err = meter.Int64ObservableUpDownCounter(semconv.DBClientConnectionCountName,
		metric.WithDescription(semconv.DBClientConnectionCountDescription), metric.WithUnit(semconv.DBClientConnectionCountUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionMax, err = meter.Int64ObservableUpDownCounter(semconv.DBClientConnectionMaxName,
		metric.WithDescription(semconv.DBClientConnectionMaxDescription), metric.WithUnit(semconv.DBClientConnectionMaxUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionPendingRequests, err = meter.Int64ObservableUpDownCounter(semconv.DBClientConnectionPendingRequestsName,
		metric.WithDescription(semconv.DBClientConnectionPendingRequestsDescription), metric.WithUnit(semconv.DBClientConnectionPendingRequestsUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionTimeouts, err = meter.Int64Counter(semconv.DBClientConnectionTimeoutsName,
		metric.WithDescription(semconv.DBClientConnectionTimeoutsDescription), metric.WithUnit(semconv.DBClientConnectionTimeoutsUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionCreateTime, err = meter.Float64Histogram(semconv.DBClientConnectionCreateTimeName,
		metric.WithDescription(semconv.DBClientConnectionCreateTimeDescription), metric.WithUnit(semconv.DBClientConnectionCreateTimeUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionWaitTime, err = meter.Float64Histogram(semconv.DBClientConnectionWaitTimeName,
		metric.WithDescription(semconv.DBClientConnectionWaitTimeDescription), metric.WithUnit(semconv.DBClientConnectionWaitTimeUnit))
	if err != nil {
		panic(err)
	}
	dbClientConnectionUseTime, err = meter.Float64Histogram(semconv.DBClientConnectionUseTimeName,
		metric.WithDescription(semconv.DBClientConnectionUseTimeDescription), metric.WithUnit(semconv.DBClientConnectionUseTimeUnit))
	if err != nil {
		panic(err)
	}
}
