package i14n

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/semconv/v1.40.0/dbconv"
	"go.opentelemetry.io/otel/trace"
)

const (
	i14nName = `github.com/quay/claircore/datastore/postgres`

	appnameKey  = `application_name`
	poolnameKey = `pool_name`
)

var (
	tracer trace.Tracer
	meter  metric.Meter
)

func init() {
	tracer = otel.Tracer(i14nName,
		trace.WithInstrumentationAttributes(semconv.DBSystemNamePostgreSQL))
	meter = otel.Meter(i14nName,
		metric.WithInstrumentationAttributes(semconv.DBSystemNamePostgreSQL))
}

var initMetrics = sync.OnceValue(func() (err error) {
	idleMax, err = dbconv.NewClientConnectionIdleMax(meter)
	if err != nil {
		return err
	}
	idleMin, err = dbconv.NewClientConnectionIdleMin(meter)
	if err != nil {
		return err
	}
	connCreateTime, err = dbconv.NewClientConnectionCreateTime(meter)
	if err != nil {
		return err
	}
	connCount, err = dbconv.NewClientConnectionCount(meter)
	if err != nil {
		return err
	}
	connWaitTime, err = dbconv.NewClientConnectionWaitTime(meter)
	if err != nil {
		return err
	}
	connUseTime, err = dbconv.NewClientConnectionUseTime(meter)
	if err != nil {
		return err
	}
	opDuration, err = dbconv.NewClientOperationDuration(meter)
	if err != nil {
		return err
	}
	responseRows, err = dbconv.NewClientResponseReturnedRows(meter)
	if err != nil {
		return err
	}
	return nil
})

// Metrics
var (
	idleMax        dbconv.ClientConnectionIdleMax
	idleMin        dbconv.ClientConnectionIdleMin
	connCreateTime dbconv.ClientConnectionCreateTime
	connCount      dbconv.ClientConnectionCount
	connWaitTime   dbconv.ClientConnectionWaitTime
	connUseTime    dbconv.ClientConnectionUseTime
	opDuration     dbconv.ClientOperationDuration
	responseRows   dbconv.ClientResponseReturnedRows
)

// Configure configures tracing and metrics hooks on the [pgxpool.Config].
//
// This modifies its argument to make sure it can use any/all hooks needed.
func Configure(ctx context.Context, cfg *pgxpool.Config) error {
	if err := initMetrics(); err != nil {
		return err
	}
	attrs := []attribute.KeyValue{
		semconv.DBSystemNamePostgreSQL,
		semconv.DBNamespace(cfg.ConnConfig.Database),
		semconv.ServerAddress(cfg.ConnConfig.Host),
	}
	if _, ok := cfg.ConnConfig.RuntimeParams[poolnameKey]; !ok {
		u := url.URL{
			Scheme: `postgresql`,
			Host:   cfg.ConnConfig.Host,
			User:   url.User(cfg.ConnConfig.User),
			Path:   "/" + cfg.ConnConfig.Database,
			RawQuery: (url.Values{
				appnameKey: {cfg.ConnConfig.RuntimeParams[appnameKey]},
			}).Encode(),
		}
		if p := int(cfg.ConnConfig.Port); p != 0 {
			u.Host = net.JoinHostPort(u.Host, strconv.Itoa(p))
			attrs = append(attrs, semconv.ServerPort(p))
		}
		cfg.ConnConfig.RuntimeParams[poolnameKey] = u.String()
	}
	poolName := cfg.ConnConfig.RuntimeParams[poolnameKey]

	ct := &ConnectionTracer{name: poolName}
	tr := &multitracer.Tracer{
		ConnectTracers: []pgx.ConnectTracer{&ConnectionCreateTracer{
			name: poolName,
		}},
		QueryTracers: []pgx.QueryTracer{&OperationTracer{
			name:  poolName,
			attrs: attrs,
		}},
		PoolAcquireTracers: []pgxpool.AcquireTracer{
			ct,
			&ConnectionWaitTracer{
				name: poolName,
			},
		},
		PoolReleaseTracers: []pgxpool.ReleaseTracer{ct},
	}

	cfg.ConnConfig.Tracer = tr
	idleMin.Add(ctx, int64(cfg.MinIdleConns), poolName)
	idleMax.Add(ctx, int64(cfg.MaxConns), poolName)

	return nil
}
