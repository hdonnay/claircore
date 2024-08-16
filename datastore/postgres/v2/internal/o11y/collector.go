package o11y

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.opentelemetry.io/otel/metric"
)

// CollectStats registers the stats exported by the [pgxpool.Pool] for
// asynchronous collection.
//
// The returned [metric.Registration] should be used to undo the collection when
// the pool is being shutdown.
func CollectStats(pool *pgxpool.Pool) (metric.Registration, error) {
	name := DBPoolName(pool.Config().ConnConfig)

	// db.client.connection.idle.max     not relevant: the pool allows this to go to the max
	// db.client.connection.idle.min     not relevant: the pool allows this to go to 0
	// db.client.connection.timeouts     not reported here
	// db.client.connection.create_time  not reported here
	// db.client.connection.wait_time    not reported here
	// db.client.connection.use_time     not reported here

	var f metric.Callback = func(ctx context.Context, obs metric.Observer) error {
		stat := pool.Stat()
		obs.ObserveInt64(dbClientConnectionCount, int64(stat.AcquiredConns()), metric.WithAttributes(name, DBConnStateUsed))
		obs.ObserveInt64(dbClientConnectionCount, int64(stat.IdleConns()), metric.WithAttributes(name, DBConnStateIdle))
		obs.ObserveInt64(dbClientConnectionMax, int64(stat.MaxConns()), metric.WithAttributes(name))
		obs.ObserveInt64(dbClientConnectionPendingRequests, stat.EmptyAcquireCount(), metric.WithAttributes(name))

		// stat.AcquireCount()
		// stat.AcquireDuration()
		// stat.CanceledAcquireCount()
		// stat.ConstructingConns()
		// stat.MaxIdleDestroyCount()
		// stat.MaxLifetimeDestroyCount()
		// stat.NewConnsCount()
		// stat.TotalConns()
		return nil
	}

	return meter.RegisterCallback(f,
		dbClientConnectionCount,
		dbClientConnectionMax,
		dbClientConnectionPendingRequests,
	)
}
