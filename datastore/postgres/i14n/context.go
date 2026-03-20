package i14n

import (
	"context"
	"time"
)

type ctxkey uint

const (
	connectCreateTiming ctxkey = iota
	connectAcquireTiming
	operationTiming
)

func withDurationStart(ctx context.Context, key ctxkey) context.Context {
	return context.WithValue(ctx, key, time.Now())
}

func durationFromContext(ctx context.Context, key ctxkey) time.Duration {
	return time.Since(ctx.Value(key).(time.Time))
}
