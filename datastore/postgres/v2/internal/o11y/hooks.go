package o11y

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TODO(hank) Record metrics

// BeforeConnect can be used as [pgxpool.Config.BeforeConnect].
func beforeConnect(ctx context.Context, cfg *pgx.ConnConfig) error {
	return nil
}

// AfterConnect can be used as [pgxpool.Config.AfterConnect].
func afterConnect(ctx context.Context, conn *pgx.Conn) error {
	return nil
}

// BeforeClose can be used as [pgxpool.Config.BeforeClose].
func beforeClose(conn *pgx.Conn) {}

// BeforeAcquire can be used as [pgxpool.Config.BeforeAcquire].
func beforeAcquire(ctx context.Context, conn *pgx.Conn) bool {
	return true
}

// AfterRelease can be used as [pgxpool.Config.AfterRelease].
func afterRelease(conn *pgx.Conn) bool {
	return true
}

// SetHooks modifies the passed [pgxpool.Config] to call this package's
// observability hooks.
//
// Any existing hooks will still be called.
func SetHooks(cfg *pgxpool.Config) {
	// Connection hooks:
	if f := cfg.BeforeConnect; f != nil {
		cfg.BeforeConnect = func(ctx context.Context, cfg *pgx.ConnConfig) error {
			return errors.Join(beforeConnect(ctx, cfg), f(ctx, cfg))
		}
	} else {
		cfg.BeforeConnect = beforeConnect
	}
	if f := cfg.AfterConnect; f != nil {
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			return errors.Join(afterConnect(ctx, conn), f(ctx, conn))
		}
	} else {
		cfg.AfterConnect = afterConnect
	}
	if f := cfg.BeforeClose; f != nil {
		cfg.BeforeClose = func(conn *pgx.Conn) {
			beforeClose(conn)
			f(conn)
		}
	} else {
		cfg.BeforeClose = beforeClose
	}

	// Pooling hooks:
	if f := cfg.BeforeAcquire; f != nil {
		cfg.BeforeAcquire = func(ctx context.Context, conn *pgx.Conn) bool {
			// Make sure to call both functions.
			// The obvious one-liner would allow short-circuiting.
			a, b := beforeAcquire(ctx, conn), f(ctx, conn)
			return a && b
		}
	} else {
		cfg.BeforeAcquire = beforeAcquire
	}
	if f := cfg.AfterRelease; f != nil {
		cfg.AfterRelease = func(conn *pgx.Conn) bool {
			// Make sure to call both functions.
			// The obvious one-liner would allow short-circuiting.
			a, b := afterRelease(conn), f(conn)
			return a && b
		}
	} else {
		cfg.AfterRelease = afterRelease
	}
}
