package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"

	"github.com/jackc/pgx/v5"
	"github.com/quay/zlog"
)

type txStart interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func beginTxFunc(ctx context.Context, c txStart, opts pgx.TxOptions, f func(context.Context, pgx.Tx) error) error {
	tx, err := c.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to start transaction: %w", err)
	}
	defer func() {
		switch err := tx.Rollback(ctx); {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrTxClosed):
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("error rolling back transaction")
		}
	}()

	if err := f(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type copyAdapter[T any] struct {
	next func() (T, error, bool)
	stop func()

	val T
	tf  func([]any, T) error

	err error
	row []any
}

var _ pgx.CopyFromSource = (*copyAdapter[struct{}])(nil)

func newCopyAdapter[T any](width int, seq iter.Seq2[T, error], tf func([]any, T) error) *copyAdapter[T] {
	next, stop := iter.Pull2(seq)
	return &copyAdapter[T]{
		next: next,
		stop: stop,
		tf:   tf,
		row:  make([]interface{}, width),
	}
}

func (src *copyAdapter[T]) Next() (ok bool) {
	src.val, src.err, ok = src.next()
	return ok
}

func (src *copyAdapter[T]) Values() ([]interface{}, error) {
	if src.err != nil {
		return nil, src.err
	}
	if err := src.tf(src.row, src.val); err != nil {
		return nil, err
	}
	return src.row, nil
}

func (src *copyAdapter[T]) Err() error {
	src.stop()
	return nil
}
