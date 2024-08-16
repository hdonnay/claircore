package postgres

import (
	"iter"

	"github.com/jackc/pgx/v5"
)

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
