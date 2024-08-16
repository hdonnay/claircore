// Package cursor is process-side cursor implementation.
package cursor

import (
	"context"
	"errors"
	"iter"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sqids/sqids-go"

	"github.com/quay/claircore/internal/ringbuf"
)

var idCodec *sqids.Sqids

func init() {
	sq, err := sqids.New(sqids.Options{
		Alphabet:  `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._ ~0123456789`,
		MinLength: 3,
	})
	if err != nil {
		panic(err)
	}
	idCodec = sq
}

// Cursor is an process-side database cursor.
//
// This works by tracking the last ID returned via the range function and
// reporting it via [Cursor.PaginationToken].
//
// The provided [FillFunc] is used to populate instances of T from the database.
//
// A Cursor is not safe for use from multiple goroutines.
type Cursor[T any] struct {
	fill FillFunc[T]
	last pgtype.Int8
	size int
}

// FillFunc is a callback to populate "ids" and "ring", starting from the row
// indicated by "last".
//
// If "ring" is not fully populated after the function returns, it's assumed to
// signal the end of iteration. If "last" is not valid (reported via
// [pgtype.Int8.Valid]), iteration should start at the beginning.
//
// The returned function should be suitable to use as an argument to
// [pgxpool.AcquireFunc].
type FillFunc[T any] func(ctx context.Context, ids *ringbuf.Buf[pgtype.Int8], ring *ringbuf.Buf[T], last pgtype.Int8) (acquireFunc func(*pgxpool.Conn) error)

// New returns a cursor using the provided [FillFunc] and starting after the
// recorded indicated by "tok". The empty string indicates starting at the
// beginning.
func New[T any](fill FillFunc[T], tok string) *Cursor[T] {
	c := Cursor[T]{
		fill: fill,
	}
	if tok != "" {
		if ns := idCodec.Decode(tok); len(ns) != 0 {
			c.last = pgtype.Int8{
				Int64: int64(ns[0]),
				Valid: true,
			}
		}
	}
	return &c
}

// SetSize sets the pagination size.
//
// If unset, the page size will be guessed according to [ringbuf.GuessFunc].
func (c *Cursor[T]) SetSize(size int) {
	c.size = size
}

// All returns an iterator walking through objects of type "T", calling the
// provided [FillFunc] as needed and tracking the last ID returned via the
// iterator.
func (c *Cursor[T]) All(ctx context.Context, pool *pgxpool.Pool) iter.Seq2[T, error] {
	ring := ringbuf.GetBuf[T](c.size)
	ids := ringbuf.GetBuf[pgtype.Int8](c.size)
	return func(yield func(T, error) bool) {
		defer func() {
			ringbuf.PutBuf(ring)
			ringbuf.PutBuf(ids)
		}()
		done := false
		for {
			switch {
			case ring.Empty() && done:
				return
			case ring.Empty(): // Pull rows.
			default:
				op, _ := ring.Shift()
				c.last, _ = ids.Shift()
				if !yield(op, nil) {
					return
				}
				continue
			}

			// Use [pgxpool.AcquireFunc] to create a nice, contained scope.
			err := pool.AcquireFunc(ctx, c.fill(ctx, ids, ring, c.last))
			switch {
			case err == nil:
			case errors.Is(err, pgx.ErrNoRows):
				// Empty page; "done" will be set and the switch in the
				// yield loop will exit the function.
			default:
				var none T
				yield(none, err)
				return
			}
			done = !ring.Full()
		}
	}
}

// PaginationToken returns a token describing the last value returned by the
// [Cursor.All] iterator.
func (c *Cursor[T]) PaginationToken() string {
	tok, _ := idCodec.Encode([]uint64{uint64(c.last.Int64)})
	return tok
}
