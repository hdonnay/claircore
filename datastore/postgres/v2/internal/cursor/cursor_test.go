package cursor

import (
	"context"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/internal/ringbuf"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
)

func TestFill(t *testing.T) {
	integration.NeedDB(t)

	want := make([]int64, 24)
	for i := range want {
		want[i] = int64(i)
	}
	callCt := 0
	fill := func(ctx context.Context, id *ringbuf.Buf[pgtype.Int8], ring *ringbuf.Buf[int64], last pgtype.Int8) func(*pgxpool.Conn) error {
		var start int64 = -1
		if last.Valid {
			start = last.Int64
		}
		start++
		stop := int64(len(want) - 1) // PostgreSQL bounds are inclusive.
		return func(conn *pgxpool.Conn) error {
			defer func() {
				callCt++
			}()
			rows, err := conn.Query(ctx, `SELECT * FROM generate_series($1::bigint, $2::bigint);`, start, stop)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				v, _ := id.Alloc()
				if err := rows.Scan(v); err != nil {
					return err
				}
				if !ring.Push(v.Int64) {
					break
				}
			}
			return nil
		}
	}

	ctx := zlog.Test(context.Background(), t)
	cfg := pgtest.TestDBv5(ctx, t)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	cur := New(fill, "")
	cur.SetSize(16)

	got := make([]int64, 0, len(want))
	for v, err := range cur.All(ctx, pool) {
		if err != nil {
			t.Error(err)
			continue
		}

		got = append(got, v)
	}

	if !gocmp.Equal(got, want) {
		t.Error(gocmp.Diff(got, want))
	}
	if got, want := callCt, 2; got != want {
		t.Errorf("bad call count: got: %v, want: %v", got, want)
	}
}
