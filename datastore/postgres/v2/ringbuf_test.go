package postgres

import (
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRingbuf(t *testing.T) {
	n := []int{1, 2, 3, 4, 5, 6, 7, 8}
	t.Run("Shift", func(t *testing.T) {
		var buf ringbuf[int]
		buf.Init(8)
		for _, v := range n {
			buf.Push(v)
		}
		got, want := slices.Collect(buf.All()), n
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})

	t.Run("Pop", func(t *testing.T) {
		var buf ringbuf[int]
		buf.Init(8)
		for _, v := range n {
			buf.Push(v)
		}
		want := slices.Clone(n)
		slices.Reverse(want)
		got := slices.Collect(buf.Backward())
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
	})
}
