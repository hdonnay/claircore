package testutil

import (
	"iter"
	"testing"
)

// FilterErrs turns an [iter.Seq2[E, error]] into [iter.Seq[E]], with any error
// values causing the test "t" to fail.
func FilterErrs[E any](t testing.TB, seq iter.Seq2[E, error]) iter.Seq[E] {
	t.Helper()
	return func(yield func(E) bool) {
		t.Helper()
		i := -1
		for v, err := range seq {
			i++
			if err != nil {
				t.Errorf("%d'th element: %v", i, err)
				continue
			}
			if !yield(v) {
				return
			}
		}
	}
}

// ValuesErr is akin to [slices.Values], but returns an [iter.Seq2] with the
// second element being [error].
func ValuesErr[E any, S ~[]E](s S) iter.Seq2[E, error] {
	return func(yield func(E, error) bool) {
		for _, t := range s {
			if !yield(t, nil) {
				return
			}
		}
	}
}
