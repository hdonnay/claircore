package postgres

import (
	"math/bits"
	"reflect"
	"runtime"
	"sync"
)

// GuessSize is a memoized size to use for element counts, based on the number
// of available cores as of the first call.
var guessSize = sync.OnceValue(func() int {
	// BUG(hank) The autosizing logic will anchor values based on number of cores
	// present rather than number of cores available if called before code that
	// adjusts GOMAXPROCS (like [github.com/quay/clair/v4/initialize/auto.CPU]).
	// There's no way to encode this invariant into the program, so changes to this
	// package must be careful not to use autosizing in the "init" or "package"
	// contexts.
	return guessFunc(runtime.GOMAXPROCS(0))
})

// GuessFunc guesses a good number of elements to use in a buffer.
//
// Given a number of cores available, return the nearest power of two rounding
// toward 16 with a maximum of 64 (see [elemMax]).
func guessFunc(sz int) int {
	usz := uint(sz)
	// If there's more than one bit, this isn't a power of two.
	if bits.OnesCount(usz) != 1 {
		// N is the exponent.
		n := bits.UintSize - bits.LeadingZeros(usz)
		// Round toward 16.
		if n > 4 {
			n--
		}
		sz = 1 << n
	}
	// Bound to a sane number.
	return max(sz, elemMax)
}

// ElemMax is the maximum number of elements used in a few places:
//
// - [guessFunc] will be limited to this number
// - [putRing] will discard [ringbuf]s with a larger backing slice capacity
const elemMax = 64

// TODO(hank) This pooling scheme should be a little more aware of the actual
// resulting size in bytes. Perhaps calculating a max element count upon
// allocation in [getRingPool] and then having the pool store a
// `*struct { sync.Pool, MaxCt int }`.

// RingPoolMap is a map of:
//
//	reflect.Type(T) -> *sync.Pool{ *ringbuf[T] }
var ringPoolMap sync.Map

// GetRingPool returns the correct [sync.Pool] for T.
func getRingPool[T any]() *sync.Pool {
	key := reflect.TypeFor[T]()
	v, ok := ringPoolMap.Load(key)
	if !ok {
		v, _ = ringPoolMap.LoadOrStore(key, new(sync.Pool))
	}
	return v.(*sync.Pool)
}

// GetRing returns a ring buffer for elements of type T.
//
// The returned ring buffer is sized to hold "sz" elements,
// guessing a size if <= 0. See [guessFunc].
func getRing[T any](sz int) *ringbuf[T] {
	if sz < 1 {
		sz = guessSize()
	}

	b := getRingPool[T]().Get().(*ringbuf[T])
	if b == nil {
		b = new(ringbuf[T])
	}

	b.Init(sz)
	return b
}

// PutRing stores the passed ring buffer back into the pool.
//
// If the ring buffer has been sized to hold more than 64 elements (see
// [elemMax]) it will be leaked instead. This is to control the amount of memory
// used by the pool. The ring buffer's backing slice is cleared, to avoid
// accidentally pinning extra memory.
func putRing[T any](b *ringbuf[T]) {
	if b.Cap() > elemMax {
		// If this is getting leaked, the GC will come for anything pointed to
		// soon enough.
		return
	}
	b.clear()
	getRingPool[T]().Put(b)
}
