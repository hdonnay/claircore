package postgres

import "iter"

// Ringbuf is a generic ring buffer.
//
// Ring buffers are used in this package to provide caches for iterators over
// database objects. This package can tune latency (network and query overhead)
// against memory usage (reading objects into process memory) by pulling pages
// of objects into a ring buffer to supply an iterator.
//
// A ringbuf is not safe for concurrent use.
type ringbuf[T any] struct {
	// Buf is the backing slice. The slice's length is the ring buffer's
	// capacity, and the ring buffer's length is tracked with "head" and "tail".
	buf []T
	// Head and tail are "absolute" positions in the ring.
	head uint32
	tail uint32
}

// Init initializes the ring buffer to hold "sz" elements, reusing an already
// allocated backing slice if possible.
//
// "Sz" must be a positive power of two less than 2³¹−1. Init will panic if not.
//
// Adding elements to a full ring buffer or removing elements from an empty ring
// buffer will panic.
func (r *ringbuf[T]) Init(sz int) {
	// The power of two requirement is to be able to use a mask instead of a
	// modulo *AND* so that the math is correct on overflow. The extra bit
	// stolen from the indices allows for distinguishing between and empty and
	// full buffer.
	//
	// To prove this to yourself, think of an implementation with 4-bit indexes.
	// If the size is not limited to 2³−1 (= 7) but instead limited to 2⁴-1 (=
	// 15), the buffer will "reset" on wrap:
	//
	//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
	//	 |   |   |   |   |   |   |   |   |   |   |   |   |   |   |   |
	//	b⇈
	//	head: 0 tail: 0
	//
	// Write 12 bytes:
	//
	//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
	//	 | x | x | x | x | x | x | x | x | x | x | x | x |   |   |   |
	//	h↑                                              t↑
	//	head: 0 tail: 12
	//
	// If 3 more bytes were written, it would be impossible to tell if the
	// buffer is empty or full:
	//
	//	 0   1   2   3   4   5   6   7   8   9   a   b   c   d   e
	//	 | x | x | x | x | x | x | x | x | x | x | x | x | x | x | x |
	//	b⇈
	//	head: 0 tail: 0 (15 % 15)
	//
	// This could be tracked with a flag, but 1073741824 elements should really
	// be enough for our purposes.
	if sz < 2 || (sz&(sz-1)) != 0 || sz > ((1<<31)-1) {
		panic("invalid size")
	}
	r.head = 0
	r.tail = 0
	if r.Cap() < sz {
		r.buf = make([]T, sz)
	} else {
		r.buf = r.buf[:sz]
	}
}

// Mask is an implementation detail.
//
// It returns the appropriate index given the absolute position.
func (r *ringbuf[T]) mask(i uint32) int { return int(i & uint32(len(r.buf)-1)) }

// Clear is an implementation detail.
//
// It clears the entirety of the backing slice. This is useful to avoid pointers
// from a ringbuf that's in a pool.
func (r *ringbuf[T]) clear() { clear(r.buf[:cap(r.buf)]) }

// Empty reports if the ring buffer is empty.
func (r *ringbuf[T]) Empty() bool { return r.head == r.tail }

// Full reports if the ring buffer is full.
func (r *ringbuf[T]) Full() bool { return r.Len() == r.Size() }

// Len reports the current length of the ring buffer.
func (r *ringbuf[T]) Len() int { return int(r.tail - r.head) }

// Size reports the capacity of the ring buffer.
//
// This is set by [Init] and does not change unless the ring buffer is
// re-initialized.
func (r *ringbuf[T]) Size() int { return len(r.buf) }

// Cap returns the capacity of the underlying slice.
//
// That is, the ring buffer can be resized up to this value without
// reallocation.
func (r *ringbuf[T]) Cap() int { return cap(r.buf) }

// Push appends an element to the ring buffer and reports if it is still okay to
// push elements.
func (r *ringbuf[T]) Push(v T) bool {
	if r.Full() {
		panic("push called on full ringbuf")
	}
	r.buf[r.mask(r.tail)] = v
	r.tail++
	return !r.Full()
}

// Alloc appends a zero element to the ring buffer, then returns a pointer to it
// and reports if it is still okay to push elements.
//
// This API has some subtle constraints:
//
//  1. The caller cannot retain this pointer without a pointer to the originating
//     ring buffer. When using the pooling functions in this package, the element
//     will be zeroed when inserted into the pool.
//  2. A reader will receive a T, *not* a *T. As such, this API cannot be used to
//     share an object to a reader. To share a type S, the type parameter for the
//     ringbuf instance should be *S.
//
// This API trades one allocation and one copy for one copy (to zero the new
// element) and additional restrictions on the caller that can't be expressed in
// the Go type system.
func (r *ringbuf[T]) Alloc() (*T, bool) {
	if r.Full() {
		panic("push called on full ringbuf")
	}
	i := r.mask(r.tail)
	r.tail++
	clear(r.buf[i:r.mask(r.tail)])
	return &r.buf[i], !r.Full()
}

// Shift returns the oldest element and reports if it is still okay to remove
// elements.
func (r *ringbuf[T]) Shift() (v T, cont bool) {
	if r.Empty() {
		panic("shift called on empty ringbuf")
	}
	v = r.buf[r.mask(r.head)]
	r.head++
	return v, !r.Empty()
}

// Pop returns the newest element and reports if it is still okay to remove
// elements.
func (r *ringbuf[T]) Pop() (v T, cont bool) {
	if r.Empty() {
		panic("shift called on empty ringbuf")
	}
	v = r.buf[r.mask(r.tail-1)]
	r.tail--
	return v, !r.Empty()
}

// All returns an iterator over the contents of the buffer in FIFO order.
//
// Yielded elements are removed from the buffer, as with [Shift]. That is, the
// iterator is multiple use but mutates the state of the collection.
func (r *ringbuf[T]) All() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			v, ok := r.Shift()
			if !yield(v) || !ok {
				return
			}
		}
	}
}

// Backward returns an iterator over the contents of the buffer in LIFO order.
//
// Yielded elements are removed from the buffer, as with [Pop]. That is, the
// iterator is multiple use but mutates the state of the collection.
func (r *ringbuf[T]) Backward() iter.Seq[T] {
	return func(yield func(T) bool) {
		for {
			v, ok := r.Pop()
			if !yield(v) || !ok {
				return
			}
		}
	}
}
