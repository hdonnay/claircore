package postgres

import "iter"

// Ringbuf is a generic ring buffer.
//
// A ringbuf is not safe for concurrent use.
type ringbuf[T any] struct {
	buf  []T
	head uint32
	tail uint32
}

// Init initializes the ring buffer to hold "sz" elements, reusing an already
// allocated backing slice if possible.
//
// "Sz" must be a positive power of two. Init will panic if not.
func (r *ringbuf[T]) Init(sz int) {
	if sz < 1 || (sz&(sz-1)) != 0 {
		panic("passed size is not a power of two")
	}
	r.head = 0
	r.tail = 0
	if cap(r.buf) < sz {
		r.buf = make([]T, sz)
	} else {
		r.buf = r.buf[:sz]
	}
}

// Mask is an implementation detail.
//
// It returns the appropriate index given the absolute position
func (r *ringbuf[T]) mask(i uint32) int { return int(i & uint32(len(r.buf)-1)) }

// Empty reports if the ring buffer is empty.
func (r *ringbuf[T]) Empty() bool { return r.head == r.tail }

// Full reports if the ring buffer is full.
func (r *ringbuf[T]) Full() bool { return r.Len() == r.Cap() }

// Len reports the current length of the ring buffer.
func (r *ringbuf[T]) Len() int { return int(r.tail - r.head) }

// Cap reports the capacity of the ring buffer.
//
// This is set by [Init] and does not change unless the ring buffer is
// re-initialized.
func (r *ringbuf[T]) Cap() int { return len(r.buf) }

// Push appends an element to the ring buffer and reports if it is still okay to
// push elements.
//
//	var buf ringbuf[int]
//	buf.Init(2)
//	for i:=0;buf.Push(i);i++ {}
//	fmt.Println(buf.Shift())
//	fmt.Println(buf.Shift())
func (r *ringbuf[T]) Push(v T) bool {
	if r.Full() {
		panic("push called on full ringbuf")
	}
	r.buf[r.mask(r.tail)] = v
	r.tail++
	return !r.Full()
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
// Yielded elements are removed from the buffer, as with [Shift].
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
// Yielded elements are removed from the buffer, as with [Pop].
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
