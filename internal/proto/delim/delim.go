// Package delim is analogous to [protodelim], but uses buffer pooling.
//
// [protodelim]: https://pkg.go.dev/google.golang.org/protobuf/encoding/protodelim
package delim

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// Message size constants.
const (
	// New buffers have at least this capacity.
	InitialMessageSize = 1 << 20
	// Buffers beyond this size are not returned to the pool.
	MaxMessageSize = 4 << 20
)

var (
	marshal   = proto.MarshalOptions{}
	unmarshal = proto.UnmarshalOptions{}
)

// MarshalTo writes a varint size-delimited wire-format message to w.
func MarshalTo(w io.Writer, m proto.Message) (int, error) {
	var err error
	msz := uint64(proto.Size(m))

	// Optimization: if writing to a [bufio.Writer], attempt to use the buffer
	// space.
	if bw, ok := w.(*bufio.Writer); ok {
		szsz := protowire.SizeVarint(msz)
		need := szsz + int(msz)
		if avail := bw.Available(); need < avail {
			b := bw.AvailableBuffer()
			b = protowire.AppendVarint(b, msz)
			b, err = marshal.MarshalAppend(b, m)
			if err != nil {
				return 0, err
			}
			return bw.Write(b)
		}
	}

	// "Normal" path: get a buffer and populate it.
	b := getBuf()
	defer putBuf(b)
	*b = protowire.AppendVarint(*b, msz)
	*b, err = marshal.MarshalAppend(*b, m)
	if err != nil {
		return 0, err
	}
	return w.Write(*b)
}

// UnmarshalFrom parses and consumes a varint size-delimited wire-format message
// from r with the default options. The provided message must be mutable (e.g.,
// a non-nil pointer to a message).
func UnmarshalFrom(r io.Reader, m proto.Message) error {
	// Optimization: use the already-populated buffer if possible.
	br, bufok := r.(*bufio.Reader)

	// Can't defer a putBuf call here because this could end up pointing to a
	// slice owned by a [bufio.Reader].
	var b *[]byte

	// Read in the message size.
	var sz int
	if bufok {
		b, err := br.Peek(binary.MaxVarintLen64)
		if err != nil && len(b) < 1 {
			// Shortest possible encode would be an "empty" frame:
			//     [ 00 ]
			//
			// Any "normal" message used by the fastimport package should have a
			// non-zero size, but may still be <128 bytes.
			return fmt.Errorf("peeking msg size (got: %d, want: %d): %w", len(b), binary.MaxVarintLen64, err)
		}
		msz, n := protowire.ConsumeVarint(b)
		br.Discard(n)
		sz = int(msz)
		// If we know that the message can't fit into the internal buffer,
		// short-circuit even trying.
		bufok = sz <= br.Size()
	} else {
		b = getBuf()
		defer putBuf(b)
		*b = (*b)[:binary.MaxVarintLen64]
		if _, err := io.ReadFull(r, *b); err != nil {
			return fmt.Errorf("reading msg size: %w", err)
		}
		msz, n := protowire.ConsumeVarint(*b)
		*b = slices.Delete(*b, 0, n)
		// Adjust "sz" because the head of the buffer already contains some data.
		sz = int(msz) - len(*b)
	}

	// Read in the message.
	var err error
	switch {
	case bufok && b != nil:
		// If we had a bufio.Reader, it's impossible to have already pulled a
		// pooled buffer.
		panic("unreachable")
	case !bufok && sz == 0:
		// We don't need additional data, the message was small enough to fit
		// into the encoded size read.
	case bufok && b == nil:
		// We know that Peek cannot return [bufio.ErrBufferFull], so any error
		// is a "real" error.
		var p []byte
		p, err := br.Peek(sz)
		if err != nil {
			return fmt.Errorf("peeking msg data (got: %d, want: %d): %w", len(p), sz, err)
		}
		defer br.Discard(sz)
		b = &p
	case !bufok && b == nil:
		// If the message is too big for the backing buffer, pull a pooled
		// buffer and fallthrough to the normal path.
		b = getBuf()
		defer putBuf(b)
		fallthrough
	case !bufok && b != nil:
		// Assume the buffer may have data in it.
		off := len(*b)
		*b = slices.Grow(*b, sz)[:off+sz]
		_, err = io.ReadFull(r, (*b)[off:])
	}
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
		return io.ErrUnexpectedEOF
	default:
		return err
	}

	// Unmarshal the message.
	return unmarshal.Unmarshal(*b, m)
}

// Bufs is the pool for [getBuf] and [putBuf].
var bufs sync.Pool

// GetBuf pulls a buffer from the pool.
func getBuf() *[]byte {
	if v := bufs.Get(); v != nil {
		return v.(*[]byte)
	}
	b := make([]byte, 0, InitialMessageSize)
	return &b
}

// PutBuf puts a buffer back into the pool iff b != nil.
func putBuf(b *[]byte) {
	if b == nil || cap(*b) > MaxMessageSize {
		return
	}
	*b = (*b)[:0]
	bufs.Put(b)
}
