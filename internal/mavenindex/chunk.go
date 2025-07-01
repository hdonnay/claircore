package mavenindex

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"iter"
	"strings"
	"time"
)

// Artifact is a type representing an artifact.
//
// It's meant to be used via [unique.Handle] to intern the strings.
type Artifact struct {
	GroupID    string
	ArtifactID string
}

// Record is a change to the index.
//
// If the [Record.SHA1] member is not nil, the Record describes an addition. If
// it is nil, it describes a removal.
type Record struct {
	Artifact
	Version string
	SHA1    []byte
}

// String implements [fmt.Stringer].
func (r *Record) String() string {
	var b strings.Builder

	if len(r.SHA1) == 0 {
		b.WriteString("- ")
	} else {
		b.WriteString("+ ")
	}
	b.WriteString(r.GroupID)
	b.WriteByte('.')
	b.WriteString(r.ArtifactID)
	b.WriteByte('@')
	b.WriteString(r.Version)

	if len(r.SHA1) != 0 {
		fmt.Fprintf(&b, " (%x)", r.SHA1)
	}

	return b.String()
}

// NewChunkReader sets up a [Record] reader over the contents of "r", which is
// assumed to be compressed.
//
// This function takes ownership of the passed [io.ReadCloser] and will close it
// when done.
func NewChunkReader(rc io.ReadCloser) (*ChunkReader, error) {
	const bufSz = 1 << 20
	z, err := gzip.NewReader(bufio.NewReaderSize(rc, bufSz))
	if err != nil {
		return nil, err
	}
	rd := bufio.NewReaderSize(z, bufSz)
	cleanup := []io.Closer{z, rc}
	ok := false
	defer func() {
		if ok {
			return
		}
		for _, c := range cleanup {
			c.Close()
		}
	}()

	v, err := rd.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("unable to read version: %w", err)
	}
	if got, want := int(v), 1; got != want {
		return nil, fmt.Errorf("unknown index format %d (need %d)", got, want)
	}
	b, err := rd.Peek(8)
	if err != nil {
		return nil, fmt.Errorf("unable to read timestamp: %w", err)
	}
	rd.Discard(8)
	ts := time.UnixMilli(int64(be.Uint64(b)))

	ok = true
	cr := ChunkReader{
		Version:   int(v),
		Timestamp: ts,
		cleanup:   cleanup,
		l:         newLexer(rd),
	}
	return &cr, nil
}

// ChunkReader reads an index chunk.
//
// A chunk may be a complete index or an incremental update.
type ChunkReader struct {
	Version   int
	Timestamp time.Time

	cleanup []io.Closer
	l       *lexer
}

// All returns an iterator of Add/Remove records contained in this index chunk.
func (cr *ChunkReader) All(ctx context.Context) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		defer func() {
			for _, c := range cr.cleanup {
				c.Close()
			}
		}()
		cr.l.All(ctx)(yield)
	}
}
