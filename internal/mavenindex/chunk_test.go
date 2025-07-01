package mavenindex

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/claircore/test"
)

// IndexWriter is a helper that emulates what the index writer does.
type indexWriter struct {
	*bufio.Writer
	z *gzip.Writer
	b []byte
}

func newIndexWriter(w io.Writer, v uint8, ts time.Time) *indexWriter {
	z := gzip.NewWriter(w)
	i := indexWriter{
		Writer: bufio.NewWriter(z),
		z:      z,
		b:      make([]byte, 8),
	}
	i.WriteByte(v)
	be.PutUint64(i.b, uint64(ts.UnixMilli()))
	i.Write(i.b)

	return &i
}

func (i *indexWriter) numFields(n int) {
	i.writeInt(n)
}

func (i *indexWriter) writeField(k, v string) {
	i.writeKey(k)
	i.writeValue(v)
}

func (i *indexWriter) writeKey(v string) {
	i.WriteByte(0xFF)
	i.writeShort(len(v))
	i.WriteString(v)
}

func (i *indexWriter) writeValue(v string) {
	i.writeInt(len(v))
	i.WriteString(v)
}

func (i *indexWriter) writeInt(n int) {
	be.PutUint32(i.b, uint32(n))
	i.Write(i.b[:4])
}

func (i *indexWriter) writeShort(n int) {
	be.PutUint16(i.b, uint16(n))
	i.Write(i.b[:2])
}

func TestChunkReader(t *testing.T) {
	generateChunk := func(t testing.TB, f *os.File) {
		fi, err := f.Stat()
		if err != nil {
			t.Fatal(err)
		}
		idx := newIndexWriter(f, 1, fi.ModTime())
		defer func() {
			if err := errors.Join(idx.Flush(), idx.z.Close()); err != nil {
				t.Errorf("unable to generate chunk: %v", err)
			}
		}()

		// Write 3 records:

		// An addition record:
		idx.numFields(3)
		idx.writeField(`n`, `testpackage`)
		idx.writeField(`u`, `group|artifact|version|NA|jar`)
		idx.writeField(`1`, `4e1243bd22c66e76c2ba9eddc1f91394e57f9f83`)

		// A skipped record
		idx.numFields(1)
		idx.writeField(`n`, `testpackage`)

		// A removal record
		idx.numFields(2)
		idx.writeField(`n`, `testpackage`)
		idx.writeField(`del`, `group|artifact|version|NA|jar`)
	}
	mustDecode := func(v string) []byte {
		b, err := hex.DecodeString(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	name := test.GenerateFixture(t, "chunk", time.Time{}, generateChunk)
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	cr, err := NewChunkReader(f)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background() // TODO(go1.25) Replace with [testing.T.Context].
	var got []Record
	for r, err := range cr.All(ctx) {
		if err != nil {
			t.Error(err)
			break
		}
		t.Log(&r)
		got = append(got, r)
	}

	want := []Record{
		{Artifact: Artifact{GroupID: "group", ArtifactID: "artifact"}, Version: "version", SHA1: mustDecode(`4e1243bd22c66e76c2ba9eddc1f91394e57f9f83`)},
		{Artifact: Artifact{GroupID: "group", ArtifactID: "artifact"}, Version: "version"},
	}
	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
