package delim

import (
	"bufio"
	"bytes"
	"io"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/apipb"
)

func TestEndToEnd(t *testing.T) {
	opt := protocmp.Transform()
	// This uses the "google.protobuf.api.Api" type only because it's bundled
	// with the google.golang.org/protobuf module.
	in := &apipb.Api{
		Name:    "test.v1",
		Version: "1.0",
		Edition: "2023",
	}
	want := proto.Clone(in)
	t.Logf("txtpb:\n%s", prototext.Format(in))
	est := proto.Size(in)
	est += int(protowire.SizeVarint(uint64(est)))
	t.Logf("reported size: %d", est)
	var buf bytes.Buffer
	buf.Grow(est)

	testcase := func(t *testing.T, r io.Reader, w io.Writer) {
		buf.Reset()

		n, err := MarshalTo(w, in)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("write OK (wrote: %d)", n)
		if bw, ok := w.(*bufio.Writer); ok {
			if err := bw.Flush(); err != nil {
				t.Error(err)
			}
		}

		got := new(apipb.Api)
		if err := UnmarshalFrom(r, got); err != nil {
			t.Fatal(err)
		}
		t.Log("read  OK")

		if !cmp.Equal(got, want, opt) {
			t.Error(cmp.Diff(got, want, opt))
		}
	}

	t.Run("Buffer", func(t *testing.T) {
		testcase(t, &buf, &buf)
	})
	t.Run("BufioRead", func(t *testing.T) {
		testcase(t, bufio.NewReader(&buf), &buf)
		t.Run("Small", func(t *testing.T) {
			// Undersizing the read buffer emulates having a very large message.
			r := bufio.NewReaderSize(&buf, 16)
			t.Logf("buffer size: %d", r.Size())
			testcase(t, r, &buf)
		})
	})
	t.Run("BufioWrite", func(t *testing.T) {
		testcase(t, &buf, bufio.NewWriter(&buf))
		t.Run("Small", func(t *testing.T) {
			// Undersizing the write buffer emulates having a very large message.
			w := bufio.NewWriterSize(&buf, 16)
			t.Logf("buffer size: %d", w.Size())
			testcase(t, &buf, w)
		})
	})
}
