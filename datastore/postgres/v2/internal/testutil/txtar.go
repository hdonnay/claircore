package testutil

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/textproto"
	"testing"

	"golang.org/x/tools/txtar"
)

// Helpers for working with txtar files.

// LoadJSON attempts to read all the top-level JSON values in "r".
func LoadJSON[T any](t testing.TB, r io.Reader) iter.Seq2[T, error] {
	t.Helper()
	dec := json.NewDecoder(r)
	return func(yield func(T, error) bool) {
		for i := 1; ; i++ {
			var v T
			err := dec.Decode(&v)
			switch {
			case err == nil:
			case errors.Is(err, io.EOF):
				return
			default:
				t.Errorf("JSON value %d: %v", i, err)
			}
			if !yield(v, err) {
				return
			}
		}
	}
}

// LoadHeaders loads the [txtar.Archive.Comment] as MIME-style headers.
func LoadHeaders(t testing.TB, ar *txtar.Archive) textproto.MIMEHeader {
	t.Helper()
	rd := io.MultiReader(bytes.NewReader(ar.Comment), bytes.NewReader([]byte("\n\n")))
	tp := textproto.NewReader(bufio.NewReader(rd))
	hdr, err := tp.ReadMIMEHeader()
	switch {
	case err == nil:
	case errors.Is(err, io.EOF):
	default:
		t.Fatal(err)
	}
	return hdr
}
