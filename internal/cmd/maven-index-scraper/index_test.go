package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"net/http"
	"net/url"
	"os"
	"testing"
)

func TestIndexParse(t *testing.T) {
	f, err := os.Open(`testdata/nexus-maven-repository-index.properties`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	var i Index
	if err := i.Parse(f); err != nil {
		t.Error(err)
	}

	t.Logf("%#v", i)
}

func TestIndexReader(t *testing.T) {
	ctx := context.Background()
	dir := os.DirFS(`testdata`)
	ir, err := NewIndexReader(ctx, nil, NewFSResource(dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Log("incremental?", ir.CanIncremental())
}

func TestLiveIndexReader(t *testing.T) {
	ctx := context.Background()
	u, err := url.Parse(`https://repo.maven.apache.org/maven2/.index/`)
	if err != nil {
		t.Fatal(err)
	}
	remote := NewHTTPResource(http.DefaultClient, u)
	ir, err := NewIndexReader(ctx, nil, remote)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("incremental?", ir.CanIncremental())

	n := 100
	for cr, err := range ir.Chunks(ctx) {
		if err != nil {
			t.Error(err)
			continue
		}

		for r, err := range cr.JARs() {
			if err != nil {
				t.Error(err)
			}
			t.Logf("%#v", &r)
			n--
			if n == 0 {
				break
			}
		}
	}
}

func TestChunkReader(t *testing.T) {
	f, err := os.Open(`testdata/nexus-maven-repository-index.891.gz`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})

	z, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := z.Close(); err != nil {
			t.Error(err)
		}
	})

	cr, err := NewChunkReader(z)
	if err != nil {
		t.Fatal(err)
	}
	n := 20
	for r, err := range cr.JARs() {
		if err != nil {
			t.Error(err)
		}
		t.Logf("%#v", &r)
		n--
		if n == 0 {
			break
		}
	}
}
