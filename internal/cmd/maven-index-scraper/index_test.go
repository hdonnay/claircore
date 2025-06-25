package main

import (
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

	var i RemoteState
	if err := i.Parse(f); err != nil {
		t.Error(err)
	}

	t.Logf("%#v", i)
}
