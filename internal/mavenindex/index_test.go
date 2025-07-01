package mavenindex

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

	var got RemoteState
	if err := got.Parse(f); err != nil {
		t.Error(err)
	}
	want := RemoteState{
		ID:        "central",
		Chain:     "1318453614498",
		Creation:  time.Unix(1339767448, 952_000_000),
		Published: time.Unix(1750558769, 877_000_000),
		Last:      891,
		Incremental: func() (r []int) {
			const n = 862
			for i := range 30 {
				r = append(r, n+i)
			}
			return r
		}(),
	}

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
