package plan

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"buf.build/go/protovalidate"
	"github.com/google/go-cmp/cmp"
	"golang.org/x/tools/txtar"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	tocv1 "github.com/quay/claircore/internal/proto/gen/toc/v1"
	"github.com/quay/claircore/test"
)

func TestSelectors(t *testing.T) {
	ms, err := filepath.Glob(`testdata/*.txtar`)
	if err != nil {
		panic(err) // programmer error
	}
	for _, f := range ms {
		name := strings.TrimSuffix(filepath.Base(f), ".txtar")
		t.Run(name, RunSelectorFixture(f))
	}
}

func RunSelectorFixture(name string) func(*testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		t.Attr("fixture", name)
		ar, err := txtar.ParseFile(name)
		if err != nil {
			t.Fatalf("unable to open %q: %v", name, err)
		}

		var selsF, entsF, wantF *txtar.File
		for i := range ar.Files {
			f := &ar.Files[i]
			switch f.Name {
			case "selectors.json":
				selsF = f
			case "entries.json":
				entsF = f
			case "want.json":
				wantF = f
			}
		}
		if selsF == nil || entsF == nil || wantF == nil {
			t.Fatal("incomplete fixture")
		}

		var sels map[string]string
		if err := json.Unmarshal(selsF.Data, &sels); err != nil {
			t.Errorf("selectors: %v", err)
		}
		var want []uint64
		if err := json.Unmarshal(wantF.Data, &want); err != nil {
			t.Errorf("want: %v", err)
		}

		// Need to do a slightly more complicated dance for protobuf-based
		// messages.
		var tmp []json.RawMessage
		if err := json.Unmarshal(entsF.Data, &tmp); err != nil {
			t.Errorf("entries (json): %v", err)
		}
		ents := make([]*tocv1.TOCEntry, len(tmp))
		for i, data := range tmp {
			ents[i] = new(tocv1.TOCEntry)
			m := ents[i]
			if err := protojson.Unmarshal(data, m); err != nil {
				t.Errorf("entries (proto) #%02d: %v", i+1, err)
			}
			if err := protovalidate.Validate(m); err != nil {
				t.Errorf("entries (validate) #%02d: %v", i+1, err)
			}
		}

		ctx := test.Logging(t)
		if testing.Verbose() {
			r, err := os.OpenRoot(t.ArtifactDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { r.Close() })
			ctx = WithDebugOutput(ctx, r)
			defer func() {
				f, err := r.Open("entry_plan.binpb")
				if err != nil {
					t.Error(err)
					return
				}
				defer f.Close()
				rec, err := LoadPlanRecord(ctx, f)
				if err != nil {
					t.Error(err)
					return
				}
				t.Logf("expression: %+q", rec.Expr)
				t.Logf("names: %v", rec.Name)
				for i := range rec.Result {
					t.Logf("entry: %v", &rec.Result[i])
				}
			}()
		}
		s, err := NewEntrySelectors(ctx, sels)
		if err != nil {
			t.Fatal(err)
		}
		seq := s.EvalEntries(ctx, slices.Values(ents))

		name := make([]string, 0, len(ents))
		got := make([]uint64, 0, len(ents))
		for n, b := range seq {
			t.Logf("%s: %v", n, s.Names(b))
			name = append(name, n)
			got = append(got, b)
		}
		if got, want := len(got), len(ents); got != want {
			t.Errorf("got: %d results, input: %d entries", got, want)
		}
		if !cmp.Equal(got, want) {
			t.Error(cmp.Diff(got, want))
		}
		if testing.Verbose() {
		}
	}
}

func TestCompose(t *testing.T) {
	ctx := test.Logging(t)
	sels := map[string]string{
		"a": `entry.name != ""`,
		"b": `entry.name == ""`,
	}

	s, err := NewEntrySelectors(ctx, sels)
	if err != nil {
		t.Fatal(err)
	}
	const name = `somefile`
	ent := (tocv1.TOCEntry_builder{
		Name: proto.String(name),
	}).Build()
	seq := s.EvalEntries(ctx, slices.Values([]*tocv1.TOCEntry{ent}))
	res := maps.Collect(seq)
	b := res[name]
	t.Logf("%s: %064b", name, b)
	t.Logf("%s: %v", name, s.Names(b))
	t.Logf("%s: %v", name, s.Result(b))
}
