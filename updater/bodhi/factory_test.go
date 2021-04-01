package bodhi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/quay/zlog"
)

func TestFactory(t *testing.T) {
	const (
		filename = "testdata/releases.json"
		jsonTmpl = `{"api":%q}`
	)
	ctx := zlog.Test(context.Background(), t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	}))
	defer srv.Close()
	var local releases
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(f).Decode(&local); err != nil {
		t.Fatal(err)
	}
	want := make([]string, 0, len(local.Releases))
	for _, r := range local.Releases {
		if r.Pending() {
			continue
		}
		want = append(want, `bodhi-`+r.Name)
	}
	sort.Strings(want)
	cf := json.NewDecoder(strings.NewReader(fmt.Sprintf(jsonTmpl, srv.URL))).Decode

	fac := &Factory{}
	if err := fac.Configure(ctx, cf, srv.Client()); err != nil {
		t.Error(err)
	}
	s, err := fac.UpdaterSet(ctx)
	if err != nil {
		t.Error(err)
	}
	got := make([]string, 0, len(want))
	for _, u := range s.Updaters() {
		got = append(got, u.Name())
	}
	sort.Strings(got)

	if !cmp.Equal(got, want) {
		t.Error(cmp.Diff(got, want))
	}
}
