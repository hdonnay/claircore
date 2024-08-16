package postgres

import (
	"context"
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/cvss"
	"github.com/quay/zlog"

	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/updater/driver/v2"
)

func testMust[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestTypes(t *testing.T) {
	integration.NeedDB(t)
	t.Parallel()

	t.Run("Matcher", func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(context.Background(), t)

		cfg := pgtest.TestMatcherDBv5(ctx, t)
		cfg = Configure(ctx, cfg)
		// Add a hook that prints out the actual query and arguments.
		testingHooks(t, cfg)

		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()

		// Encode tests that
		t.Run("Encode", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Release()

			// Simple SQL for types that are stored in text form.
			const eqAsText = `SELECT $1::TEXT = $2::TEXT;`

			t.Run("CPE", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				wfn, err := cpe.UnbindFS(`cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`)
				if err != nil {
					t.Fatal(err)
				}
				got, want := false, true
				err = conn.QueryRow(ctx, eqAsText, &wfn, wfn.BindFS()).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})

			t.Run("CVSS", func(t *testing.T) {
				runOne := func(in string, vec any) func(*testing.T) {
					return func(t *testing.T) {
						t.Helper()
						ctx := zlog.Test(ctx, t)
						got, want := false, true
						err := conn.QueryRow(ctx, eqAsText, vec, in).
							Scan(&got)
						if err != nil {
							t.Error(err)
						}
						t.Logf("got: %v, want: %v", got, want)
						if got != want {
							t.Fail()
						}
					}
				}

				const v4in = `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`
				v4vec, err := cvss.ParseV4(v4in)
				if err != nil {
					t.Error(err)
				}
				const v3in = `CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N`
				v3vec, err := cvss.ParseV3(v3in)
				if err != nil {
					t.Error(err)
				}
				const v2in = `AV:N/AC:L/Au:N/C:N/I:N/A:C`
				v2vec, err := cvss.ParseV2(v2in)
				if err != nil {
					t.Error(err)
				}
				if t.Failed() {
					return
				}

				t.Run("V4", runOne(v4in, &v4vec))
				t.Run("V3", runOne(v3in, &v3vec))
				t.Run("V2", runOne(v2in, &v2vec))
			})

			// Complex types:
			t.Run("VersionRange", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				var err error
				const check = `SELECT $1::matcher_v2.VersionRange = matcher_v2.VersionRange(NULL, $2::TEXT[], '(]');`
				v := driver.VersionRange{
					Lower: driver.VersionEndpoint{},
					Upper: driver.VersionEndpoint{
						Components: []string{`1`, `0`, `0`},
						Inclusive:  true,
					},
				}

				got, want := false, true
				err = conn.QueryRow(ctx, check, &v, []string{"0000000001", "0000000000", "0000000000"}).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})
			t.Run("VersionMultiRange", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				var err error
				const check = `SELECT $1::matcher_v2.VersionMultiRange =
					matcher_v2.VersionMultiRange(matcher_v2.VersionRange(NULL, $2::TEXT[], '(]'), matcher_v2.VersionRange($3::TEXT[], $4::TEXT[], '[)'));`
				v := []driver.VersionRange{
					{
						Lower: driver.VersionEndpoint{},
						Upper: driver.VersionEndpoint{
							Components: []string{`1`, `0`, `0`},
							Inclusive:  true,
						},
					},
					{
						Lower: driver.VersionEndpoint{
							Components: []string{`1`, `99`, `0`},
							Inclusive:  true,
						},
						Upper: driver.VersionEndpoint{
							Components: []string{`2`, `0`, `0`},
						},
					},
				}

				got, want := false, true
				err = conn.QueryRow(ctx, check, v,
					/* NULL, */
					[]string{"0000000001", "0000000000", "0000000000"},
					[]string{"0000000001", "0000000099", "0000000000"},
					[]string{"0000000002", "0000000000", "0000000000"}).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})

			// Row types:

			t.Run("Attr", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const check = `SELECT EXISTS (SELECT 1 FROM (SELECT $1::matcher_v2_import.attr AS input)
				WHERE
					(input).mediatype = $2::TEXT AND
					(input).data = $3::jsonb
				);`
				a := driver.Attr{
					Kind:  `applicaiton/vnd.claircore.attrTest+json`,
					Value: json.RawMessage(`{"test": true}`),
				}
				got, want := false, true
				err := conn.QueryRow(ctx, check, &a, a.Kind, string(a.Value)).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})

			t.Run("Advisory", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const check = `SELECT EXISTS (SELECT 1 FROM (SELECT $1::matcher_v2_import.advisory AS input)
				WHERE
					(input).name = $2::TEXT AND
					(input).issued = $3::TIMESTAMPTZ AND
					(input).summary = $4::TEXT AND
					(input).description = $5::TEXT AND
					(input).uri = $6::TEXT AND
					(input).severity = $7::TEXT AND
					(input).normalized_severity = $8::matcher_v2.Severity
				);`
				a := driver.Advisory{
					AdvisoryName: driver.AdvisoryName{
						Name: "TEST-0001",
					},
					Issued:      time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC),
					Summary:     "summary",
					Description: "description",
					URI:         "http://example.com/",
					Severity: driver.Severity{
						Upstream:   "nbd",
						Normalized: types.Low,
					},
				}
				got, want := false, true
				err := conn.QueryRow(ctx, check, &a,
					a.Name, a.Issued, a.Summary, a.Description, a.URI, a.Severity.Upstream, a.Severity.Normalized.String()). // Use string to avoid the Severity path.
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})

			t.Run("Reference", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const check = `SELECT EXISTS (SELECT 1 FROM (SELECT $1::matcher_v2_import.reference AS input)
				WHERE
					(input).namespace = $2::TEXT AND
					(input).name = $3::TEXT AND
					(input).uri = $4::TEXT[]
				);`
				r := driver.Reference{
					Namespace: "TEST",
					Name:      "0001",
					URI: []string{
						"http://example.com/",
						"http://example.com/test-0001",
					},
				}
				got, want := false, true
				err := conn.QueryRow(ctx, check, &r, r.Namespace, r.Name, r.URI).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})

			t.Run("Package", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const check = `SELECT EXISTS (SELECT 1 FROM (SELECT $1::matcher_v2_import.package AS input)
				WHERE
					(input).name = $2::TEXT AND
					(input).kind = $3::matcher_v2.PackageKind AND
					(input).arch = $4::matcher_v2.Architecture[] AND
					(input).vulnerable_range = $5::matcher_v2.VersionMultiRange AND
					(input).version_upstream = $6::TEXT[] AND
					(input).version_kind = $7::TEXT AND
					(input).purl = $8::TEXT AND
					(input).cpe = $9::TEXT
				);`
				wfn, err := cpe.UnbindFS(`cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`)
				if err != nil {
					t.Fatal(err)
				}
				u, err := url.Parse("rpm:example/hello")
				if err != nil {
					t.Fatal(err)
				}
				p := driver.Package{
					Name: "hello",
					PURL: u,
					CPE:  &wfn,
					Version: driver.Versions{
						Kind:     "semver",
						Upstream: []string{">=0.1.0,<1.0.0"},
						Ranges: []driver.VersionRange{
							{
								Lower: driver.VersionEndpoint{Components: []string{"0", "1", "0"}, Inclusive: true},
								Upper: driver.VersionEndpoint{Components: []string{"1", "0", "0"}},
							},
						},
					},
					Arch: []driver.Architecture{driver.ArchAMD64, driver.ArchArm64},
					Kind: types.BinaryPackage,
				}
				got, want := false, true
				err = conn.QueryRow(ctx, check, &p,
					p.Name, p.Kind, p.Arch, p.Version.Ranges, p.Version.Upstream, p.Version.Kind, p.PURL.String(), p.CPE.BindFS()).
					Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if got != want {
					t.Fail()
				}
			})
		})

		t.Run("Scan", func(t *testing.T) {
			t.Skip("TODO")
		})
	})

	t.Run("Indexer", func(t *testing.T) {
		// ctx := zlog.Test(context.Background(), t)
		t.Skip("TODO")
		t.Parallel()
	})
}
