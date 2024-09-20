package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/cvss"
	"github.com/quay/zlog"

	"github.com/quay/claircore/datastore/postgres/v2/internal/testutil"
	"github.com/quay/claircore/test/integration"
	pgtest "github.com/quay/claircore/test/postgres"
	"github.com/quay/claircore/updater/driver/v2"
)

func TestTypes(t *testing.T) {
	integration.NeedDB(t)
	t.Parallel()

	t.Run("Matcher", func(t *testing.T) {
		t.Parallel()
		ctx := zlog.Test(context.Background(), t)

		cfg := pgtest.TestMatcherDBv5(ctx, t)
		cfg = Configure(ctx, cfg)
		// Add a hook that prints out the actual query and arguments.
		testutil.PrintQueries(t, cfg)

		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()

		// Encode tests that the go types are translated into the expected SQL.
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

			t.Run("RemoveWrapper", func(t *testing.T) {
				t.Skip("TODO")
			})
		})

		// Scan tests that the SQL is translated correctly into go types.
		t.Run("Scan", func(t *testing.T) {
			ctx := zlog.Test(ctx, t)
			conn, err := pool.Acquire(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Release()

			t.Run("Error", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const query = `SELECT 'some error';`
				var got error
				want := errors.New("some error")
				err := conn.QueryRow(ctx, query).Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if !cmp.Equal(got, want, testutil.CmpOpts) {
					t.Fail()
				}
			})
			t.Run("Severity", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				for _, tc := range []struct {
					Query string
					Want  types.Severity
				}{
					{`SELECT 'Critical'::matcher_v2.Severity;`, types.Critical},
					{`SELECT 'High'::matcher_v2.Severity;`, types.High},
					{`SELECT 'Medium'::matcher_v2.Severity;`, types.Medium},
					{`SELECT 'Low'::matcher_v2.Severity;`, types.Low},
					{`SELECT 'Negligible'::matcher_v2.Severity;`, types.Negligible},
					{`SELECT 'Unknown'::matcher_v2.Severity;`, types.Unknown},
				} {
					var got types.Severity
					err := conn.QueryRow(ctx, tc.Query).Scan(&got)
					if err != nil {
						t.Error(err)
					}
					want := tc.Want
					t.Logf("got: %v, want: %v", got, want)
					if !cmp.Equal(got, want, testutil.CmpOpts) {
						t.Fail()
					}
				}
			})
			t.Run("PackageKind", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				for _, tc := range []struct {
					Query string
					Want  types.PackageKind
				}{
					{`SELECT 'binary'::matcher_v2.PackageKind;`, types.BinaryPackage},
					{`SELECT 'source'::matcher_v2.PackageKind;`, types.SourcePackage},
				} {
					var got types.PackageKind
					err := conn.QueryRow(ctx, tc.Query).Scan(&got)
					if err != nil {
						t.Error(err)
					}
					want := tc.Want
					t.Logf("got: %v, want: %v", got, want)
					if !cmp.Equal(got, want, testutil.CmpOpts) {
						t.Fail()
					}
				}
			})
			t.Run("UpdateOperation", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const query = `SELECT ROW('test', 'd03dff60-105b-4de2-ac71-d1971e0e8b50'::uuid, now(), true, '{}'::BYTEA, NULL);`
				var got driver.UpdateOperation
				want := driver.UpdateOperation{
					Updater:     "test",
					Ref:         uuid.MustParse(`d03dff60-105b-4de2-ac71-d1971e0e8b50`),
					Date:        time.Now(),
					Success:     true,
					Fingerprint: driver.Fingerprint(`{}`),
				}
				err := conn.QueryRow(ctx, query).Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %v, want: %v", got, want)
				if !cmp.Equal(got, want, testutil.CmpOpts) {
					t.Fail()
				}
			})
			t.Run("Fingerprint", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				const query = `SELECT '{"is":"json"}'::BYTEA;`
				var got driver.Fingerprint
				want := driver.Fingerprint(`{"is":"json"}`)
				err := conn.QueryRow(ctx, query).Scan(&got)
				if err != nil {
					t.Error(err)
				}
				t.Logf("got: %#q, want: %#q", got, want)
				if !cmp.Equal(got, want, testutil.CmpOpts) {
					t.Fail()
				}
			})
			t.Run("Architecture", func(t *testing.T) {
				ctx := zlog.Test(ctx, t)
				for _, tc := range []struct {
					Query string
					Want  driver.Architecture
				}{
					{`SELECT '386'::matcher_v2.Architecture;`, driver.Arch386},
					{`SELECT 'amd64'::matcher_v2.Architecture;`, driver.ArchAMD64},
					{`SELECT 'any'::matcher_v2.Architecture;`, driver.ArchAny},
					{`SELECT 'arm'::matcher_v2.Architecture;`, driver.ArchArm},
					{`SELECT 'arm64'::matcher_v2.Architecture;`, driver.ArchArm64},
					{`SELECT 'mips'::matcher_v2.Architecture;`, driver.ArchMips},
					{`SELECT 'mips64'::matcher_v2.Architecture;`, driver.ArchMips64},
					{`SELECT 'mips64le'::matcher_v2.Architecture;`, driver.ArchMips64LE},
					{`SELECT 'mipsle'::matcher_v2.Architecture;`, driver.ArchMipsLE},
					{`SELECT 'ppc64'::matcher_v2.Architecture;`, driver.ArchPPC64},
					{`SELECT 'ppc64le'::matcher_v2.Architecture;`, driver.ArchPPC64LE},
					{`SELECT 'riscv64'::matcher_v2.Architecture;`, driver.ArchRiscV64},
					{`SELECT 's390x'::matcher_v2.Architecture;`, driver.ArchS390X},
				} {
					var got driver.Architecture
					err := conn.QueryRow(ctx, tc.Query).Scan(&got)
					if err != nil {
						t.Error(err)
					}
					want := tc.Want
					t.Logf("got: %v, want: %v", got, want)
					if !cmp.Equal(got, want, testutil.CmpOpts) {
						t.Fail()
					}
				}
			})
		})
	})

	t.Run("Indexer", func(t *testing.T) {
		// ctx := zlog.Test(context.Background(), t)
		t.Skip("TODO")
		t.Parallel()
	})
}
