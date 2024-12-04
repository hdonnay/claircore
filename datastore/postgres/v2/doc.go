/*
Package postgres implements v2 of the claircore datastore interfaces.

# Indexer

tktk

# Contributing

Functions should use [pgxpool.Pool.AcquireFunc]/[pgx.BeginTxFunc] to make use of the observability helpers
(see [Configure] and [internal/o11y]).

SQL statements are embedded as string literals with the help of a program run via `go generate`.
This is done instead of using "embed" directly to be able to generate metadata alongside the queries.
See [NameLookup]/[TableLookup]/[OpLookup].

Read methods should generally follow this pattern:

	func (*S) GetKind(ctx context.Context, args any, token string) (iter.Seq2[Kind, error], func() string) {}

This means the method should take a pagination token as the last argument and return
an iterator and a function to return the pagination token for the most recently yielded value.
There are helpers to implement this in an efficient way;
see the [internal/cursor] and [internal/ringbuf] packages.
This method signature and helpers force queries to be written using keyset pagination,
which is needed for efficient queries.
This sort of method allows for efficient memory use in RPC situations:

	const breakSz = 102400
	func handler(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var b bytes.Buffer
		enc := jsontext.NewEncoder(&b)
		enc.WriteToken(jsontext.ArrayStart)
		seq, token := matcher.GetKind(ctx, r.FormValue("last"))
		for k, err := range seq {
			if err != nil {
				http.Error(w, http.StatusInternalServerError, err.Error())
				return
			}
			json.MarshalEncode(enc, k)
			if b.Len() >= breakSz {
				break
			}
		}
		enc.WriteToken(jsontext.ArrayEnd)
		w.Header().Set("Link", fmt.Sprintf("<.?last=%s>;rel=next", token()))
		io.Copy(w, &b)
	}

This package should try to avoid processing local types into SQL in methods directly.
Instead, leverage type mapping via [github.com/jackc/pgx/v5/pgtype].
See the existing code in this package (ending in "_types.go") and
the examples called out in the [pgtype] documentation.

# Tests

See the [test/integration] and [test/postgres] packages for integration and helper code.

If the type handling code is isolated correctly,
those tests should be verifying that values are being translated between Go and PostgreSQL correctly.
This means the method testing should only require a database to verify any concurrency semantics,
and could be mocked out for most testing.

Currently, this package uses a full PostgreSQL database because the harness already existed.
*/
package postgres

// BUG(hank) This package makes heavy usage of [runtime.SetFinalizer]. Keep an
// eye on the [AddCleanup] proposal and use it instead.
//
// [AddCleanup]: https://github.com/golang/go/issues/67535

// Style tip: use the "Func" methods on the Pool to get a scope for
// metrics/tracing for "free."

// Previous "updater" interface:
/*
EnrichmentUpdater

- UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability) (uuid.UUID, error)
- UpdateVulnerabilitiesIter(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulnIter VulnerabilityIter) (uuid.UUID, error)
- DeltaUpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []*claircore.Vulnerability, deletedVulns []string) (uuid.UUID, error)

These should be handled in the new updater type hierarchy: matcher_updater.go

- GetUpdateOperations(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error)
- GetLatestUpdateRefs(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error)
- GetLatestUpdateRef(context.Context, driver.UpdateKind) (uuid.UUID, error)
- DeleteUpdateOperations(context.Context, ...uuid.UUID) (int64, error)

TODO: matcher_updater.go

The first 3 can probably be consolidated.

- GetUpdateDiff(ctx context.Context, prev, cur uuid.UUID) (*driver.UpdateDiff, error)

TODO: matcher.go

- GC(ctx context.Context, keep int) (int64, error)

TODO: matcher.go

- Initialized(context.Context) (bool, error)

TODO: matcher.go

- RecordUpdaterStatus(ctx context.Context, updaterName string, updateTime time.Time, fingerprint driver.Fingerprint, updaterError error) error
- RecordUpdaterSetStatus(ctx context.Context, updaterSet string, updateTime time.Time) error

These should be handled via the updater type hierarchy: matcher_updater.go
*/

// Previous Vulnerability interface:
/*
// GetOpts provides instructions on how to match packages to vulnerabilities.
type GetOpts struct {
	// Matchers tells the Get method to limit the returned vulnerabilities by
	// the provided [driver.MatchConstraint]s.
	Matchers []driver.MatchConstraint
	// Debug asks the database layer to log extra information.
	//
	// Deprecated: This does nothing.
	Debug bool
	// VersionFiltering enables filtering based on the normalized versions in
	// the database.
	VersionFiltering bool
}

// Vulnerability is the interface for querying stored Vulnerabilities.
type Vulnerability interface {
	// Get finds the vulnerabilities which match each package provided in the
	// [IndexRecord]s. This may be a one-to-many relationship. A map of Package
	// ID to Vulnerabilities is returned.
	Get(ctx context.Context, records []*claircore.IndexRecord, opts GetOpts) (map[string][]*claircore.Vulnerability, error)
}

TODO -- need to think through what this should turn into.
See matcher_vulnerability.go

*/
