package postgres

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

TODO

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
