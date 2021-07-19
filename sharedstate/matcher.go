package sharedstate

import (
	"context"

	"github.com/google/uuid"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

type Matcher interface {
	UpdateEnrichments(ctx context.Context, kind string, fingerprint driver.Fingerprint, enrichments []driver.EnrichmentRecord) (uuid.UUID, error)
	UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []claircore.Vulnerability) (uuid.UUID, error)

	GetUpdateOperations(context.Context, driver.UpdateKind, ...string) (map[string][]driver.UpdateOperation, error)
	DeleteUpdateOperations(context.Context, ...uuid.UUID) (int64, error)
	GetLatestUpdateRefs(context.Context, driver.UpdateKind) (map[string][]driver.UpdateOperation, error)
	GetLatestUpdateRef(context.Context, driver.UpdateKind) (uuid.UUID, error)
	GetUpdateDiff(ctx context.Context, prev uuid.UUID, cur uuid.UUID) (*driver.UpdateDiff, error)

	GC(ctx context.Context, keep int) (int64, error)
	Initialized(context.Context) (bool, error)

	GetVulnerability(context.Context, []claircore.IndexRecord, []driver.Matcher, bool) (map[string][]claircore.Vulnerability, error)
	GetEnrichment(ctx context.Context, kind string, tags []string) ([]driver.EnrichmentRecord, error)

	Close() error
}
