package driver

import (
	"context"
	"iter"
	"net/http"
	"time"
	"unique"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/cvss"
)

type ConfigUnmarshaler func(any) error

type Updater interface {
	Update(context.Context, *http.Client, UpdateBuilder) error
}

type UpdateBuilder interface {
	// Meta:

	PreviousOp(ctx context.Context) (*UpdateMetadata, map[string]string, error)
	SetOpAttr(ctx context.Context, key, value string) error
	Build(ctx context.Context) error
	Abandon(ctx context.Context, reason error)

	// Advisories:

	// StatAdvisory ...
	StatAdvisory(ctx context.Context, id string) (bool, error)

	// ClearAdvisory ...
	ClearAdvisories(ctx context.Context) error
	// DeleteAdvisory ...
	DeleteAdvisory(ctx context.Context, id string) error
	// CreateAdvisory ...
	CreateAdvisory(ctx context.Context, id string) (AdvisoryBuilder, error)
	// UpdateAdvisory ...
	UpdateAdvisory(ctx context.Context, id string) (AdvisoryBuilder, error)

	// Artiacts:

	GetArtifact(ctx context.Context, h ArtifactHandle) (*ReadOnlyArtifact, error)

	// CreateArtifact ...
	CreateArtifact(ctx context.Context) (ArtifactBuilder, error)
}

type UpdateMetadata struct {
	ID [16]byte // UUID
	At time.Time
}

type Alias struct {
	Space unique.Handle[string]
	Name  string
}

type AdvisoryBuilder interface {
	Description(context.Context, string) error
	Issued(context.Context, time.Time) error
	Updated(context.Context, time.Time) error
	Links(context.Context, []string) error

	Self(context.Context, Alias) error
	Aliases(context.Context, []Alias) error

	AddArtifact(context.Context, ArtifactHandle) error
	RemoveArtifacts(context.Context, func(ArtifactHandle) bool) error

	Attrs(context.Context, iter.Seq2[string, string]) error

	Build(context.Context) error
	Abandon(ctx context.Context, reason error)
}

type ArtifactBuilder interface {
	// State sets the artifact state.
	//
	// This should be called first.
	State(context.Context, ArtifactState) error

	// Purl sets the purl identifier for the artifact.
	//
	// If available, this should be called no matter the state.
	Purl(context.Context, *packageurl.PackageURL) error
	// CPE sets the CPE Name for the artifact.
	//
	// If available, this should be called no matter the state.
	CPE(context.Context, cpe.WFN) error

	// EndOfLife ...
	//
	// This should only be called if the state was set to "end-of-life".
	// Implementations should error if called with the artifact in the incorrect
	// state.
	EndOfLife(context.Context, time.Time) error

	// VersionRange ...
	//
	// This should only be called if the state was set to "vulnerable" or
	// "unaffected".
	// Implementations should error if called with the artifact in the incorrect
	// state.
	VersionRange(context.Context, string) error
	// CVSSv3 ...
	//
	// This should only be called if the state was set to "vulnerable" or
	// "unaffected".
	// Implementations should error if called with the artifact in the incorrect
	// state.
	CVSSv3(context.Context, cvss.V3) error
	// CVSSv4 ...
	//
	// This should only be called if the state was set to "vulnerable" or
	// "unaffected".
	// Implementations should error if called with the artifact in the incorrect
	// state.
	CVSSv4(context.Context, cvss.V4) error
	// Severity ...
	Severity(_ context.Context, orig string, norm Severity) error

	// Attrs sets additional unstructured attributes.
	Attrs(context.Context, iter.Seq2[string, string]) error

	// Build finishes building the artifact representation.
	//
	// The reported handle is only valid for the current UpdateOperation.
	//
	// Implementations may delay additional checking to this step.
	// If this reports an error, the ArtifactBuilder is no longer usable and the
	// ID is not valid.
	Build(context.Context) (ArtifactHandle, error)
	// Abandon abandons the unbuilt artifact, with an optional reason.
	Abandon(ctx context.Context, reason error)
}

// ArtifactHandle is an identifier for an artifact that's only valid for the
// duration of UpdateOperationBuilder that it's created from.
type ArtifactHandle int64

type ArtifactState uint

const (
	ArtifactStateUnknown    ArtifactState = iota // unknown
	ArtifactStateVulnerable                      // vulnerable
	ArtifactStateUnaffected                      // unaffected
	ArtifactStateEndOfLife                       // end-of-life
)

type Severity uint

const (
	SeverityUnknown    Severity = iota // unknown
	SeverityNegligible                 // negligible
	SeverityLow                        // low
	SeverityMedium                     // medium
	SeverityHigh                       // high
	SeverityCritical                   // critical
)

type ReadOnlyArtifact struct {
	State ArtifactState
}
