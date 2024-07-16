package driver

import (
	"archive/zip"
	"context"
	"io/fs"
	"iter"
	"net/http"
)

// Configs is a map of name to ConfigUnmarshaler.
//
// It's used for runtime configuration in the Updater.
type Configs func(string) (ConfigUnmarshaler, bool)

// ConfigUnmarshaler can be thought of as an Unmarshal function with the byte
// slice provided, or a Decode function.
//
// The function should populate a passed struct with any configuration
// information.
type ConfigUnmarshaler func(interface{}) error

// UpdaterFactory is called to construct new Updaters.
type UpdaterFactory interface {
	// Name is used to determine what configuration to use when calling Create.
	Name() string
	// Create is called whenever Updaters are needed to run.
	//
	// The Updater controller makes no assumptions about the lifecycle of the
	// updaters, so implementations may construct new objects on every call, or
	// create a set once and return it repeatedly.
	Create(context.Context, ConfigUnmarshaler) ([]Updater, error)
}

// Updater is the interface for fetching security advisory information.
//
// An Updater should implement at least one of the Parser interfaces.
type Updater interface {
	// Name is a unique name for this updater.
	//
	// The name preferably indicates the vendor who implemented it and the data
	// source it's fetching and interpreting.
	Name() string

	// Fetch downloads data from the Internet and records it so that a later
	// Parser implementation can parse it.
	//
	// When called, the function should determine if new security advisory data
	// is available. A Fingerprint may be passed into in order for the Fetcher to
	// determine if the content has changed. A nil Fingerprint indicates no
	// previous state.
	//
	// Any downloaded data should be written to the provided zip.Writer.
	//
	// The "snapshot" return reports whether the written data is an entire
	// database or delta between the provided Fingerprint and the current state.
	//
	// If the content has not changed, an implementation can write nothing and
	// return the same Fingerprint that was passed in.
	Fetch(context.Context, *zip.Writer, Fingerprint, *http.Client) (snapshot bool, next Fingerprint, err error)
}

// SnapshotParser takes a provided fs and reports the Advisories found.
type SnapshotParser interface {
	ParseSnapshot(ctx context.Context, sys fs.FS, cur, next Fingerprint) (ParsedSnapshot, error)
}

// ParsedSnapshot ...
type ParsedSnapshot interface {
	// All returns an iterator over all Advisories in the snapshot.
	All(context.Context) (iter.Seq2[Advisory, error], error)

	// Close releases any held resources, reporting any errors.
	//
	// Implementations may panic if Close is not called.
	Close() error
}

// DeltaParser takes a provided fs and reports the Advisories found.
type DeltaParser interface {
	ParseDelta(ctx context.Context, sys fs.FS, cur, next Fingerprint) (ParsedDelta, error)
}

// ParsedDelta ...
type ParsedDelta interface {
	// Added returns an iterator over all added Advisories in the delta.
	//
	// An Advisory overwrites any previous Advisory with the same name, if
	// present.
	Added(context.Context) (iter.Seq2[Advisory, error], error)

	// Removed returns an iterator over all removed Advisories in the delta.
	//
	// All removed Advisories are processed after additions.
	Removed(context.Context) (iter.Seq2[AdvisoryName, error], error)

	// Close releases any held resources, reporting any errors.
	//
	// Implementations may panic if Close is not called.
	Close() error
}
