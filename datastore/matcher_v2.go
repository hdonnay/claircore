//go:build go1.23 || (go1.22 && goexperiment.rangefunc)

package datastore

import (
	"context"
	"iter"
	"time"

	"github.com/google/uuid"

	"github.com/quay/claircore/updater/driver/v1"
)

// As a general rule: if a method takes a [context.Context], the corresponding
// Close method on that object must be called.

// MatcherV2 ...
type MatcherV2 interface {
	Updater() UpdaterV2
}

// TODO(hank) make `driver.UpdaterName = unique.Handle[string]` ?

// UpdaterV2 is the uniform interface for the Updater subsystem.
//
// # Updaters
//
// Updaters are created upon first use with [Run.UpdaterRun] and removed with a
// [GC] call that results in no advisories from an Updater left in the backing
// store.
type UpdaterV2 interface {
	// Query APIs:
	ListUpdaters(context.Context) (iter.Seq2[UpdaterInfo, error], error)
	UpdateStatus(context.Context) (UpdateStatus, error)

	// Create APIs:
	NewRun(context.Context) (Run, error)

	// Delete APIs:
	GC(context.Context) error
}

// UpdaterInfo describes an updater known to the system.
type UpdaterInfo interface {
	Name() string
}

// UpdateStatus is the uniform interface for the update status metadata.
type UpdateStatus interface {
	ListRuns(context.Context, ...string) (iter.Seq2[RunStatus, error], error)
	ListUpdaterRuns(context.Context, uuid.UUID) (iter.Seq2[UpdaterRunStatus, error], error)

	RunStatus(context.Context, uuid.UUID) (RunStatus, error)
	UpdaterRunStatus(context.Context, uuid.UUID) (UpdaterRunStatus, error)

	// Close releases held resources for listing run information.
	//
	// An implementation may panic if Close is not called when needed.
	Close() error
}

// RunStatus describes the status of a particular run.
type RunStatus struct {
	Ref  uuid.UUID
	Date time.Time

	// UpdaterRuns ...
	//
	// The iterator must be consumed before the [UpdateStatus.Close] call of the
	// creating [UpdateStatus].
	UpdaterRuns iter.Seq2[UpdaterRunStatus, error]
	// Implementor note: this member should have an empty iterator instead of a
	// nil value when there are no values to return. This convention saves
	// callers from needing nil checks.
}

// UpdaterRunStatus describes the status of a particular updater's run.
type UpdaterRunStatus struct {
	Ref         uuid.UUID
	Date        time.Time
	Updater     string
	Fingerprint []byte
	Err         error
}

// Run ...
type Run interface {
	// UpdaterRun begins a run of a particular updater, returning the previous
	// successful run's fingerprint and an [UpdaterRun] interface.
	//
	// The fingerprint is arbitrary information passed between runs of the same
	// updater.
	UpdaterRun(context.Context, string) ([]byte, UpdaterRun, error)

	// Finish marks the run as complete. It should be called regardless of the
	// status of individual updater runs.
	//
	// Because this method may cause writes to the backing store, the [Close]
	// method is still needed to release any held resources.
	Finish(context.Context) error

	// Close releases held resources for the current run of updaters.
	//
	// An implementation may panic if Close is not called correctly.
	Close() error
}

// UpdaterRun ...
//
// # Update Types
//
// There are two types of updates that backing stores may support:
//
//   - Snapshot
//   - Delta
//
// If a type is unsupported, a call to the relevant method will report
// [errors.ErrUnsupported].
//
// "Snapshot" updates are for updaters that have the entire state of the
// advisory database. This style is usually easier to write, but has increased
// resource usage, usually memory and network.
//
// "Delta" updates only report what is new or changed, and what has been
// removed. If the vendor source/API tracks this information, it's probably more
// efficient to consume that as a delta update than reconstructing the source
// locally.
type UpdaterRun interface {
	// Snapshot starts a "snapshot" update.
	Snapshot(context.Context) (SnapshotUpdate, error)
	// Delta starts a "delta" update.
	Delta(context.Context) (DeltaUpdate, error)

	// Success marks the run of this updater successful and records the provided
	// fingerprint.
	Success(context.Context, []byte) error
	// Error marks the run of this updater unsuccessful and records the provided
	// error.
	Error(context.Context, error) error

	// Close releases held resources for the current run of this updater.
	//
	// An implementation may panic if Close is not called correctly.
	Close() error
}

// SnapshotUpdate ...
type SnapshotUpdate interface {
	Set(context.Context, iter.Seq2[driver.Vulnerability, error]) error
}

// DeltaUpdate ...
type DeltaUpdate interface {
	Add(context.Context, iter.Seq2[driver.Vulnerability, error]) error
	Remove(context.Context, iter.Seq2[string, error]) error
}
