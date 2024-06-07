package datastore

import (
	"context"
	"iter"
	"time"

	"github.com/google/uuid"
)

type MatcherV2 interface {
	Updater() UpdaterV2
}

type UpdaterV2 interface {
	GC(context.Context) error
	NewRun(context.Context) (Run, error)

	UpdateStatus(context.Context) (UpdateStatus, error)
}

type Run interface {
	UpdaterRun(context.Context, string) ([]byte, UpdaterRun, error)
	Finish(context.Context) error
	Close() error
}

type UpdaterRun interface {
	Snapshot(context.Context) (SnapshotUpdate, error)
	Delta(context.Context) (DeltaUpdate, error)

	Success(context.Context, []byte) error
	Error(context.Context, error) error
	Close() error
}

type Advisory struct{} // ???

type SnapshotUpdate interface {
	Set(context.Context, iter.Seq2[Advisory, error]) error
}

type DeltaUpdate interface {
	Add(context.Context, iter.Seq2[Advisory, error]) error
	Remove(context.Context, iter.Seq2[string, error]) error
}

type UpdateStatus interface {
}

type RunStatus struct {
	Ref  uuid.UUID
	Date time.Time
}

type UpdaterRunStatus struct {
	Ref         uuid.UUID
	Updater     string
	Fingerprint []byte
	Date        time.Time
	Err         error
}
