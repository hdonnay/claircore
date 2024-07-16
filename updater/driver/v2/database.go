package driver

import (
	"errors"
	"iter"
	"time"

	"github.com/google/uuid"
)

// These need to exist in some common place, so they're tucked here.

// ErrDuplicateRef is reported when a ref is attempted to be created when it
// already exists.
var ErrDuplicateRef = errors.New("an UpdateOperation with this ref already exists")

// Fingerprint is some identifying information about a vulnerability database.
type Fingerprint []byte

// UpdateOperation is a unique update to the Store by an Updater.
type UpdateOperation struct {
	Date        time.Time
	Updater     string
	Fingerprint Fingerprint
	Ref         uuid.UUID
}

// UpdateDiff represents added or removed vulnerabilities between update
// operations.
type UpdateDiff struct {
	Added, Removed iter.Seq2[Advisory, error]
	Prev, Cur      UpdateOperation
}

// NamespacedAdvisory is one of the advisory types along with a namespace.
//
// This is added by the controller and not used in Updater implementations.
type NamespacedAdvisory[A Advisory | AdvisoryName] struct {
	Updater  string
	Advisory A
}

// NamespaceSeq wraps the passed iterator and adds the provided namespace.
func NamespaceSeq[A Advisory | AdvisoryName](updater string, seq iter.Seq2[A, error]) iter.Seq2[NamespacedAdvisory[A], error] {
	return func(yeild func(NamespacedAdvisory[A], error) bool) {
		for a, err := range seq {
			n := NamespacedAdvisory[A]{
				Updater:  updater,
				Advisory: a,
			}
			if !yeild(n, err) {
				return
			}
		}
	}
}
