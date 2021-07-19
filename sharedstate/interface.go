package sharedstate

import (
	"context"

	"github.com/quay/claircore/internal/indexer"
	"github.com/quay/claircore/internal/vulnstore"
	"github.com/quay/claircore/pkg/distlock"
)

type LockerService interface {
	Locker(context.Context) (distlock.Locker, error)
}

type MatcherService interface {
	Matcher(context.Context) (Matcher, error)
	Vulnstore(context.Context) (vulnstore.Store, error)
}

type IndexerService interface {
	Indexer(context.Context) (indexer.Store, error)
}
