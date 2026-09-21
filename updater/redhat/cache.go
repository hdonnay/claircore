package redhat

import (
	"context"
	"sync"

	"github.com/quay/claircore/internal/singleflight"

	"github.com/quay/claircore/updater/driver"
)

type Cache struct {
	m sync.Map
}

type ArtifactCache struct {
	m  sync.Map
	sf singleflight.Group[uint64, driver.ArtifactHandle]
}

type CreateArtifactFunc func(context.Context, driver.ArtifactBuilder, *status) error

func (c *ArtifactCache) Get(ctx context.Context, upd driver.UpdateBuilder, st *status, create CreateArtifactFunc) (driver.ArtifactHandle, error) {
	key := st.Key()
	// Try to load an existing handle out of the cache.
	value, ok := c.m.Load(key)
	if ok {
		return value.(driver.ArtifactHandle), nil
	}
	// No handle found. Create a new handle.
	fn := func() (driver.ArtifactHandle, error) {
		// Eagerly check the Context so the create function doesn't need the
		// preamble.
		if ctx.Err() != nil {
			return -1, context.Cause(ctx)
		}

		// Create the builder:
		art, err := upd.CreateArtifact(ctx)
		if err != nil {
			return -1, err
		}

		// Run the passed-in function:
		err = create(ctx, art, st)
		// Mark the artifact as abandoned or built as-needed:
		if err != nil {
			art.Abandon(ctx, err)
			return -1, err
		}
		h, err := art.Build(ctx)
		if err != nil {
			return -1, err
		}

		// Store and return the handle.
		c.m.Store(key, h)
		return h, nil
	}

	select {
	case res := <-c.sf.DoChan(key, fn):
		return res.Val, res.Err
	case <-ctx.Done():
		c.sf.Forget(key)
		return -1, context.Cause(ctx)
	}
}

// Reset removes all cached entries.
func (c *ArtifactCache) Clear() {
	c.m.Clear()
}

// Len reports the approximate number of entries in the cache.
//
// The count is approximate because concurrent removals and additions may not be
// seen.
func (c *ArtifactCache) Len() (n int) {
	c.m.Range(func(_, _ any) bool {
		n++
		return true
	})
	return n
}
