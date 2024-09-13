package postgres

import (
	"context"
	"iter"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/quay/claircore/updater/driver/v2"
)

// AdvisorySource is a [pgx.CopyFromSource] for an [AddSeq].
type advisorySource struct {
	next func() (driver.NamespacedAdvisory[driver.Advisory], error, bool)
	stop func()
	// This is not idiomatic, but we don't control the [pgx.CopyFromSource] API
	// and need a [context.Context] in the [Values] method.
	ctx context.Context

	err error
	adv driver.Advisory
}

var _ pgx.CopyFromSource = (*advisorySource)(nil)

func advisoryCopySource(ctx context.Context, vs AddSeq) *advisorySource {
	next, stop := iter.Pull2(vs)
	src := &advisorySource{
		next: next,
		stop: stop,
		ctx:  ctx,
	}
	return src
}

func (src *advisorySource) Names() []string {
	return []string{"advisory", "reference", "package", "attr"}
}

func (src *advisorySource) Next() (ok bool) {
	var a driver.NamespacedAdvisory[driver.Advisory]
	a, src.err, ok = src.next()
	if src.err == nil {
		src.adv = a.Advisory
	}
	return ok && src.err == nil
}

// TODO(hank) There's probably some memory savings to be had if the accumulator
// slices were re-used between [Values] calls. If tackling that, make sure to
// check the contract for the [pgx.Batch] API; I think it eagerly produces the
// wire format and this optimization is only possible if it does.

func (src *advisorySource) Values() ([]any, error) {
	const (
		ordAdvisory int = iota
		ordReference
		ordPackage
		ordAttr
		numCol
	)
	row := make([]interface{}, numCol)

	row[ordAdvisory] = &src.adv

	refs, err := src.adv.Refs(src.ctx)
	if err != nil {
		return nil, err
	}
	row[ordReference] = slices.Collect(filterErrs(&err, refs))
	if err != nil {
		return nil, err
	}

	pkgs, err := src.adv.Packages(src.ctx)
	if err != nil {
		return nil, err
	}
	row[ordPackage] = slices.Collect(filterErrs(&err, pkgs))
	if err != nil {
		return nil, err
	}

	attrs, err := src.adv.Attrs(src.ctx)
	if err != nil {
		return nil, err
	}
	row[ordAttr] = slices.Collect(filterErrs(&err, attrs))
	if err != nil {
		return nil, err
	}

	return row, nil
}

func (src *advisorySource) Err() error {
	if src.err != nil {
		return src.err
	}
	return nil
}

func filterErrs[T any](out *error, seq iter.Seq2[T, error]) iter.Seq[T] {
	return func(yield func(T) bool) {
		for v, err := range seq {
			if err != nil {
				*out = err
				return
			}
			if !yield(v) {
				return
			}
		}
	}
}

// RemoveSource is a [pgx.CopyFromSource] for a [RemSeq].
type removeSource struct {
	next func() (driver.NamespacedAdvisory[driver.AdvisoryName], error, bool)
	stop func()
	// This is not idiomatic, but we don't control the [pgx.CopyFromSource] API
	// and need a [context.Context] in the [Values] method.
	ctx context.Context

	err error
	adv string
}

var _ pgx.CopyFromSource = (*removeSource)(nil)

func removeCopySource(ctx context.Context, vs RemSeq) *removeSource {
	next, stop := iter.Pull2(vs)
	src := &removeSource{
		next: next,
		stop: stop,
		ctx:  ctx,
	}
	return src
}

func (src *removeSource) Names() []string {
	return []string{"advisory"}
}

func (src *removeSource) Next() (ok bool) {
	var a driver.NamespacedAdvisory[driver.AdvisoryName]
	a, src.err, ok = src.next()
	if src.err == nil {
		src.adv = a.Advisory.Name
	}
	return ok && src.err == nil
}

// Err implements [pgx.CopyFromSource].
func (src *removeSource) Err() error {
	if src.err != nil {
		return src.err
	}
	return nil
}

// Values implements [pgx.CopyFromSource].
func (src *removeSource) Values() ([]any, error) {
	return []any{removeWrapper(src.adv)}, nil
}
