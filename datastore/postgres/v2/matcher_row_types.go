package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/updater/driver/v2"
)

// TryRowEncodePlan supports encoding directly from our row types.
func tryRowEncodePlan(tgt any) (plan pgtype.WrappedEncodePlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *driver.Advisory:
		return &wrapAdvisoryEncodePlan{}, (*advisoryWrapper)(tgt), true
	case *driver.Attr:
		return &wrapAttrEncodePlan{}, (*attrWrapper)(tgt), true
	case *driver.Reference:
		return &wrapReferenceEncodePlan{}, (*referenceWrapper)(tgt), true
	case *driver.Package:
		return &wrapPackageEncodePlan{}, (*packageWrapper)(tgt), true
	}
	return nil, nil, false
}

// Implementation assertions for row types.
var (
	_ pgtype.CompositeIndexGetter = (*advisoryWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*attrWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*referenceWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*packageWrapper)(nil)
	_ pgtype.CompositeIndexGetter = removeWrapper("")
)

// Wrapper types for row types.
type (
	advisoryWrapper  driver.Advisory
	attrWrapper      driver.Attr
	referenceWrapper driver.Reference
	packageWrapper   driver.Package
	removeWrapper    string
)

// Index implements [pgtype.CompositeIndexGetter].
func (a *advisoryWrapper) Index(i int) any {
	switch i {
	case 0:
		return &a.Name
	case 1:
		return &a.Issued
	case 2:
		return &a.Summary
	case 3:
		return &a.Description
	case 4:
		return &a.URI
	case 5:
		return &a.Severity.Upstream
	case 6:
		return &a.Severity.Normalized
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (a *advisoryWrapper) IsNull() bool { return a == nil }

// Index implements [pgtype.CompositeIndexGetter].
func (a *attrWrapper) Index(i int) any {
	switch i {
	case 0:
		return &a.Kind
	case 1:
		return &a.Value
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (a *attrWrapper) IsNull() bool { return a == nil }

// Index implements [pgtype.CompositeIndexGetter].
func (r *referenceWrapper) Index(i int) any {
	switch i {
	case 0:
		return &r.Namespace
	case 1:
		return &r.Name
	case 2:
		return &r.URI
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (r *referenceWrapper) IsNull() bool { return r == nil }

// Index implements [pgtype.CompositeIndexGetter].
func (p *packageWrapper) Index(i int) any {
	switch i {
	case 0:
		return &p.Name
	case 1:
		return &p.Kind
	case 2:
		return &p.Arch
	case 3:
		return &p.Version.Ranges
	case 4:
		return &p.Version.Upstream
	case 5:
		return &p.Version.Kind
	case 6:
		return &p.PURL
	case 7:
		return &p.CPE
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (p *packageWrapper) IsNull() bool { return p == nil }

// Index implements [pgtype.CompositeIndexGetter].
func (r removeWrapper) Index(i int) any {
	switch i {
	case 0:
		return (*string)(&r)
	case 1:
		return nil
	case 2:
		return nil
	case 3:
		return nil
	case 4:
		return nil
	case 5:
		return nil
	case 6:
		return nil
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (r removeWrapper) IsNull() bool { return r == "" }

// [pgtype.WrappedEncodePlanNextSetter] implementations for row types:
// - [*driver.Advisory]
// - [*driver.Attr]
// - [*driver.Reference]
// - [*driver.Package]
type (
	wrapAdvisoryEncodePlan  struct{ next pgtype.EncodePlan }
	wrapAttrEncodePlan      struct{ next pgtype.EncodePlan }
	wrapReferenceEncodePlan struct{ next pgtype.EncodePlan }
	wrapPackageEncodePlan   struct{ next pgtype.EncodePlan }
)

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapAdvisoryEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*advisoryWrapper)(value.(*driver.Advisory)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapAdvisoryEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapAttrEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*attrWrapper)(value.(*driver.Attr)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapAttrEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapReferenceEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*referenceWrapper)(value.(*driver.Reference)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapReferenceEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapPackageEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*packageWrapper)(value.(*driver.Package)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapPackageEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }
