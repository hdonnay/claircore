// # Type support
//
// This package provides support for the following types in the described ways:
//
// A [driver.Advisory] is scanned & encoded as a composite type in this order:
//   - Name
//   - Issued
//   - Summary
//   - Description
//   - URI
//   - Severity.Upstream
//   - Severity.Normalized
//
// A [driver.Attr] is scanned & encoded as a composite type in this order:
//   - Kind
//   - Value
//
// A [driver.Package] is scanned & encoded as a composite type in this order:
//   - Name
//   - Kind
//   - Arch
//   - Version.Ranges
//   - Version.Upstream
//   - Version.Kind
//   - PURL
//   - CPE
//
// A [driver.Reference] is scanned & encoded as a composite type in this order:
//   - Namespace
//   - Name
//   - URI
//
// A [driver.VersionRange] is scanned into & encoded from a
// "matcher_v2.VersionRange". Arrays of this type are scanned into & encoded
// from a "matcher_v2.VersionMultiRange".
//
// A [driver.Fingerprint] is scanned into & encoded from BYTEA.
//
// A [driver.Architecture] is scanned into & encoded from a
// "matcher_v2.Architecture". Arrays of this type are supported.
//
// A [driver.UpdateOperation] is encoded from a composite type in this order:
//   - Updater
//   - Ref
//   - Date
//   - Success
//   - Fingerprint
//   - Error
package postgres

import (
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/updater/driver/v2"
)

// TryDriverEncodePlan supports encoding directly from [github.com/quay/claircore/updater/driver/v2] types.
func tryDriverEncodePlan(tgt any) (plan pgtype.WrappedEncodePlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *driver.Advisory:
		return &wrapAdvisoryEncodePlan{}, (*advisoryWrapper)(tgt), true
	case *driver.Attr:
		return &wrapAttrEncodePlan{}, (*attrWrapper)(tgt), true
	case *driver.Package:
		return &wrapPackageEncodePlan{}, (*packageWrapper)(tgt), true
	case *driver.Reference:
		return &wrapReferenceEncodePlan{}, (*referenceWrapper)(tgt), true
	case []driver.VersionRange:
		return &wrapVersionMultiRangeEncodePlan{}, versionMultiRangeWrapper(tgt), true
	case driver.VersionRange:
		return &wrapVersionRangeEncodePlan{}, versionRangeWrapper(tgt), true
	default:
	}
	return nil, nil, false
}

// TryDriverScanPlan supports scanning directly into [github.com/quay/claircore/updater/driver/v2] types.
func tryDriverScanPlan(tgt any) (plan pgtype.WrappedScanPlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case *driver.UpdateOperation:
		return &wrapUpdateOperationScanPlan{}, (*updateOperationWrapper)(tgt), true
	case *driver.Fingerprint:
		return &wrapFingerprintScanPlan{}, (*fingerprintWrapper)(tgt), true
	case *driver.Architecture:
		return &wrapArchitectureScanPlan{}, (*architectureWrapper)(tgt), true
	}
	return nil, nil, false
}

// Encode machinery:

// [pgtype.WrappedEncodePlanNextSetter] implementations for driver types:
// - [driver.Advisory]
// - [driver.Attr]
// - [driver.Package]
// - [driver.Reference]
// - [[]driver.VersionRange]
// - [driver.VersionRange]
type (
	wrapAdvisoryEncodePlan          struct{ next pgtype.EncodePlan }
	wrapAttrEncodePlan              struct{ next pgtype.EncodePlan }
	wrapPackageEncodePlan           struct{ next pgtype.EncodePlan }
	wrapReferenceEncodePlan         struct{ next pgtype.EncodePlan }
	wrapVersionMultiRangeEncodePlan struct{ next pgtype.EncodePlan }
	wrapVersionRangeEncodePlan      struct{ next pgtype.EncodePlan }
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
func (w *wrapPackageEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*packageWrapper)(value.(*driver.Package)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapPackageEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapReferenceEncodePlan) Encode(value any, buf []byte) (newBuf []byte, err error) {
	return w.next.Encode((*referenceWrapper)(value.(*driver.Reference)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapReferenceEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionMultiRangeEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	return w.next.Encode(versionMultiRangeWrapper(value.([]driver.VersionRange)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionMultiRangeEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionRangeEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	return w.next.Encode(versionRangeWrapper(value.(driver.VersionRange)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionRangeEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

var (
	_ pgtype.CompositeIndexGetter = (*advisoryWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*attrWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*packageWrapper)(nil)
	_ pgtype.CompositeIndexGetter = (*referenceWrapper)(nil)
	_ pgtype.MultirangeGetter     = versionMultiRangeWrapper{}
	_ pgtype.RangeValuer          = versionRangeWrapper{}
)

type (
	advisoryWrapper          driver.Advisory
	attrWrapper              driver.Attr
	packageWrapper           driver.Package
	referenceWrapper         driver.Reference
	versionMultiRangeWrapper []driver.VersionRange
	versionRangeWrapper      driver.VersionRange
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

// Index implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) Index(i int) any { return v[i] }

// IndexType implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) IndexType() any { return driver.VersionRange{} }

// IsNull implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) IsNull() bool { return v == nil }

// Len implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) Len() int { return len(v) }

// BoundTypes implements [pgtype.RangeValuer].
func (v versionRangeWrapper) BoundTypes() (lower pgtype.BoundType, upper pgtype.BoundType) {
	lower, upper = pgtype.Exclusive, pgtype.Exclusive

	switch {
	case len(v.Lower.Components) == 0:
		lower = pgtype.Unbounded
	case v.Lower.Inclusive:
		lower = pgtype.Inclusive
	}
	switch {
	case len(v.Upper.Components) == 0:
		upper = pgtype.Unbounded
	case v.Upper.Inclusive:
		upper = pgtype.Inclusive
	}

	return lower, upper
}

// Bounds implements [pgtype.RangeValuer].
func (v versionRangeWrapper) Bounds() (lower any, upper any) {
	nonDigit := func(r rune) bool { return r < '0' || r > '9' }

	for i, c := range v.Lower.Components {
		if strings.ContainsFunc(c, nonDigit) {
			continue
		}
		if len(c) < 10 {
			v.Lower.Components[i] = fmt.Sprintf("%0*s", 10, c)
		}
	}
	for i, c := range v.Upper.Components {
		if strings.ContainsFunc(c, nonDigit) {
			continue
		}
		if len(c) < 10 {
			v.Upper.Components[i] = fmt.Sprintf("%0*s", 10, c)
		}
	}

	return v.Lower.Components, v.Upper.Components
}

// IsNull implements [pgtype.RangeValuer].
func (v versionRangeWrapper) IsNull() bool {
	return v.Lower.Components == nil && v.Upper.Components == nil
}

// Scan machinery:

// [pgtype.WrappedScanPlanNextSetter] implementations for driver types:
// - [*driver.Architecture]
// - [*driver.Fingerprint]
// - [*driver.UpdateOperation]
type (
	wrapArchitectureScanPlan    struct{ next pgtype.ScanPlan }
	wrapFingerprintScanPlan     struct{ next pgtype.ScanPlan }
	wrapUpdateOperationScanPlan struct{ next pgtype.ScanPlan }
)

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapArchitectureScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*architectureWrapper)(dst.(*driver.Architecture)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapArchitectureScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapFingerprintScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*fingerprintWrapper)(dst.(*driver.Fingerprint)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapFingerprintScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

// Scan implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapUpdateOperationScanPlan) Scan(src []byte, dst any) error {
	return w.next.Scan(src, (*updateOperationWrapper)(dst.(*driver.UpdateOperation)))
}

// SetNext implements [pgtype.WrappedScanPlanNextSetter].
func (w *wrapUpdateOperationScanPlan) SetNext(next pgtype.ScanPlan) { w.next = next }

var (
	_ pgtype.TextScanner           = (*architectureWrapper)(nil)
	_ pgtype.BytesScanner          = (*fingerprintWrapper)(nil)
	_ pgtype.CompositeIndexScanner = (*updateOperationWrapper)(nil)
)

type (
	architectureWrapper    driver.Architecture
	fingerprintWrapper     driver.Fingerprint
	updateOperationWrapper driver.UpdateOperation
)

// ScanText implements [pgtype.TextScanner].
func (a *architectureWrapper) ScanText(v pgtype.Text) error {
	if !v.Valid {
		return errors.New("unable to scan null Architecture")
	}
	switch v.String {
	case "any":
		*(*driver.Architecture)(a) = driver.ArchAny
	case "386":
		*(*driver.Architecture)(a) = driver.Arch386
	case "amd64":
		*(*driver.Architecture)(a) = driver.ArchAMD64
	case "arm":
		*(*driver.Architecture)(a) = driver.ArchArm
	case "arm64":
		*(*driver.Architecture)(a) = driver.ArchArm64
	case "mips":
		*(*driver.Architecture)(a) = driver.ArchMips
	case "mipsle":
		*(*driver.Architecture)(a) = driver.ArchMipsLE
	case "mips64":
		*(*driver.Architecture)(a) = driver.ArchMips64
	case "mips64le":
		*(*driver.Architecture)(a) = driver.ArchMips64LE
	case "ppc64":
		*(*driver.Architecture)(a) = driver.ArchPPC64
	case "ppc64le":
		*(*driver.Architecture)(a) = driver.ArchPPC64LE
	case "riscv64":
		*(*driver.Architecture)(a) = driver.ArchRiscV64
	case "s390x":
		*(*driver.Architecture)(a) = driver.ArchS390X
	default:
		return fmt.Errorf("unknown Architecture %q", v.String)
	}
	return nil
}

// ScanBytes implements [pgtype.BytesScanner].
func (f *fingerprintWrapper) ScanBytes(v []byte) error {
	b := append([]byte(*f)[:0], v...)
	*f = fingerprintWrapper(driver.Fingerprint(b))
	return nil
}

// ScanIndex implements [pgtype.CompositeIndexScanner].
func (u *updateOperationWrapper) ScanIndex(i int) any {
	switch i {
	case 0:
		return &u.Updater
	case 1:
		return &u.Ref
	case 2:
		return &u.Date
	case 3:
		return &u.Success
	case 4:
		return &u.Fingerprint
	case 5:
		return &u.Error
	default:
		panic("bad index")
	}
}

// ScanNull implements [pgtype.CompositeIndexScanner].
func (u *updateOperationWrapper) ScanNull() error {
	u = nil
	return nil
}
