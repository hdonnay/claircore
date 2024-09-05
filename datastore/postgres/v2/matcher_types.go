package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/quay/claircore/updater/driver/v2"
)

func registerDataTypes(ctx context.Context, conn *pgx.Conn) error {
	m := conn.TypeMap()
	m.TryWrapScanPlanFuncs = append([]pgtype.TryWrapScanPlanFunc{
		tryEnumScanPlan,
		tryCommonScanPlan,
	}, m.TryWrapScanPlanFuncs...)
	m.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{
		tryCommonEncodePlan,
		tryVersionEncodePlan,
		tryRowEncodePlan,
	}, m.TryWrapEncodePlanFuncs...)

	// The underscore convention is a PostgreSQL thing: https://www.postgresql.org/docs/16/sql-createtype.html#SQL-CREATETYPE-ARRAY

	// Register OIDs for everything:
	for _, n := range []string{
		"matcher_v2.Severity",
		"matcher_v2._Severity",
		"matcher_v2.PackageKind",
		"matcher_v2._PackageKind",
		"matcher_v2.Architecture",
		"matcher_v2._Architecture",
		"matcher_v2.VersionRange",
		"matcher_v2._VersionRange",
		"matcher_v2.VersionMultiRange",
		"matcher_v2._VersionMultiRange",
		"matcher_v2_import.advisory",
		"matcher_v2_import._advisory",
		"matcher_v2_import.reference",
		"matcher_v2_import._reference",
		"matcher_v2_import.package",
		"matcher_v2_import._package",
		"matcher_v2_import.attr",
		"matcher_v2_import._attr",
		"matcher_v2_import.advisory_import_row",
		"matcher_v2_import._advisory_import_row",
	} {
		t, err := conn.LoadType(ctx, n)
		if err != nil {
			return fmt.Errorf("registering %q: %w", n, err)
		}
		m.RegisterType(t)
	}

	return nil
}

// "Scan" is the term for reading from the database.
// "Encode" is the term for preparing a value or writing to the database.

// It seems like these "EncodePlan"/"ScanPlan" types should be able to be
// written with a type parameter, but the type conversions don't work with the
// generics. There's no "convertable" constraint or the ability to use a `~T`
// constraint.

func tryVersionEncodePlan(tgt any) (plan pgtype.WrappedEncodePlanNextSetter, dst any, ok bool) {
	switch tgt := tgt.(type) {
	case driver.VersionRange:
		return &wrapVersionRangeEncodePlan{}, versionRangeWrapper(tgt), true
	case []driver.VersionRange:
		return &wrapVersionMultiRangeEncodePlan{}, versionMultiRangeWrapper(tgt), true
	default:
	}
	return nil, nil, false
}

type (
	wrapVersionRangeEncodePlan      struct{ next pgtype.EncodePlan }
	wrapVersionMultiRangeEncodePlan struct{ next pgtype.EncodePlan }
)

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionRangeEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	return w.next.Encode(versionRangeWrapper(value.(driver.VersionRange)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionRangeEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

// Encode implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionMultiRangeEncodePlan) Encode(value any, buf []byte) ([]byte, error) {
	return w.next.Encode(versionMultiRangeWrapper(value.([]driver.VersionRange)), buf)
}

// SetNext implements [pgtype.WrappedEncodePlanNextSetter].
func (w *wrapVersionMultiRangeEncodePlan) SetNext(next pgtype.EncodePlan) { w.next = next }

var (
	_ pgtype.RangeValuer      = versionRangeWrapper{}
	_ pgtype.MultirangeGetter = versionMultiRangeWrapper{}
)

type (
	versionRangeWrapper      driver.VersionRange
	versionMultiRangeWrapper []driver.VersionRange
)

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

// Index implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) Index(i int) any { return v[i] }

// IndexType implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) IndexType() any { return driver.VersionRange{} }

// IsNull implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) IsNull() bool { return v == nil }

// Len implements [pgtype.MultirangeGetter].
func (v versionMultiRangeWrapper) Len() int { return len(v) }
