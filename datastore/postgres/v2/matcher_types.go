package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// "Scan" is the term for reading from the database.
// "Encode" is the term for preparing a value or writing to the database.

// It seems like the "EncodePlan"/"ScanPlan" types should be able to be written
// with a type parameter, but the type conversions don't work with the generics.
// There's no "convertable" constraint or the ability to use a `~T` constraint.

func registerDataTypes(ctx context.Context, conn *pgx.Conn) error {
	m := conn.TypeMap()
	m.TryWrapScanPlanFuncs = append([]pgtype.TryWrapScanPlanFunc{
		tryCommonScanPlan,
		tryDriverScanPlan,
	}, m.TryWrapScanPlanFuncs...)
	m.TryWrapEncodePlanFuncs = append([]pgtype.TryWrapEncodePlanFunc{
		tryCommonEncodePlan,
		tryDriverEncodePlan,
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
