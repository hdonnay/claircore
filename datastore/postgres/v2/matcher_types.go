package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func registerDataTypes(ctx context.Context, conn *pgx.Conn) error {
	// The underscore convention is a PostgreSQL thing: https://www.postgresql.org/docs/16/sql-createtype.html#SQL-CREATETYPE-ARRAY
	typeNames := []string{
		// Explicit domain types:
		"matcher_v2.Severity",
		"matcher_v2.PackageKind",
		"matcher_v2.Architecture",
		"matcher_v2._Architecture",
		// Row types:
		"matcher_v2_import.advisory",
		"matcher_v2_import.reference",
		"matcher_v2_import._reference",
		"matcher_v2_import.package",
		"matcher_v2_import._package",
		"matcher_v2_import.attr",
		"matcher_v2_import._attr",
		"matcher_v2_import.advisory_import_row",
		"matcher_v2_import._advisory_import_row",
	}
	m := conn.TypeMap()
	for _, n := range typeNames {
		t, err := conn.LoadType(ctx, n)
		if err != nil {
			return err
		}
		m.RegisterType(t)
	}
	return nil
}
