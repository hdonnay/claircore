// Package vacuumlo implements Large Object vacuuming, a la [vacuumlo(1)].
//
// [vacuumlo(1)]: https://www.postgresql.org/docs/current/vacuumlo.html
package vacuumlo

import (
	"context"
	_ "embed" // for queries
	"errors"
	"fmt"

	"github.com/jackc/pgx/v4"
)

// This is also hard-coded in sql/fetch.sql.
//
// Make sure to parameterize that query if making this adjustable.
const txLimit = 1000

// Run does the vacuum.
//
// Run takes ownership of "conn" and closes it when done.
func Run(ctx context.Context, conn *pgx.Conn) (err error) {
	defer conn.Close(ctx)

	// Create and populate the temp table with all the large object oids in the
	// database.
	if _, err := conn.Exec(ctx, createTemp); err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}
	// Analyze the temp table so that planner will generate decent plans for the
	// DELETEs below.
	if _, err := conn.Exec(ctx, analyzeTemp); err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}

	// Find any candidate tables that have columns of type oid.
	rows, err := conn.Query(ctx, findTables)
	if err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var schema, table, field string
		if err := rows.Scan(&schema, &table, &field); err != nil {
			return fmt.Errorf("vacuumlo: %w", err)
		}
		// Remove entries in the temp table that exist in the tables.
		_, err = conn.Exec(ctx, fmt.Sprintf(removeLive, schema, table, field))
		if err != nil {
			return fmt.Errorf("vacuumlo: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}

	// Entries remaining in the temp table are orphans.
	//
	// Batch-delete them to avoid too many locks piling up server-side.
	var (
		tx      pgx.Tx
		deleted int64
	)
	tx, err = conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}

	if _, err := tx.Exec(ctx, declareCursor); err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}

Delete:
	for {
		var oid uint32
		_, err := tx.QueryFunc(ctx, fetch, nil,
			[]any{&oid},
			func(row pgx.QueryFuncRow) error {
				var ok uint32
				err := tx.QueryRow(ctx, `SELECT lo_unlink($1)`, oid).Scan(&ok)
				if err != nil {
					return err
				}
				if ok != 1 {
					return fmt.Errorf("failed to unlink large object 0x%08x", oid)
				}
				return nil
			})
		switch {
		case err == nil:
			deleted++
		case errors.Is(err, pgx.ErrNoRows):
			break Delete
		default:
			return fmt.Errorf("vacuumlo: %w", err)
		}

		if deleted%1000 == 0 {
			if err := tx.Commit(ctx); err != nil {
				return fmt.Errorf("vacuumlo: %w", err)
			}
			tx, err = conn.Begin(ctx)
			if err != nil {
				return fmt.Errorf("vacuumlo: %w", err)
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("vacuumlo: %w", err)
	}

	return nil
}

var (
	//go:embed sql/create_temp.sql
	createTemp string
	//go:embed sql/analyze_temp.sql
	analyzeTemp string
	//go:embed sql/find_tables.sql
	findTables string
	//go:embed sql/remove_live.sql
	removeLive string
	//go:embed sql/declare_cursor.sql
	declareCursor string
	//go:embed sql/fetch.sql
	fetch string
)

// Go generate command to reformat the SQL files:
//go:generate find sql -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --language postgresql --fix {} ;
