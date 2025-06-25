package main

import (
	"context"
	"database/sql"
	_ "embed" // for the sql queries
	"errors"
	"fmt"
	"log/slog"
	"strconv"
)

// DB is a wrapper over a SQlite database containing the index state.
type DB struct {
	*sql.DB
}

func OpenDB(ctx context.Context, f string) (*DB, error) {
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s", f))
	if err != nil {
		slog.ErrorContext(ctx, "unable to open database", "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, querySetup); err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}

	return &DB{db}, nil
}

func (db *DB) WriteRecord(ctx context.Context, r Record) error {
	// TODO(hank) Support removal records.
	_, err := db.ExecContext(ctx,
		queryWriteRecordAdd,
		r.GroupID, r.ArtifactID, r.Version, r.SHA1, r.SHA256)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) CommitRecords(ctx context.Context) error {
	_, err := db.ExecContext(ctx, queryCommitRecords)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) ReadChainID(ctx context.Context) (string, error) {
	const key = `chain-id`
	value, err := db.readMeta(ctx, key)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	default:
		return "", err
	}

	return value, nil
}

func (db *DB) WriteChainID(ctx context.Context, id string) error {
	const key = `chain-id`
	return db.writeMeta(ctx, key, id)
}

func (db *DB) ReadLastIndex(ctx context.Context) (int, error) {
	const key = `last-incremental`
	value, err := db.readMeta(ctx, key)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	default:
		return 0, err
	}

	id, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (db *DB) WriteLastIndex(ctx context.Context, idx int) error {
	const key = `last-incremental`
	return db.writeMeta(ctx, key, strconv.Itoa(idx))
}

func (db *DB) readMeta(ctx context.Context, key string) (string, error) {
	var val string
	return val, db.QueryRowContext(ctx, queryReadMeta, key).Scan(&val)
}

func (db *DB) writeMeta(ctx context.Context, key, value string) error {
	_, err := db.ExecContext(ctx, queryWriteMeta, key, value)
	return err
}

var (
	//go:embed sql/setup.sql
	querySetup string
	//go:embed sql/write_record_add.sql
	queryWriteRecordAdd string
	//go:embed sql/write_record_remove.sql
	queryWriteRecordRemove string
	//go:embed sql/commit_records.sql
	queryCommitRecords string
	//go:embed sql/read_meta.sql
	queryReadMeta string
	//go:embed sql/write_meta.sql
	queryWriteMeta string
)

//go:generate find sql -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --fix {} ;
