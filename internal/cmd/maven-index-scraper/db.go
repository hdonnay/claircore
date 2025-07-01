package main

import (
	"context"
	"database/sql"
	_ "embed" // for the sql queries
	"encoding/csv"
	"encoding/hex"
	"errors"
	"expvar"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
)

type Staging struct {
	artifacts *csv.Writer
	add       *csv.Writer
	remove    *csv.Writer
}

func (s *Staging) Record(ctx context.Context, r ExportRecord) error {
	rec := []string{r.GroupID, r.ArtifactID}
	s.artifacts.Write(rec)
	rec = append(rec, r.Version)
	if r.SHA1 != nil {
		rec = append(rec, hex.EncodeToString(r.SHA1))
		s.add.Write(rec)
	} else {
		s.remove.Write(rec)
	}
	return nil
}

// DB is a wrapper over a SQlite database containing the index state.
type DB struct {
	*sql.DB

	artifacts      strings.Builder
	record         strings.Builder
	add            *sql.Stmt
	remove         *sql.Stmt
	commit         *sql.Stmt
	insertArtifact *sql.Stmt
	added          expvar.Int
	removed        expvar.Int
}

func OpenDB(ctx context.Context, f string) (*DB, error) {
	name := fmt.Sprintf("file:%s", f)
	db, err := sql.Open("sqlite", name)
	if err != nil {
		slog.ErrorContext(ctx, "unable to open database", "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, querySetup); err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}
	addStmt, err := db.PrepareContext(ctx, queryWriteRecordAdd)
	if err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}
	removeStmt, err := db.PrepareContext(ctx, queryWriteRecordRemove)
	if err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}
	commitStmt, err := db.PrepareContext(ctx, queryCommitRecords)
	if err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}
	insertArtifactStmt, err := db.PrepareContext(ctx, queryInsertArtifact)
	if err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}

	r := DB{
		DB: db,

		add:            addStmt,
		remove:         removeStmt,
		commit:         commitStmt,
		insertArtifact: insertArtifactStmt,
	}
	m := new(expvar.Map)
	nv := new(expvar.String)
	nv.Set(name)
	m.Set("filename", nv)
	m.Set("added", &r.added)
	m.Set("removed", &r.removed)
	expvar.Publish("database", m)

	return &r, nil
}

func (db *DB) WriteRecord(ctx context.Context, r ExportRecord) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO artifact (groupId, artifactId) VALUES (? ,?) ON CONFLICT DO NOTHING`,
		r.ArtifactID, r.GroupID,
	)
	if err != nil {
		return err
	}
	if r.SHA1 != nil {
		db.added.Add(1)
		_, err = db.ExecContext(ctx,
			`INSERT INTO lookup (artifact, version, sha1) SELECT id, ?, ? FROM artifact WHERE groupId = ? AND artifactId = ? ON CONFLICT (sha1) DO UPDATE SET version = excluded.version`,
			r.Version, r.SHA1, r.ArtifactID, r.GroupID,
		)
	} else {
		db.removed.Add(1)
		_, err = db.ExecContext(ctx,
			`WITH a AS (SELECT id FROM artifact WHERE groupId = ? AND artifactId = ?) DELETE FROM lookup WHERE artifact = a.id AND version = ?`,
			r.ArtifactID, r.GroupID, r.Version,
		)
	}
	if err != nil {
		return err
	}

	return nil
}

var ErrCommitRunning = errors.New("commit already running")

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
	//go:embed sql/insert_artifact.sql
	queryInsertArtifact string
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
