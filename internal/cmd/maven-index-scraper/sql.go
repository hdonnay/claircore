package main

import (
	"context"
	"database/sql"
	"embed" // for SQL statements
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"unique"

	"zombiezen.com/go/sqlite"
	"zombiezen.com/go/sqlite/sqlitex"

	"github.com/quay/claircore/internal/mavenindex"
)

//go:generate find sql -name *.sql -exec go run github.com/wasilibs/go-sql-formatter/v15/cmd/sql-formatter@latest --language sqlite --fix {} ;

//go:embed sql/*.sql
var queries embed.FS

type LocalIndex struct {
	conn *sqlite.Conn

	artifact        map[unique.Handle[mavenindex.Artifact]]struct{}
	lookup          map[unique.Handle[dbVersion]][]byte
	writtenArtifact map[unique.Handle[mavenindex.Artifact]]struct{}
}

type dbVersion struct {
	Artifact unique.Handle[mavenindex.Artifact]
	Version  string
}

func NewLocalIndex(ctx context.Context, p string) (*LocalIndex, error) {
	conn, err := sqlite.OpenConn("file:"+p, sqlite.OpenReadWrite, sqlite.OpenCreate, sqlite.OpenURI)
	if err != nil {
		slog.ErrorContext(ctx, "unable to open database", "error", err)
		return nil, err
	}
	if err := sqlitex.ExecuteScriptFS(conn, queries, "sql/setup.sql", nil); err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, err
	}

	l := LocalIndex{
		conn:            conn,
		artifact:        make(map[unique.Handle[mavenindex.Artifact]]struct{}),
		lookup:          make(map[unique.Handle[dbVersion]][]byte),
		writtenArtifact: make(map[unique.Handle[mavenindex.Artifact]]struct{}),
	}

	return &l, nil
}

func (l *LocalIndex) Changes(num int) (*Changes, error) {
	session, err := l.conn.CreateSession("main")
	if err != nil {
		return nil, err
	}
	if err := session.Attach(""); err != nil {
		session.Delete()
		return nil, err
	}

	c := Changes{
		conn:     l.conn,
		session:  session,
		artifact: make(map[unique.Handle[mavenindex.Artifact]]struct{}),
		lookup:   make(map[unique.Handle[dbVersion]][]byte),

		Number: num,
	}

	return &c, nil
}

type Changes struct {
	conn    *sqlite.Conn
	session *sqlite.Session

	artifact map[unique.Handle[mavenindex.Artifact]]struct{}
	lookup   map[unique.Handle[dbVersion]][]byte

	Number int
}

func (c *Changes) Enqueue(ctx context.Context, r mavenindex.Record) error {
	a := unique.Make(r.Artifact)
	c.artifact[a] = struct{}{}
	v := unique.Make(dbVersion{
		Artifact: a,
		Version:  r.Version,
	})
	if len(r.SHA1) != 0 {
		c.lookup[v] = r.SHA1
	} else {
		c.lookup[v] = nil
	}

	if len(c.lookup) > 16*1024 { // Just some amount of batching...
		return c.Flush(ctx)
	}
	return nil
}

func (c *Changes) Flush(ctx context.Context) (err error) {
	done, err := sqlitex.ImmediateTransaction(c.conn)
	if err != nil {
		return err
	}
	defer done(&err)

	// Write any new artifact IDs into the import table:
	for a := range c.artifact {
		v := a.Value()
		opts := &sqlitex.ExecOptions{
			Named: map[string]any{
				":artifactId": v.ArtifactID,
				":groupId":    v.GroupID,
			},
		}
		err = sqlitex.ExecuteFS(c.conn, queries, "sql/insert_artifact.sql", opts)
		if err != nil {
			err = fmt.Errorf("artifact: %#v: %w", v, err)
			return err
		}
	}

	// Write new versions:
	for ver, sum := range c.lookup {
		v := ver.Value()
		a := v.Artifact.Value()
		opts := &sqlitex.ExecOptions{
			Named: map[string]any{
				":artifactId": a.ArtifactID,
				":groupId":    a.GroupID,
				":version":    v.Version,
				":sha1":       sum,
			},
		}

		if len(sum) != 0 {
			err = sqlitex.ExecuteFS(c.conn, queries, "sql/add_version.sql", opts)
		} else {
			err = sqlitex.ExecuteFS(c.conn, queries, "sql/remove_version.sql", opts)
		}
		if err != nil {
			err = fmt.Errorf("artifact: %#v, version: %#v: %w", a, v, err)
			return err
		}
	}
	// Clear the queued data:
	clear(c.artifact)
	clear(c.lookup)

	return nil
}

func (c *Changes) Close(ctx context.Context) (err error) {
	c.session.Disable()
	defer func() {
		c.session.Delete()
		c.session = nil
	}()

	f, err := os.Create(fmt.Sprintf("repository.%03d.changeset", c.Number))
	if err != nil {
		return err
	}
	if err := c.session.WriteChangeset(f); err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	metaConflict := func(ty sqlite.ConflictType, it *sqlite.ChangesetIterator) sqlite.ConflictAction {
		panic("unimplemented")
	}

	artifactConflict := func(ty sqlite.ConflictType, it *sqlite.ChangesetIterator) sqlite.ConflictAction {
		panic("unimplemented")
	}

	lookupConflict := func(ty sqlite.ConflictType, it *sqlite.ChangesetIterator) sqlite.ConflictAction {
		panic("unimplemented")
	}

	var conflictErr error
	err = c.conn.ApplyChangeset(f, nil, func(ty sqlite.ConflictType, it *sqlite.ChangesetIterator) sqlite.ConflictAction {
		op, err := it.Operation()
		if err != nil {
			conflictErr = err
			return sqlite.ChangesetAbort
		}
		switch op.TableName {
		case "meta":
			return metaConflict(ty, it)
		case "artifact":
			return artifactConflict(ty, it)
		case "lookup":
			return lookupConflict(ty, it)
		default:
			panic("unexpected table: " + op.TableName)
		}
	})

	return errors.Join(conflictErr, err)
}

func (l *LocalIndex) Enqueue(r mavenindex.Record) {
	a := unique.Make(r.Artifact)
	l.artifact[a] = struct{}{}
	v := unique.Make(dbVersion{
		Artifact: a,
		Version:  r.Version,
	})
	if len(r.SHA1) != 0 {
		l.lookup[v] = r.SHA1
	} else {
		l.lookup[v] = nil
	}
}

func (w *LocalIndex) ReadChainID(ctx context.Context) (string, error) {
	const key = `chain-id`
	value, err := w.readMeta(ctx, key)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return "", nil
	default:
		return "", err
	}

	return value, nil
}

func (l *LocalIndex) WriteChainID(ctx context.Context, id string) error {
	const key = `chain-id`
	return l.writeMeta(ctx, key, id)
}

func (l *LocalIndex) ReadLastIndex(ctx context.Context) (int, error) {
	const key = `last-incremental`
	value, err := l.readMeta(ctx, key)
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

func (l *LocalIndex) WriteLastIndex(ctx context.Context, idx int) error {
	const key = `last-incremental`
	return l.writeMeta(ctx, key, strconv.Itoa(idx))
}

func (l *LocalIndex) readMeta(ctx context.Context, key string) (string, error) {
	var val string
	opts := &sqlitex.ExecOptions{
		Named: map[string]any{
			":key": key,
		},
		ResultFunc: func(stmt *sqlite.Stmt) (err error) {
			val, err = sqlitex.ResultText(stmt)
			return err
		},
	}
	return val, sqlitex.ExecuteFS(l.conn, queries, `sql/read_meta.sql`, opts)
}

func (l *LocalIndex) writeMeta(ctx context.Context, key, value string) error {
	opts := &sqlitex.ExecOptions{
		Named: map[string]any{
			":key":   key,
			":value": value,
		},
	}
	return sqlitex.ExecuteFS(l.conn, queries, `sql/write_meta.sql`, opts)
}

var (
	//go:embed sql/setup.sql
	querySetup string
	//go:embed sql/insert_artifact.sql
	queryInsertArtifact string
	//go:embed sql/write_record_add.sql
	queryWriteRecordAdd string
	//go:embed sql/write_record_remove.sql
	queryWriteRecordRemove string
	//go:embed sql/read_meta.sql
	queryReadMeta string
	//go:embed sql/write_meta.sql
	queryWriteMeta string
)

func (w *LocalIndex) Close(_ context.Context) error {
	return w.conn.Close()
}
