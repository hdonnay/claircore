//go:build go1.23 || (go1.22 && goexperiment.rangefunc)

package postgres

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/quay/zlog"

	"github.com/quay/claircore/updater/driver/v1"
)

func (u *Matcher) UpdaterRun(ctx context.Context, ref uuid.UUID) (*UpdateCycle, error) {
	return nil, nil
}

type UpdateCycle struct {
	pool *pgxpool.Pool
}

func (r *UpdateCycle) New(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint) (*UpdaterRun, error) {
	return nil, nil
}
func (r *UpdateCycle) Close() error {
	return nil
}

type UpdaterRun struct {
	isDeltaOnce sync.Once
	isDelta     bool
	err         error

	id   int64
	gen  int64
	conn *pgxpool.Conn
}

var errSingleUpdateBotch = errors.New("TODO")

func (u *UpdaterRun) Previous(ctx context.Context) (driver.UpdateOperation, bool, error) {
	var op driver.UpdateOperation
	return op, false, nil
}

// ...
//
// Exclusive with [Set].
func (u *UpdaterRun) Add(ctx context.Context, vs iter.Seq2[driver.Vulnerability, error]) error {
	u.isDeltaOnce.Do(u.markIsDelta)
	if !u.isDelta {
		return errSingleUpdateBotch
	}

	return nil
}

// ...
//
// Exclusive with [Set].
func (u *UpdaterRun) Remove(ctx context.Context, vs iter.Seq2[driver.Vulnerability, error]) error {
	u.isDeltaOnce.Do(u.markIsDelta)
	if !u.isDelta {
		return errSingleUpdateBotch
	}

	return nil
}

// ...
//
// Exclusive with [Add]/[Remove].
func (u *UpdaterRun) Set(ctx context.Context, vs iter.Seq2[driver.Vulnerability, error]) error {
	u.isDeltaOnce.Do(u.markNotDelta)
	if u.isDelta {
		return errSingleUpdateBotch
	}

	opts := pgx.TxOptions{}
	err := u.conn.BeginTxFunc(ctx, opts, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_import LIKE matcher_v2.advisory_import_template ON COMMIT DROP;`)
		_ = tag // TODO(hank) Metrics
		if err != nil {
			return err
		}
		src := advisoryCopySource(ctx, vs)
		ct, err := tx.CopyFrom(ctx, []string{"advisory_import"}, src.Names(), src)
		_ = ct // TODO(hank) Metrics
		if err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (u *UpdaterRun) markIsDelta() {
	u.isDelta = true
}

func (u *UpdaterRun) markNotDelta() {}

func (u *UpdaterRun) Close(ctx context.Context) error {
	// Flush/merge?
	if u.err != nil {
		// TODO(hank) embed
		const markError = `UPDATE matcher_v2.updater_run SET error = $2 WHERE id = $1`
		tag, err := u.conn.Exec(ctx, markError, u.id, u.err.Error())
		_ = tag // TODO(hank) Metrics

		return errors.Join(err, u.err)
	}

	return nil
}

func (u *Matcher) UpdateVulnerabilities(ctx context.Context, ref uuid.UUID, updater string, fp driver.Fingerprint, vs driver.ParsedVulnerabilities) error {
	opts := pgx.TxOptions{}
	tx, err := u.pool.BeginTx(ctx, opts)
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to start transaction: %w", err)
	}
	defer func() {
		switch err := tx.Rollback(ctx); {
		case errors.Is(err, nil):
		case errors.Is(err, pgx.ErrTxClosed):
		default:
			zlog.Warn(ctx).
				Err(err).
				Msg("error rolling back transaction")
		}
	}()
	//
	// Create a run:
	var runid int64
	err = tx.QueryRow(ctx, `
		WITH u AS (SELECT id FROM updater_v1.updater WHERE name = $2)
		INSERT INTO updater_v1.run ( ref, updater, fingerprint) VALUES ($1, u.id, $3::jsonb) RETURNING id;`, ref, updater, string(fp)).Scan(&runid)
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create run: %w", err)
	}

	// Bulk load advisories:
	tag, err := tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_new LIKE updater_v1.advisory ON COMMIT DROP;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("temporary table creation")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create temporary advisory table: %w", err)
	}
	src := advisoryCopySource(ctx, runid, vs)
	nrow, err := tx.CopyFrom(ctx, pgx.Identifier([]string{"advisory_new"}), src.Names(), src)
	zlog.Debug(ctx).
		Int64("count", nrow).
		Msg("temporary advisory copy")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to populate temporary advisory table: %w", err)
	}
	tag, err = tx.Exec(ctx, `MERGE INTO updater_v1.advisory a USING advisory_new n ON a.namespace = n.namespace AND a.name = n.name
	WHEN MATCHED THEN UPDATE SET a.generation = n.generation
	WHEN NOT MATCHED THEN INSERT (added, generation, namespace, name) VALUES
		(n.generation, n.generation, n.namespace, n.name)
	;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("advisory merge")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to merge into advisory table: %w", err)
	}

	// Bulk load metadata:
	tag, err = tx.Exec(ctx, `CREATE TEMPORARY TABLE UNLOGGED advisory_meta_load (
		namespace TEXT,
		name TEXT,
		issued TIMESTAMPTZ,
		summary TEXT NOT NULL,
		description TEXT NOT NULL,
		uri TEXT,
		severity TEXT,
		normalized_severity TEXT,
		cvss3 TEXT
	) ON COMMIT DROP;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("temporary table creation")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to create temporary table: %w", err)
	}
	msrc := advisoryMetaCopySource(&vs)
	nrow, err = tx.CopyFrom(ctx, pgx.Identifier([]string{"advisory_meta_load"}), msrc.Names(), msrc)
	zlog.Debug(ctx).
		Int64("count", nrow).
		Msg("temporary advisory copy")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to populate temporary advisory table: %w", err)
	}

	tag, err = tx.Exec(ctx, `MERGE INTO updater_v1.advisory_meta a
	USING
		(SELECT a.id, n.* FROM advisory_meta_load n JOIN advisory a ON a.namespace = n.namespace AND a.name = n.name) n 
		ON a.id = n.id
	WHEN MATCHED THEN UPDATE SET (issued, summary, description, uri, severity, normalized_severity) =
		(n.issued, n.summary, n.description, n.uri, n.severity, n.normalized_severity)
	WHEN NOT MATCHED THEN INSERT (advisory, issued, summary, description, uri, severity, normalized_severity) VALUES
		(n.id, n.issued, n.summary, n.description, n.uri, n.severity, n.normalized_severity)
	;`)
	zlog.Debug(ctx).
		Stringer("tag", tag).
		Msg("advisory merge")
	if err != nil {
		return fmt.Errorf("postgres: UpdaterV1: unable to merge into advisory_meta table: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		// TODO(hank) Remove log-and-return.
		zlog.Warn(ctx).
			Err(err).
			Msg("error committing transaction")
		return fmt.Errorf("postgres: UpdaterV1: unable to commit transaction: %w", err)
	}
	return nil
}

func advisoryMetaCopySource(vs *driver.ParsedVulnerabilities) *metaAdvisorySource {
	row := make([]interface{}, 9)
	return &metaAdvisorySource{
		vs:  vs,
		row: row,
	}
}

var _ pgx.CopyFromSource = (*metaAdvisorySource)(nil)

type metaAdvisorySource struct {
	vs  *driver.ParsedVulnerabilities
	pos int
	// Ch is a token channel to pass control between the goroutine calling
	// exported methods and the "push" goroutine.
	ch chan struct{}

	err error
	row []interface{}
}

func (src *metaAdvisorySource) Next() bool {
	return src.pos < len(src.vs.Vulnerability)
}
func (src *metaAdvisorySource) Values() ([]interface{}, error) {
	v := &src.vs.Vulnerability[src.pos]
	src.pos++
	src.row[1] = v.Namespace
	src.row[2] = v.Name
	return src.row, nil
}
func (src *metaAdvisorySource) Err() error {
	return nil
}
func (src *metaAdvisorySource) Names() []string {
	return []string{"generation", "namespace", "name"}
}
