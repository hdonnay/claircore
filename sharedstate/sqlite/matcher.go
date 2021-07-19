package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"runtime"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/sharedstate"
)

func (c *Config) Matcher(ctx context.Context) (sharedstate.Matcher, error) {
	const setup = `PRAGMA foreign_keys = ON;`
	db, err := sql.Open("sqlite", c.URI)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, setup); err != nil {
		db.Close()
		return nil, fmt.Errorf("unable to setup database: %w", err)
	}
	m := &matcher{db}
	_, file, line, _ := runtime.Caller(1)
	runtime.SetFinalizer(m, func(m *matcher) {
		panic(fmt.Sprintf("%s:%d: db handle not closed", file, line))
	})
	return &matcher{db}, nil
}

type matcher struct {
	*sql.DB
}

func (m *matcher) Close() error {
	runtime.SetFinalizer(m, nil)
	if err := m.DB.Close(); err != nil {
		return err
	}
	return nil
}

var _ sharedstate.Matcher = (*matcher)(nil)

func (m *matcher) UpdateEnrichments(ctx context.Context, kind string, fp driver.Fingerprint, es []driver.EnrichmentRecord) (uuid.UUID, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/UpdateEnrichments"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) UpdateVulnerabilities(ctx context.Context, updater string, fingerprint driver.Fingerprint, vulns []claircore.Vulnerability) (uuid.UUID, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/UpdateVulnerabilities"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetUpdateOperations(ctx context.Context, _ driver.UpdateKind, _ ...string) (map[string][]driver.UpdateOperation, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetUpdateOperations"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetLatestUpdateRefs(ctx context.Context, _ driver.UpdateKind) (map[string][]driver.UpdateOperation, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetLatestUpdateRefs"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetLatestUpdateRef(ctx context.Context, kind driver.UpdateKind) (uuid.UUID, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetLatestUpdateRef"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) DeleteUpdateOperations(ctx context.Context, refs ...uuid.UUID) (int64, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/DeleteUpdateOperations"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return 0, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetUpdateDiff(ctx context.Context, prev uuid.UUID, cur uuid.UUID) (*driver.UpdateDiff, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetUpdateDiff"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GC(ctx context.Context, keep int) (int64, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GC"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		Isolation: sql.LevelDefault,
	})
	if err != nil {
		return 0, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) Initialized(ctx context.Context) (bool, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/Initialized"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return false, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetVulnerability(ctx context.Context, _ []claircore.IndexRecord, _ []driver.Matcher, _ bool) (map[string][]claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetVulnerability"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}

func (m *matcher) GetEnrichment(ctx context.Context, kind string, tags []string) ([]driver.EnrichmentRecord, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "sharedstate/sqlite/matcher/GetEnrichment"))
	tx, err := m.DB.BeginTx(ctx, &sql.TxOptions{
		ReadOnly: true,
	})
	if err != nil {
		return nil, err
	}
	defer tx.Commit()
	panic("not implemented") // TODO: Implement
}
