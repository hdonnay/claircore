package postgres

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/quay/claircore/datastore/postgres/v2/internal/o11y"
	"github.com/quay/zlog"
)

// Configure returns a copy of the passed [pgxpool.Config] modified with
// observability hooks and other needed settings.
//
// Any existing hooks will still be called.
func Configure(ctx context.Context, cfg *pgxpool.Config) *pgxpool.Config {
	cfg = cfg.Copy()

	if f := cfg.AfterConnect; f != nil {
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			return errors.Join(
				f(ctx, conn),
				registerDataTypes(ctx, conn),
			)
		}
	} else {
		cfg.AfterConnect = registerDataTypes
	}

	o11y.SetHooks(cfg)
	o11y.SetTracer(cfg)
	cfg.ConnConfig.OnNotice = noticeHandler(ctx)

	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	// emulate "fallback_application_name"
	if _, exist := cfg.ConnConfig.RuntimeParams["application_name"]; !exist {
		name := "claircore/v4"
		if mode := os.Getenv("CLAIR_MODE"); mode != "" && mode != "combo" {
			name += "/" + mode
		}
		cfg.ConnConfig.RuntimeParams["application_name"] = name
	}
	cfg.ConnConfig.RuntimeParams["client_encoding"] = "UTF8"

	if cfg.ConnConfig.ConnectTimeout <= 0 {
		cfg.ConnConfig.ConnectTimeout = 30 * time.Second
	}

	return cfg
}

// TokenFunc is a function that reports a pagination token for the last value
// read from a paired iterator.
type TokenFunc func() string

// SanityCheck runs a bunch of status checks against a database.
//
// [pgconn.PgConn.ParameterStatus] keys:
// - application_name
// - is_superuser
// - client_encoding
// - scram_iterations
// - DateStyle
// - server_encoding
// - default_transaction_read_only
// - server_version
// - in_hot_standby
// - session_authorization
// - integer_datetimes
// - standard_conforming_strings
// - IntervalStyle
// - TimeZone
func sanityCheck(ctx context.Context, workMem *int64, migrationTable string, schemaVer int) func(*pgxpool.Conn) error {
	const minDBVersion int64 = 15
	return func(conn *pgxpool.Conn) error {
		ll := conn.Conn().PgConn()

		// Check parameters returned from the database:
		param := ll.ParameterStatus("server_version")
		pgMaj, _ /*pgMin*/, ok := strings.Cut(param, ".")
		if !ok {
			return fmt.Errorf("unable to determine database version: weird format: %q", param)
		}
		pgVersion, err := strconv.ParseInt(pgMaj, 10, 0)
		if err != nil {
			return fmt.Errorf("unable to determine database version: %w", err)
		}
		if got, want := pgVersion, minDBVersion; got < want {
			return fmt.Errorf("database version too low: %d < %d", got, want)
		}
		if got, want := ll.ParameterStatus("client_encoding"), "UTF8"; got != want {
			return fmt.Errorf("bad client encoding: client_encoding == %q (need %q)", got, want)
		}
		if got, want := ll.ParameterStatus("standard_conforming_strings"), "on"; got != want {
			return fmt.Errorf("need standard conforming strings: standard_conforming_strings == %v", got == want)
		}

		// Check migration version:
		var migrationVersion int
		if err := conn.QueryRow(ctx, initSelectVersion, migrationTable).Scan(&migrationVersion); err != nil {
			return fmt.Errorf("unable to determine version: %w", err)
		}
		if got, want := migrationVersion, schemaVer; got < want {
			return fmt.Errorf("schema version too low: %d < %d (run migrations)", got, want)
		}

		// Query the server's `work_mem`:
		var setting string
		if err := conn.QueryRow(ctx, initSelectWorkMem).Scan(&setting); err != nil {
			return fmt.Errorf("unable to determine work_mem: %w", err)
		}
		mem, err := strconv.ParseInt(setting, 10, 64)
		if err != nil {
			return fmt.Errorf("unable to determine work_mem: %w", err)
		}
		*workMem = mem
		return nil
	}
}

// NoticeHandler returns a handler to log notices from the database, using the
// passed Context.
func noticeHandler(ctx context.Context) func(*pgconn.PgConn, *pgconn.Notice) {
	return func(conn *pgconn.PgConn, n *pgconn.Notice) {
		if n.Code == "LOG00" && n.SchemaName == `matcher_v2_meta` && n.TableName == `log` {
			ev := zlog.Info(ctx).Bool("database_log", true)
			kind, msg, ok := strings.Cut(n.Message, ": ")
			if !ok {
				ev.
					Str("raw_message", n.Message).
					Msg("odd database-side log line")
				return
			}
			if n.Detail != "" {
				ev = ev.RawJSON("event", []byte(n.Detail))
			}
			ev.
				Str("kind", kind).
				Msg(msg)
			return
		}
		ev := zlog.Info(ctx)
		switch n.Severity {
		case "ERROR", "FATAL", "PANIC":
			ev.Discard()
			ev = zlog.Error(ctx)
		case "WARNING":
			ev.Discard()
			ev = zlog.Warn(ctx)
		case "NOTICE", "INFO", "LOG":
		default:
			ev.Discard()
			return
		}
		ev.
			Uint32("pid", conn.PID()).
			Interface("notice", n).
			Msg("database notice")
	}
}
