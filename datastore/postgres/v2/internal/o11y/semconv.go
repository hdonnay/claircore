package o11y

import (
	"fmt"
	"net"
	"strconv"
	"unique"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// This file is extra metric and trace attributes, ala the [semconv] package.

// Additional PostgreSQL attributes.
const (
	DBPostgresqlPIDKey           = attribute.Key("db.postgresql.pid")
	DBPostgresqlCopyFromTableKey = attribute.Key("db.postgresql.copy_from.table")
	DBPostgresqlRowsAffectedKey  = attribute.Key("db.postgresql.rows_affected")
)

// Additional database attributes.
const (
	DBQueryNameKey = attribute.Key("db.query.name")
	DBUserKey      = attribute.Key("db.user") // Now deprecated, still useful.

	DBPoolNameKey  = attribute.Key("db.client.connection.pool.name")
	DBConnStateKey = attribute.Key("db.client.connection.state")
)

// The two defined connection states.
var (
	DBConnStateIdle = DBConnStateKey.String("idle")
	DBConnStateUsed = DBConnStateKey.String("used")
)

// PostgresqlPID returns an attribute recording the pid of the server-side
// process.
func PostgresqlPID(pid uint32) attribute.KeyValue {
	return DBPostgresqlPIDKey.Int(int(pid))
}

// PostgresqlCopyFromTable returns an attribute recording the table that's used
// as the target for a COPY command.
//
// Note that this is the table records are being inserted into. The actual SQL
// command reads like:
//
//	COPY "table" FROM 'source';
func PostgresqlCopyFromTable(t string) attribute.KeyValue {
	return DBPostgresqlCopyFromTableKey.String(t)
}

// PostgresqlRowsAffected returns an attribute recording the number of affected
// rows.
func PostgresqlRowsAffected(ct int64) attribute.KeyValue {
	return DBPostgresqlRowsAffectedKey.Int64(ct)
}

// DBQueryAttr returns an attribute recording either a developer-friendly name
// for the query or the query text.
func DBQueryAttr(query string) attribute.KeyValue {
	name, ok := nameLookup[unique.Make(query)]
	if ok {
		return DBQueryNameKey.String(name)
	}
	return semconv.DBQueryText(query)
}

// DBUser returns an attribute recording the name of user (role) being used to
// connect to the database.
func DBUser(user string) attribute.KeyValue {
	return DBUserKey.String(user)
}

// DBPoolName returns an attribute recording the name of connection pool.
func DBPoolName(cfg *pgx.ConnConfig) attribute.KeyValue {
	return DBPoolNameKey.String(fmt.Sprintf("%s/%s",
		net.JoinHostPort(cfg.Host, strconv.Itoa(int(cfg.Port))),
		cfg.Database))
}
