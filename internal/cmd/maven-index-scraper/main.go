package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite"
)

const (
	scraperoot = `https://repo.maven.apache.org/maven2/`
	Trace      = slog.LevelDebug - 4
)

var rec = trace.NewFlightRecorder()

func main() {
	ctx := context.Background()
	var logLevel slog.LevelVar
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &logLevel,
	})))

	var databasePath string
	var indexRoot string
	debugLogFlag := flag.Bool("D", false, "debug logging")
	traceLogFlag := flag.Bool("DD", false, "trace logging")
	traceFlag := flag.Bool("trace", false, "write execution trace when sent USR1")
	flag.StringVar(&databasePath, "db", "index.db", "current state database")
	flag.StringVar(&indexRoot, "index", `https://repo.maven.apache.org/maven2/.index/`, "index root URL")
	flag.Parse()
	switch {
	case *debugLogFlag:
		logLevel.Set(slog.LevelDebug)
	case *traceLogFlag:
		logLevel.Set(Trace)
	}

	var wg sync.WaitGroup
	ctx, done := context.WithCancel(ctx)
	ctx, stop := signal.NotifyContext(ctx, unix.SIGINT, unix.SIGTERM)
	wg.Add(1)
	// Create a goroutine that immediately restores the default signal handler,
	// so ^C^C exits immediately.
	go func() {
		<-ctx.Done()
		stop()
		wg.Done()
	}()

	if *traceFlag {
		rec.SetSize(16 << 20)
		usr1 := make(chan os.Signal, 1)
		signal.Notify(usr1, unix.SIGUSR1)
		wg.Add(2)
		go func() {
			// On context cancellation, stop listening for USR1 and close the
			// channel relaying that signal.
			<-ctx.Done()
			signal.Stop(usr1)
			rec.Stop()
			close(usr1)
			wg.Done()
		}()
		go func() {
			// Read from the USR1 relay channel until closed.
			// Context cancellation is propagated from the above goroutine.
			defer wg.Done()
			n := 0
			for range usr1 {
				name := fmt.Sprintf("trace.out.%04d", n)
				l := slog.With("name", name)
				f, err := os.Create(name)
				if err != nil {
					l.ErrorContext(ctx, "unable to create trace output", "error", err)
					continue
				}
				n++
				if _, err := rec.WriteTo(f); err != nil {
					l.ErrorContext(ctx, "unable to write trace output", "error", err)
				}
				if err := f.Close(); err != nil {
					l.ErrorContext(ctx, "unable to close trace output", "error", err)
				}
				l.InfoContext(ctx, "wrote trace output")
			}
		}()
		rec.Start()
	}

	var err error
	go func() {
		defer done()
		var root *url.URL
		root, err = url.Parse(indexRoot)
		if err != nil {
			return
		}

		var db *DB
		db, err = OpenDB(ctx, databasePath)
		if err != nil {
			return
		}
		defer db.Close()
		err = Main(ctx, db, root)
	}()

	wg.Wait()
	if err != nil {
		os.Exit(1)
	}
}

func Main(ctx context.Context, db *DB, root *url.URL) error {
	client := new(http.Client)
	cur := NewHTTPResource(client, root)

	ir, err := NewIndexReader(ctx, db, cur)
	if err != nil {
		slog.ErrorContext(ctx, "unable to create index reader", "error", err)
		return err
	}
	slog.InfoContext(ctx, "attempting index update", "incremental", ir.CanIncremental())

	eg, ctx := errgroup.WithContext(ctx)
	ch := make(chan Record, runtime.NumCPU())
	eg.Go(func() error {
		defer close(ch)
		for cr, err := range ir.Chunks(ctx) {
			if err != nil {
				slog.ErrorContext(ctx, "unable to read chunk", "error", err)
				return err
			}
			for r, err := range cr.JARs() {
				if err != nil {
					slog.ErrorContext(ctx, "unable to read record", "error", err)
					return err
				}
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case ch <- r:
				}
			}
		}
		return nil
	})
	eg.Go(func() error {
		ct := 0
		start := time.Now()
		for r := range ch {
			if err := db.WriteRecord(ctx, r); err != nil {
				return err
			}
			ct++
			if ct&0x0f == 0 {
				slog.Log(ctx, Trace, "writing records", "count", ct)
			}
			if ct&0x03ff == 0 {
				rps := float64(ct) / time.Since(start).Seconds()
				slog.InfoContext(ctx, "writing records", "count", ct, "records_per_second", rps)
			}
		}
		return nil
	})

	// TODO(hank): write back index state

	return eg.Wait()
}

type DB struct {
	*sql.DB
}

// Exists implements Resource.
func (db *DB) Exists(context.Context, string) (bool, error) {
	return false, nil
}

// Open implements Resource.
func (db *DB) Open(context.Context, string) (io.ReadCloser, error) {
	return nil, fs.ErrNotExist
}

// Index implements Resource.
func (db *DB) Index(ctx context.Context) (Index, error) {
	rows, err := db.QueryContext(ctx, `SELECT key, value FROM meta;`)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return Index{}, nil
	default:
		return Index{}, err
	}
	defer rows.Close()

	var i Index
	var key, value string
	for rows.Next() {
		if err := rows.Scan(&key, &value); err != nil {
			return Index{}, err
		}
		switch key {
		case `id`:
			i.ID = value
		case `creation`:
			i.Creation, err = time.Parse(time.RFC3339, value)
		case `published`:
			i.Published, err = time.Parse(time.RFC3339, value)
		case `chain`:
			i.Chain = value
		case `last`:
			i.Last, err = strconv.Atoi(value)
		case `incremental`:
			for _, v := range strings.Split(value, ",") {
				var n int
				n, err = strconv.Atoi(v)
				if err != nil {
					break
				}
				i.Incremental = append(i.Incremental, n)
			}
		}
		if err != nil {
			return Index{}, err
		}
	}

	return i, rows.Err()
}

func OpenDB(ctx context.Context, f string) (*DB, error) {
	const dbSetup = `--
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS repository (
	groupId TEXT,
	artifactId TEXT,
	version TEXT,
	sha1 BLOB,
	sha256 BLOB,
	UNIQUE (groupId, artifactId, version) ON CONFLICT IGNORE,
	UNIQUE (sha1) ON CONFLICT REPLACE,
	UNIQUE (sha256) ON CONFLICT REPLACE
);
PRAGMA cache_size = 1048576; -- 1GiB of RAM
PRAGMA journal_mode = MEMORY;
PRAGMA locking_mode = EXCLUSIVE;
`
	db, err := sql.Open("sqlite", fmt.Sprintf("file:%s", f))
	if err != nil {
		slog.ErrorContext(ctx, "unable to open database", "error", err)
		return nil, err
	}
	if _, err := db.ExecContext(ctx, dbSetup); err != nil {
		slog.ErrorContext(ctx, "unable to set up database", "error", err)
		return nil, errors.Join(err, db.Close())
	}

	return &DB{db}, nil
}

func (db *DB) WriteRecord(ctx context.Context, r Record) error {
	_, err := db.ExecContext(ctx,
		`INSERT INTO repository (groupId, artifactId, version, sha1, sha256) VALUES (?,?,?,?,?);`,
		r.GroupID, r.ArtifactID, r.Version, r.SHA1, r.SHA256)
	if err != nil {
		return err
	}
	return nil
}

func (db *DB) ReadLastUpdated(ctx context.Context) (time.Time, error) {
	const key = `last_updated`
	value, err := db.readMeta(ctx, key)
	switch {
	case err == nil:
	case errors.Is(err, sql.ErrNoRows):
		return time.UnixMilli(0), nil
	default:
		return time.Time{}, err
	}

	return time.Parse(time.RFC3339, value)
}

func (db *DB) WriteLastUpdated(ctx context.Context, t time.Time) error {
	const key = `last_updated`
	value := t.Format(time.RFC3339)
	return db.writeMeta(ctx, key, value)
}

func (db *DB) readMeta(ctx context.Context, key string) (string, error) {
	const query = `SELECT value FROM meta WHERE key = ?;`
	var val string
	return val, db.QueryRowContext(ctx, query, key).Scan(&val)
}

func (db *DB) writeMeta(ctx context.Context, key, value string) error {
	const query = `INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value;`
	_, err := db.ExecContext(ctx, query, key, value)
	return err
}
