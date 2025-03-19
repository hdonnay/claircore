package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	_ "modernc.org/sqlite"

	"github.com/quay/claircore/internal/xmlutil"
)

const (
	scraperoot = `https://repo.maven.apache.org/maven2/`
	Trace      = slog.LevelDebug - 4
)

func main() {
	ctx := context.Background()
	var logLevel slog.LevelVar
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &logLevel,
	})))

	debugFlag := flag.Bool("D", false, "debug logging")
	traceFlag := flag.Bool("DD", false, "trace logging")
	flag.Parse()
	switch {
	case *debugFlag:
		logLevel.Set(slog.LevelDebug)
	case *traceFlag:
		logLevel.Set(Trace)
	}

	if err := Main(ctx); err != nil {
		os.Exit(1)
	}
}

func Main(ctx context.Context) error {
	db, err := OpenDB(ctx, "maven.db")
	if err != nil {
		return err
	}
	defer db.Close()

	s, err := NewIndexScraper(scraperoot)
	if err != nil {
		slog.ErrorContext(ctx, "unable to create index scraper", "error", err)
		return err
	}

	lastUpdated, err := s.LastUpdated(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "unable to fetch updated", "error", err)
		return err
	}
	slog.InfoContext(ctx, "index update time", "at", lastUpdated)
	lastFetched, err := db.ReadLastUpdated(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "unable to read last_updated", "error", err)
		return err
	}
	slog.InfoContext(ctx, "last fetch time", "at", lastFetched)

	dur := lastUpdated.Sub(lastFetched)
	slog.InfoContext(ctx, "fetch delta", "ago", dur)
	if dur < (time.Hour * 12) {
		slog.InfoContext(ctx, "new enough, done")
		return nil
	}

	n := 0
	seq, errFunc := s.Metadata(ctx)
	for u, m := range seq {
		fmt.Printf("%v\t%#+v\n", u, m)
		if n++; n == 10 {
			break
		}
	}
	if err := errFunc(); err != nil {
		slog.ErrorContext(ctx, "error walking index", "error", err)
		return err
	}

	return nil
}

type IndexScraper struct {
	bufs sync.Pool
	c    *http.Client
	toks chan struct{}
	root *url.URL
}

func NewIndexScraper(root string) (*IndexScraper, error) {
	u, err := url.Parse(root)
	if err != nil {
		return nil, err
	}
	s := IndexScraper{
		c:    &http.Client{},
		toks: make(chan struct{}, 4),
		root: u,
	}
	return &s, nil
}

func (s *IndexScraper) getbuf() *bytes.Buffer {
	v := s.bufs.Get()
	if v == nil {
		const startSz = 1 << 16
		b := new(bytes.Buffer)
		b.Grow(startSz)
		v = b
	}
	return v.(*bytes.Buffer)
}

func (s *IndexScraper) putbuf(buf *bytes.Buffer) {
	const tooBig = 1 << 20
	if buf.Len() >= tooBig {
		return
	}
	buf.Reset()
	s.bufs.Put(buf)
}

func (s *IndexScraper) lim(ctx context.Context) (func(), error) {
	t := time.Now()
	select {
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	case s.toks <- struct{}{}:
		slog.Log(ctx, Trace, "got token", "waited", time.Since(t))
	}

	return func() { <-s.toks }, nil
}

func (s *IndexScraper) httpGet(ctx context.Context, u *url.URL) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	done, err := s.lim(ctx)
	if err != nil {
		return nil, err
	}
	defer done()

	slog.Log(ctx, Trace, "http request", "url", u)
	res, err := s.c.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%q: unexpected status: %v", u, res.Status)
	}
	return res, nil
}

func (s *IndexScraper) httpLoad(ctx context.Context, b *bytes.Buffer, u *url.URL) error {
	res, err := s.httpGet(ctx, u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if _, err := io.Copy(b, res.Body); err != nil {
		return err
	}

	return nil
}

type MatchFunc func(ps []string, tgt string) (ok bool, err error)

func (s *IndexScraper) walk(ctx context.Context, match MatchFunc, yield func(*url.URL) bool, ps []string) error {
	b := s.getbuf()
	defer s.putbuf(b)
	if err := s.httpLoad(ctx, b, s.root.JoinPath(ps...)); err != nil {
		return err
	}
	rd, err := newPageReader(ctx, b)
	if err != nil {
		return err
	}

	links := slices.Collect(rd.Links())
	links = slices.DeleteFunc(links, func(tgt string) bool {
		return tgt == "./" || tgt == "../"
	})
	slices.SortFunc(links, func(a, b string) int {
		aIsDir := strings.HasSuffix(a, "/")
		bIsDir := strings.HasSuffix(b, "/")
		switch {
		case aIsDir && !bIsDir:
			return 1
		case !aIsDir && bIsDir:
			return -1
		}
		return strings.Compare(a, b)
	})

	for _, tgt := range links {
		ok, err := match(ps, tgt)
		slog.DebugContext(ctx, "walk", "path", path.Join(ps...), "tgt", tgt, "ok", ok, "err", err)
		switch {
		case errors.Is(err, fs.SkipDir):
		case err != nil:
			return err
		case strings.HasSuffix(tgt, "/"):
			if err := s.walk(ctx, match, yield, append(ps, tgt)); err != nil {
				return err
			}
		default:
		}
		if ok {
			u := s.root.JoinPath(append(ps, tgt)...)
			if !yield(u) {
				return fs.SkipAll
			}
		}

		if errors.Is(err, fs.SkipDir) {
			break
		}
	}

	if err := rd.Err(); err != nil {
		return err
	}
	return nil
}

func (s *IndexScraper) Metadata(ctx context.Context) (iter.Seq2[*url.URL, Metadata], func() error) {
	var seqErr error
	findMetadata := func(yield func(*url.URL) bool) {
		match := func(ps []string, tgt string) (bool, error) {
			if tgt == `maven-metadata.xml` {
				return true, fs.SkipDir
			}
			return false, nil
		}
		seqErr = errors.Join(seqErr, s.walk(ctx, match, yield, make([]string, 0, 5)))
	}

	seq := func(yield func(*url.URL, Metadata) bool) {
		for md := range findMetadata {
			var m Metadata

			u, _ := md.Parse(".")
			err := func() error {
				res, err := s.httpGet(ctx, md)
				if err != nil {
					return err
				}
				defer res.Body.Close()
				dec := xml.NewDecoder(res.Body)
				dec.CharsetReader = xmlutil.CharsetReader
				return dec.Decode(&m)
			}()
			if err != nil {
				seqErr = errors.Join(seqErr, err)
				return
			}
			if len(m.Versioning.Versions) == 0 {
				slog.InfoContext(ctx, "skipping directory", "url", u)
				continue
			}
			slog.InfoContext(ctx, "found directory", "url", u)
			if !yield(u, m) {
				return
			}
		}
	}

	return seq, func() error {
		if seqErr == nil || errors.Is(seqErr, fs.SkipAll) {
			return nil
		}
		return seqErr
	}
}

func (s *IndexScraper) LastUpdated(ctx context.Context) (time.Time, error) {
	p := `last_updated.txt` // Wed Mar 19 15:15:59 UTC 2025
	b := s.getbuf()
	defer s.putbuf(b)
	if err := s.httpLoad(ctx, b, s.root.JoinPath(p)); err != nil {
		return time.Time{}, err
	}
	value := strings.TrimSpace(b.String())
	return time.Parse(time.UnixDate, value)
}

func newPageReader(ctx context.Context, r io.Reader) (*pageReader, error) {
	p := pageReader{
		ctx: ctx,
		tok: html.NewTokenizer(r),
	}

	return &p, nil
}

type pageReader struct {
	ctx context.Context
	tok *html.Tokenizer
	err error
}

func (p *pageReader) Err() error {
	if p.err != nil {
		return p.err
	}
	return nil
}

func (p *pageReader) Links() iter.Seq[string] {
	return func(yield func(string) bool) {
	Next:
		for ty := p.tok.Next(); ty != html.ErrorToken; ty = p.tok.Next() {
			if ty != html.StartTagToken {
				continue
			}
			name, hasAttr := p.tok.TagName()
			if atom.Lookup(name) != atom.A || !hasAttr {
				continue
			}
			for {
				k, v, more := p.tok.TagAttr()
				if atom.Lookup(k) == atom.Href {
					if !yield(string(v)) {
						return
					}
					continue Next
				}
				if !more {
					break
				}
			}
		}
		err := p.tok.Err()
		if !errors.Is(err, io.EOF) {
			p.err = fmt.Errorf("unexpected error reading page: %w", err)
		}
	}
}

const dbSetup = `--
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS maven (
	groupId TEXT,
	artifactId TEXT,
	version TEXT,
	sha1 BLOB
);
`

type DB struct {
	*sql.DB
}

func OpenDB(ctx context.Context, f string) (*DB, error) {
	db, err := sql.Open("sqlite", "file:"+f)
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
