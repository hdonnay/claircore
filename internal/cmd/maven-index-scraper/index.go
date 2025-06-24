package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	indexFilePrefix = `nexus-maven-repository-index`
	indexTimeFmt    = `20060102150405.000 Z0700`
)

func NewIndexReader(ctx context.Context, prev, cur Resource) (*IndexReader, error) {
	ir := IndexReader{
		cur:  cur,
		prev: prev,
	}

	if cur == nil {
		return nil, fmt.Errorf(`"cur" Resource is nil`)
	}
	var err error
	ir.curState, err = cur.Index(ctx)
	if err != nil {
		return nil, err
	}
	if prev != nil {
		ir.prevState, err = prev.Index(ctx)
		if err != nil {
			return nil, err
		}
	}

	return &ir, nil
}

type IndexReader struct {
	curState, prevState Index

	cur, prev   Resource
	incremental *bool
}

func (i *IndexReader) CanIncremental() (ok bool) {
	if i.incremental != nil {
		return *i.incremental
	}
	defer func() {
		i.incremental = &ok
	}()

	if i.prev == nil {
		return false
	}
	if i.curState.Chain != i.prevState.Chain {
		return false
	}
	if i.prevState.Last == i.curState.Last {
		return true
	}

	return slices.Contains(i.curState.Incremental, i.prevState.Last+1)
}

func (i *IndexReader) Chunks(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	if !i.CanIncremental() {
		return i.fullIndex(ctx)
	}
	return i.incrementalIndex(ctx)
}

func (i *IndexReader) fullIndex(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	return func(yield func(*ChunkReader, error) bool) {
		rc, err := i.cur.Open(ctx, indexFilePrefix+`.gz`)
		if err != nil {
			yield(nil, err)
			return
		}
		defer rc.Close()
		z, err := gzip.NewReader(bufio.NewReaderSize(rc, 1<<20))
		if err != nil {
			yield(nil, err)
			return
		}
		defer z.Close()

		cr, err := NewChunkReader(z)
		slog.DebugContext(ctx, "full chunk reader created", "reader", cr, "error", err)
		yield(cr, err)
	}
}

func (i *IndexReader) incrementalIndex(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	done := errors.New("iteration done")
	return func(yield func(*ChunkReader, error) bool) {
		for _, n := range i.curState.Incremental {
			if n <= i.prevState.Last {
				continue
			}
			name := fmt.Sprintf(`%s.%d.gz`, indexFilePrefix, n)
			err := func() error {
				rc, err := i.cur.Open(ctx, name)
				if err != nil {
					return err
				}
				defer rc.Close()
				z, err := gzip.NewReader(rc)
				if err != nil {
					return err
				}
				defer z.Close()

				cr, err := NewChunkReader(z)
				slog.DebugContext(ctx, "incremental chunk reader created", "reader", cr, "error", err)
				if err != nil {
					return err
				}
				if !yield(cr, nil) {
					return done
				}
				return nil
			}()
			switch {
			case err == nil:
			case errors.Is(err, done):
				return
			default:
				yield(nil, err)
				return
			}
		}
	}
}

var (
	_ Resource = (*HTTPResource)(nil)
	_ Resource = (*FSResource)(nil)
)

type HTTPResource struct {
	c    *http.Client
	root *url.URL
}

func NewHTTPResource(c *http.Client, root *url.URL) *HTTPResource {
	return &HTTPResource{
		c:    c,
		root: root,
	}
}

// Exists implements Resource.
func (r *HTTPResource) Exists(ctx context.Context, name string) (bool, error) {
	u := r.root.JoinPath(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u.String(), nil)
	if err != nil {
		return false, err
	}
	res, err := r.c.Do(req)
	if err != nil {
		return false, err
	}
	res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected response status: %s", res.Status)
	}
}

// Open implements Resource.
func (r *HTTPResource) Open(ctx context.Context, name string) (io.ReadCloser, error) {
	u := r.root.JoinPath(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	res, err := r.c.Do(req)
	if err != nil {
		return nil, err
	}
	switch res.StatusCode {
	case http.StatusOK:
	default:
		res.Body.Close()
		return nil, fmt.Errorf("unexpected response status: %s", res.Status)
	}

	return res.Body, nil
}

func (r *HTTPResource) Index(ctx context.Context) (Index, error) {
	propsURL := r.root.JoinPath(indexFilePrefix + ".properties")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, propsURL.String(), nil)
	if err != nil {
		return Index{}, err
	}
	res, err := r.c.Do(req)
	if err != nil {
		return Index{}, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return Index{}, fmt.Errorf("unexpected response status: %s", res.Status)
	}

	var idx Index
	if err := idx.Parse(res.Body); err != nil {
		return Index{}, err
	}
	return idx, nil
}

type FSResource struct {
	sys fs.FS
}

func NewFSResource(sys fs.FS) *FSResource {
	return &FSResource{
		sys: sys,
	}
}

// Exists implements Resource.
func (f *FSResource) Exists(_ context.Context, name string) (bool, error) {
	_, err := fs.Stat(f.sys, name)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
	return true, nil
}

// Index implements Resource.
func (f *FSResource) Index(_ context.Context) (Index, error) {
	p, err := f.sys.Open(indexFilePrefix + ".properties")
	if err != nil {
		return Index{}, err
	}
	defer p.Close()

	var idx Index
	if err := idx.Parse(p); err != nil {
		return Index{}, err
	}
	return idx, nil
}

// Open implements Resource.
func (f *FSResource) Open(_ context.Context, name string) (io.ReadCloser, error) {
	return f.sys.Open(name)
}

type Resource interface {
	Index(context.Context) (Index, error)
	Open(context.Context, string) (io.ReadCloser, error)
	Exists(context.Context, string) (bool, error)
}

type Index struct {
	ID        string
	Creation  time.Time
	Published time.Time
	Chain     string

	Last        int
	Incremental []int
}

func (i *Index) Parse(r io.Reader) error {
	s := bufio.NewScanner(r)
	m := make(map[string]string)
	for s.Scan() {
		if b := s.Bytes(); b[0] == '#' || len(b) == 0 {
			continue
		}
		key, value, ok := strings.Cut(s.Text(), "=")
		if !ok { // ???
			return fmt.Errorf("bad/unknown line: %q", s.Text())
		}
		m[strings.TrimPrefix(key, `nexus.index.`)] = value
	}
	if err := s.Err(); err != nil {
		return err
	}

	var err error
	i.ID = m[`id`]
	i.Chain = m[`chain-id`]
	i.Published, err = time.Parse(indexTimeFmt, m[`timestamp`])
	if err != nil {
		return err
	}
	i.Creation, err = time.Parse(indexTimeFmt, m[`time`])
	if err != nil {
		return err
	}
	i.Last, err = strconv.Atoi(m[`last-incremental`])
	if err != nil {
		return err
	}

	for ct := 0; ; ct++ {
		v, ok := m[fmt.Sprintf(`incremental-%d`, ct)]
		if !ok {
			break
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return err
		}
		i.Incremental = append(i.Incremental, n)
	}

	return nil
}

// All numbers in the index format are big endian.
var be = binary.BigEndian

// All timestamps are milliseconds.

func readTimestamp(rd *bufio.Reader) (time.Time, error) {
	b, err := rd.Peek(8)
	if err != nil {
		return time.Time{}, err
	}
	defer rd.Discard(8)
	ts := int64(be.Uint64(b))
	return time.UnixMilli(ts), nil
}

func parseTimestamp(s string) (time.Time, error) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ts), nil
}

func NewChunkReader(r io.Reader) (*ChunkReader, error) {
	rd := bufio.NewReader(r)
	v, err := rd.ReadByte()
	if err != nil {
		return nil, err
	}
	if got, want := int(v), 1; got != want {
		return nil, fmt.Errorf("unknown index format %d (need %d)", got, want)
	}
	ts, err := readTimestamp(rd)
	if err != nil {
		return nil, err
	}

	return &ChunkReader{
		rd:        rd,
		Version:   int(v),
		Timestamp: ts,
	}, nil
}

// ChunkReader ...
//
// The iterator methods are all single-use.
type ChunkReader struct {
	// The iterators are all single-use because they all mutate this buffer.
	//
	// To remove this restriction, you'd need to have an [io.ReaderAt], which
	// would make streaming data impossible, and the uncompressed data would
	// need to be buffered. For the initial/full index, this is much too large.
	rd *bufio.Reader

	Version   int
	Timestamp time.Time
}

var skipKeys = map[string]struct{}{
	// Description: don't care
	`d`: {},
	// Jar file contents (optional)
	"classnames": {},
	// Maven Plugin (optional)
	"px": {},
	"gx": {},
	// OSGi (optional)
	"Bundle-SymbolicName":                 {},
	"Bundle-Version":                      {},
	"Export-Package":                      {},
	"Export-Service":                      {},
	"Bundle-Description":                  {},
	"Bundle-Name":                         {},
	"Bundle-License":                      {},
	"Bundle-DocURL":                       {},
	"Import-Package":                      {},
	"Require-Bundle":                      {},
	"Provide-Capability":                  {},
	"Require-Capability":                  {},
	"Fragment-Host":                       {},
	"Bundle-RequiredExecutionEnvironment": {},
}

func (idx *ChunkReader) All() iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		var key, value strings.Builder
		// Over-allocate for these, they're almost certainly too big.
		key.Grow(512)
		value.Grow(512)
		m := make(map[string]string)
		for {
			ct, err := idx.readInt()
			switch {
			case err == nil:
			case errors.Is(err, io.EOF):
				return
			default:
				yield(Record{}, err)
				return
			}
			clear(m)
			for range ct {
				idx.rd.ReadByte() // Flags, ignored.
				if err := idx.readKey(&key); err != nil {
					yield(Record{}, fmt.Errorf("reading key: %w", err))
					return
				}

				if _, skip := skipKeys[key.String()]; skip {
					if err := idx.skipValue(); err != nil {
						yield(Record{}, fmt.Errorf("skipping key: %w", err))
						return
					}
					continue
				}

				if err := idx.readValue(&value); err != nil {
					yield(Record{}, fmt.Errorf("reading value: %w (key: %q)", err, key.String()))
					return
				}

				// I'd like to build the record directly, but we need to pull in
				// all the key-value pairs to see what's in it to determine the
				// type.
				m[key.String()] = value.String()
			}

			r, err := expandRecord(m)
			if !yield(r, err) {
				return
			}

		}
	}
}

// Return an iterator over Records that describe adding or removing the sort of
// archives we care about.
func (idx *ChunkReader) JARs() iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		for r, err := range idx.All() {
			if err != nil {
				yield(r, err)
				return
			}

			switch r.Kind {
			case KindArtifactAdd, KindArtifactRemove:
			default:
				continue
			}

			if r.Classifier != "" {
				continue
			}
			if r.FileExtension == "aar" {
				continue
			}
			if !strings.HasSuffix(r.FileExtension, "ar") {
				continue
			}
			if r.SHA1 == nil && r.SHA256 == nil {
				continue
			}

			if !yield(r, err) {
				return
			}
		}
	}
}

// Read an "int" (a 32-bit integer).
func (idx *ChunkReader) readInt() (int, error) {
	const sz = 4
	b, err := idx.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer idx.rd.Discard(sz)
	return int(be.Uint32(b)), nil
}

// Read a "short" (a 16-bit integer).
func (idx *ChunkReader) readShort() (int, error) {
	const sz = 2
	b, err := idx.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer idx.rd.Discard(sz)
	return int(be.Uint16(b)), nil
}

// This is effectively [java.io.DataInput.readUTF].
//
// [java.io.DataInput.readUTF]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#readUTF--
func (idx *ChunkReader) readKey(buf *strings.Builder) error {
	sz, err := idx.readShort()
	if err != nil {
		return err
	}
	return idx.readString(buf, sz)
}

// This is effectively [java.io.DataInput.readUTF], except that the payload can
// be larger, and so the prefixed length is 32 bits instead of 16.
//
// [java.io.DataInput.readUTF]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#readUTF--
func (idx *ChunkReader) readValue(buf *strings.Builder) error {
	sz, err := idx.readInt()
	if err != nil {
		return err
	}
	return idx.readString(buf, sz)
}

// Like [ChunkReader.readValue], but don't bother reading the string.
func (idx *ChunkReader) skipValue() error {
	sz, err := idx.readInt()
	if err != nil {
		return err
	}
	if _, err := idx.rd.Discard(sz); err != nil {
		return err
	}
	return nil
}

// ReadString builds a string of "sz" bytes in "buf" from the current read
// position and reports any errors.
//
// The encoded strings are actually [modified UTF8], but this currently panics
// if the encoding edge cases are hit.
//
// [modified UTF8]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#modified-utf-8
func (idx *ChunkReader) readString(buf *strings.Builder, sz int) error {
	if sz > idx.rd.Size() {
		slog.Warn("big read!", "size", sz)
	}
	b, err := idx.rd.Peek(sz)
	if err != nil {
		return err
	}
	defer idx.rd.Discard(sz)
	if !utf8.Valid(b) {
		// The non-standard parts are:
		//
		// 	- Allowing NULLs in strings by packing them into a two-byte encoding.
		// 	- Disallowing encodings > 3 bytes
		// 	- Possibly encoding some astral-plane characters not in minimal form.
		panic("TODO: custom utf8 unpacking")
	}
	buf.Reset()
	if _, err := buf.Write(b); err != nil {
		return err
	}
	return nil
}

const (
	fieldSeparator = `|`
	notAvailable   = `NA`

	keyUInfo      = `u`
	keyInfo       = `i`
	keyDescriptor = `DESCRIPTOR`
	keyAllGroups  = `allGroups`
	keyRootGroups = `rootGroups`
	keyDelete     = `del`
)

type RecordKind int

const (
	_ RecordKind = iota
	KindDescriptor
	KindAllGroups
	KindRootGroups
	KindArtifactRemove
	KindArtifactAdd
)

type Record struct {
	Kind RecordKind

	RepositoryID  string
	AllGroups     []string
	RootGroups    []string
	Modified      time.Time
	GroupID       string
	ArtifactID    string
	Version       string
	Classifier    string
	Packaging     string
	FileExtension string
	FileModified  time.Time
	FileSize      int64
	Name          string
	Description   string
	SHA1          []byte
	SHA256        []byte
	HasSources    bool
	HasJavadoc    bool
	HasSignature  bool
}

func (r *Record) GoString() string {
	switch r.Kind {
	case KindDescriptor:
		return fmt.Sprintf(`Record{Descriptor, RepositoryID: %q}`, r.RepositoryID)
	case KindAllGroups:
		var b strings.Builder
		b.WriteString(`Record{AllGroups, [`)
		for i, g := range r.AllGroups {
			if i != 0 {
				b.WriteString(`, `)
			}
			b.WriteString(g)
		}
		b.WriteString(`]}`)
		return b.String()
	case KindRootGroups:
		return `Record{RootGroups}`
	case KindArtifactRemove:
		return `Record{ArtifactRemove}`
	case KindArtifactAdd:
		var b strings.Builder
		b.WriteString(`Record{ArtifactAdd, `)
		b.WriteString(r.FileExtension)
		if r.Classifier != "" {
			b.WriteByte('(')
			b.WriteString(r.Classifier)
			b.WriteByte(')')
		}
		b.WriteString(`, `)
		b.WriteString(r.GroupID)
		b.WriteByte('.')
		b.WriteString(r.ArtifactID)
		b.WriteByte('@')
		b.WriteString(r.Version)
		if r.SHA1 != nil {
			b.WriteString(`, sha1:`)
			b.WriteString(hex.EncodeToString(r.SHA1))
		}
		if r.SHA256 != nil {
			b.WriteString(`, sha256:`)
			b.WriteString(hex.EncodeToString(r.SHA256))
		}
		b.WriteByte('}')
		return b.String()
	default:
		return `Record{INVALID}`
	}
}

func expandRecord(m map[string]string) (Record, error) {
	if _, ok := m[keyDescriptor]; ok {
		return expandRecordDescriptor(m)
	}
	if _, ok := m[keyAllGroups]; ok {
		return expandRecordAllGroups(m)
	}
	if _, ok := m[keyRootGroups]; ok {
		return expandRecordRootGroups(m)
	}
	if _, ok := m[keyDelete]; ok {
		return expandRecordDeleted(m)
	}
	return expandRecordAdded(m)
}

func expandRecordDescriptor(m map[string]string) (Record, error) {
	rs := strings.Split(m[`IDXINFO`], fieldSeparator)
	r := Record{
		Kind:         KindDescriptor,
		RepositoryID: rs[1],
	}
	return r, nil
}

func expandRecordAllGroups(m map[string]string) (Record, error) {
	r := Record{
		Kind:      KindAllGroups,
		AllGroups: strings.Split(m[`allGroupsList`], fieldSeparator),
	}
	return r, nil
}

func expandRecordRootGroups(m map[string]string) (Record, error) {
	r := Record{
		Kind:       KindRootGroups,
		RootGroups: strings.Split(m[`rootGroupsList`], fieldSeparator),
	}
	return r, nil
}

func expandRecordDeleted(m map[string]string) (Record, error) {
	t, err := time.Parse(indexTimeFmt, m[`m`])
	if err != nil {
		return Record{}, err
	}
	r := Record{
		Kind:     KindArtifactRemove,
		Modified: t,
	}
	if err := parseUinfo(&r, m[`del`]); err != nil {
		return Record{}, err
	}
	return r, nil
}

func expandRecordAdded(m map[string]string) (Record, error) {
	r := Record{
		Kind: KindArtifactAdd,
	}
	if err := parseUinfo(&r, m[keyUInfo]); err != nil {
		return Record{}, err
	}
	if err := parseInfo(&r, m[keyInfo]); err != nil {
		return Record{}, err
	}

	var err error
	r.Modified, err = parseTimestamp(m[`m`])
	if err != nil {
		return Record{}, err
	}
	r.Name = m[`n`]
	r.Description = m[`d`]

	key := `1`
	r.SHA1, err = hex.DecodeString(m[key])
	if err != nil {
		slog.Warn("unable to decode hex", "name", m[`n`], "key", key, "value", m[key])
	}
	key = `sha256`
	if s, ok := m[key]; ok {
		r.SHA256, err = hex.DecodeString(s)
		if err != nil {
			slog.Warn("unable to decode hex", "name", m[`n`], "key", key, "value", m[key])
		}
	}

	return r, nil
}

func parseUinfo(r *Record, u string) error {
	if u == "" {
		return nil
	}
	s := strings.Split(u, fieldSeparator)
	r.GroupID = s[0]
	r.ArtifactID = s[1]
	r.Version = s[2]
	switch {
	case s[3] != notAvailable && len(s) > 4:
		r.FileExtension = s[4]
		fallthrough
	case s[3] != notAvailable:
		r.Classifier = s[3]
	case s[3] == notAvailable && len(s) > 4:
		r.Packaging = s[4]
	}
	return nil
}

func parseInfo(r *Record, i string) error {
	if i == "" {
		return nil
	}
	s := strings.Split(i, fieldSeparator)
	if s[0] == notAvailable {
		return nil
	}

	var err error
	r.Packaging = s[0]
	r.FileModified, err = parseTimestamp(s[1])
	if err != nil {
		return err
	}
	r.FileSize, err = strconv.ParseInt(s[2], 10, 64)
	if err != nil {
		return err
	}
	r.HasSources = s[3] == "1"
	r.HasJavadoc = s[4] == "1"
	r.HasSignature = s[5] == "1"
	if len(s) > 6 { // ???
		r.FileExtension = s[6]
	} else {
		ext := "jar" // Guess
		if p := r.Packaging; r.Classifier != "" || p == "pom" || p == "war" || p == "ear" {
			ext = p
		}
		r.FileExtension = ext
	}

	return nil
}
