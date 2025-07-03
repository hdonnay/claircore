//go:build ignore

package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"expvar"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type Artifact struct {
	GroupID    string
	ArtifactID string
}

type ExportRecord struct {
	Artifact
	Version string
	SHA1    []byte
}

const (
	fieldSeparator = `|`
	notAvailable   = `NA`
)

type RecordKind int

const (
	KindInvalid RecordKind = iota
	KindArtifactRemove
	KindArtifactAdd
)

type ImportRecord struct {
	Kind RecordKind

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
	SHA1          []byte
	HasSources    bool
	HasJavadoc    bool
	HasSignature  bool
}

func (r *ImportRecord) export() ExportRecord {
	return ExportRecord{
		Kind: r.Kind,
		Artifact: Artifact{
			GroupID:    r.GroupID,
			ArtifactID: r.ArtifactID,
		},
		Version: r.Version,
		SHA1:    slices.Clone(r.SHA1),
	}
}

func (r *ImportRecord) GoString() string {
	if r.Kind == KindInvalid {
		return `Record{INVALID}`
	}
	var b strings.Builder
	b.WriteString(`Record{`)
	switch r.Kind {
	case KindArtifactRemove:
		b.WriteString(`ArtifactRemove, `)
		b.WriteString(r.GroupID)
		b.WriteByte('.')
		b.WriteString(r.ArtifactID)
		b.WriteByte('@')
		b.WriteString(r.Version)
	case KindArtifactAdd:
		b.WriteString(`ArtifactAdd, `)
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
	default:
		panic("unreachable")
	}
	b.WriteByte('}')

	return b.String()
}

func (r *ImportRecord) parseUinfo(u string) error {
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

func (r *ImportRecord) parseInfo(i string) error {
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

func (r *ImportRecord) hasChecksum() bool { return len(r.SHA1) == (160 / 8) }

// All numbers in the index format are big endian.
var be = binary.BigEndian

// All timestamps are milliseconds.

// ReadTimestamp reads a timestamp directly from the bitstream.
func readTimestamp(rd *bufio.Reader) (time.Time, error) {
	b, err := rd.Peek(8)
	if err != nil {
		return time.Time{}, err
	}
	defer rd.Discard(8)
	ts := int64(be.Uint64(b))
	return time.UnixMilli(ts), nil
}

// ParseTimestamp reads a timestamp from an integer formatted into a string.
func parseTimestamp(s string) (time.Time, error) {
	ts, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(ts), nil
}

// NewChunkReader sets up a [ImportRecord] reader over the contents of "r", which is
// assumed to be compressed.
//
// "Num" is used for reporting and does not affect processing
func NewChunkReader(num int, rc io.ReadCloser) (*ChunkReader, error) {
	const bufSz = 1 << 20
	z, err := gzip.NewReader(bufio.NewReaderSize(rc, bufSz))
	if err != nil {
		return nil, err
	}
	rd := bufio.NewReaderSize(z, bufSz)

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

	cr := ChunkReader{
		rc:        rc,
		z:         z,
		rd:        rd,
		Version:   int(v),
		Timestamp: ts,
		Number:    num,
		step:      readRecord,
	}
	cr.registerMetrics(num)

	return &cr, nil
}

// ChunkReader ...
type ChunkReader struct {
	chunkMetrics

	Version   int
	Timestamp time.Time
	Number    int

	rc io.ReadCloser
	z  *gzip.Reader
	// The iterator is single-use because they it mutates this buffer.
	//
	// To remove this restriction, you'd need to have an [io.ReaderAt], which
	// would make streaming data impossible, and the uncompressed data would
	// need to be buffered. For the initial/full index, this is much too large.
	rd *bufio.Reader

	// Records are read out via a little lexer state machine.
	//
	// Everything below this is the state for that:
	step     stateFn
	key, val strings.Builder
	err      error
	// abs(fields) is the number of fields in the current record. If negative,
	// the fields should be skipped instead of read and processed.
	fields int
	// Out is the current record.
	out ImportRecord
}

type chunkMetrics struct {
	recordsTotal      expvar.Int
	recordsDiscarded  expvar.Int
	recordsAdd        expvar.Int
	recordsRemove     expvar.Int
	recordsDescriptor expvar.Int
	recordsAllGroups  expvar.Int
	recordsRootGroups expvar.Int
	invalidSHA1       expvar.Int
	notJar            expvar.Int
	android           expvar.Int
	missingChecksums  expvar.Int
	bytesSkipped      expvar.Int
}

func (cm *chunkMetrics) registerMetrics(n int) {
	name := fmt.Sprintf("chunk#%02d", n)
	m := expvar.NewMap(name)
	m.Set("bytes_skipped", &cm.bytesSkipped)

	recordStats := new(expvar.Map)
	recordStats.Set("total", &cm.recordsTotal)
	recordStats.Set("discarded", &cm.recordsDiscarded)
	recordStats.Set("type:add", &cm.recordsAdd)
	recordStats.Set("type:remove", &cm.recordsRemove)
	recordStats.Set("type:descriptor", &cm.recordsDescriptor)
	recordStats.Set("type:all_groups", &cm.recordsAllGroups)
	recordStats.Set("type:root_groups", &cm.recordsRootGroups)
	m.Set("records", recordStats)

	reason := new(expvar.Map)
	reason.Set("invalid_sha1", &cm.invalidSHA1)
	reason.Set("not_jar", &cm.notJar)
	reason.Set("android", &cm.android)
	reason.Set("missing_checksums", &cm.missingChecksums)
	m.Set("skip_reason", reason)
}

// All returns an iterator of Add/Remove records contained in this index chunk.
func (cr *ChunkReader) All(ctx context.Context) iter.Seq2[ExportRecord, error] {
	return func(yield func(ExportRecord, error) bool) {
		defer func() {
			cr.z.Close()
			cr.rc.Close()
		}()
		for cr.step != nil {
			cr.step = cr.step(ctx, cr, yield)
		}
		if cr.err != nil {
			yield(ExportRecord{}, cr.err)
		}
	}
}

// Read an "int" (a 32-bit integer).
func (cr *ChunkReader) readInt() (int, error) {
	const sz = 4
	b, err := cr.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer cr.rd.Discard(sz)
	return int(be.Uint32(b)), nil
}

// Read a "short" (a 16-bit integer).
func (cr *ChunkReader) readShort() (int, error) {
	const sz = 2
	b, err := cr.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer cr.rd.Discard(sz)
	return int(be.Uint16(b)), nil
}

// ReadString builds a string of "sz" bytes in "buf" from the current read
// position and reports any errors.
//
// The encoded strings are actually [modified UTF8], but this currently panics
// if the encoding edge cases are hit.
//
// [modified UTF8]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#modified-utf-8
func (cr *ChunkReader) readString(buf *strings.Builder, sz int) error {
	if sz > cr.rd.Size() {
		slog.Warn("big read!", "size", sz)
	}
	b, err := cr.rd.Peek(sz)
	if err != nil {
		return err
	}
	defer cr.rd.Discard(sz)
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

// YieldRecord is the type used in the [ChunkReader.All] iterator.
type yieldRecord func(ExportRecord, error) bool

// StateFn is a lexer state.
type stateFn func(context.Context, *ChunkReader, yieldRecord) stateFn

// ReadRecord is the start for building a new Record.
//
// Transitions to:
//   - nil
//   - [readField]
func readRecord(_ context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	cr.fields, cr.err = cr.readInt()
	switch {
	case cr.err == nil:
	case errors.Is(cr.err, io.EOF):
		cr.err = nil
		fallthrough
	default:
		return nil
	}
	cr.recordsTotal.Add(1)
	return readField
}

// ReadField decides whether this field should be read or skipped.
//
// Transitions to:
//   - [skipKey]
//   - [readKey]
func readField(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	switch {
	case cr.fields < 0:
		return skipKey
	case cr.fields > 0:
		return readKey
	default:
		panic("unreachable")
	}
}

// `ReadKey`/`readValue` are effectively [java.io.DataInput.readUTF].
//
// [java.io.DataInput.readUTF]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#readUTF--

// ReadKey reads in this field's key, then determines if this field should be
// skipped, this record should be skipped, or the field should be completed.
//
// Transitions to:
//   - nil
//   - [skipValue]
//   - [readValue]
func readKey(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	cr.rd.Discard(1) // Flags, ignored.
	var sz int
	sz, cr.err = cr.readShort()
	if cr.err != nil {
		return nil
	}

	cr.key.Reset()
	cr.err = cr.readString(&cr.key, sz)
	if cr.err != nil {
		return nil
	}

	key := cr.key.String()
	if _, skip := skipRecordKeys[key]; skip {
		cr.fields *= -1
		return skipValue
	}
	if _, skip := skipKeys[key]; skip {
		return skipValue
	}

	return readValue
}

// SkipKey advances the read stream over the key.
//
// Transitions to:
//   - nil
//   - [skipValue]
func skipKey(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	cr.rd.Discard(1) // Flags, ignored.
	var sz int
	sz, cr.err = cr.readShort()
	if cr.err != nil {
		return nil
	}
	cr.rd.Discard(sz)
	cr.bytesSkipped.Add(int64(sz))
	return skipValue
}

// ReadValue reads in this field's value.
//
// Transitions to:
//   - nil
//   - [fieldDone]
func readValue(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	var sz int
	sz, cr.err = cr.readInt()
	if cr.err != nil {
		return nil
	}

	cr.val.Reset()
	cr.err = cr.readString(&cr.val, sz)
	if cr.err != nil {
		return nil
	}

	return fieldDone
}

// SkipValue advances the read stream over the value.
//
// Transitions to:
//   - nil
//   - [fieldDone]
func skipValue(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	var sz int
	sz, cr.err = cr.readInt()
	if cr.err != nil {
		return nil
	}
	cr.rd.Discard(sz)
	cr.bytesSkipped.Add(int64(sz))
	return fieldDone
}

// FieldDone marks the field as done and determines if the remaining fields need
// to be read and if the record is complete.
//
// Transitions to:
//   - nil
//   - [emitRecord]
//   - [discardRecord]
//   - [readField]
func fieldDone(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	markDiscard := func(why *expvar.Int) {
		cr.out.Kind = KindInvalid
		cr.fields *= -1
		why.Add(1)
	}
	switch {
	case cr.fields == 0:
		panic("unreachable")
	case cr.fields > 0:
		cr.fields--
	case cr.fields < 0:
		cr.fields++
		goto Done
	}

	switch cr.key.String() {
	case `m`:
		cr.out.Modified, cr.err = parseTimestamp(cr.val.String())
	case `del`:
		cr.out.Kind = KindArtifactRemove
		cr.recordsRemove.Add(1)
		cr.err = cr.out.parseUinfo(cr.val.String())
	case `n`:
		cr.out.Name = cr.val.String()
		if cr.out.Kind == KindInvalid {
			cr.out.Kind = KindArtifactAdd
			cr.recordsAdd.Add(1)
		}
	case `i`:
		cr.err = cr.out.parseInfo(cr.val.String())
	case `u`:
		cr.err = cr.out.parseUinfo(cr.val.String())
	case `1`:
		// A lot of early entries are malformed (they seem to be the wrong part
		// of `sha1sum` output), so just ignore an artifact that doesn't parse.
		var err error
		cr.out.SHA1, err = hex.DecodeString(cr.val.String())
		if err != nil {
			slog.Log(ctx, Trace, "unable to decode hex", "name", cr.out.Name, "key", `1`, "value", &cr.val)
			markDiscard(&cr.invalidSHA1)
		}
	case `DESCRIPTOR`:
		markDiscard(&cr.recordsDescriptor)
	case `allGroups`:
		markDiscard(&cr.recordsAllGroups)
	case `rootGroups`:
		markDiscard(&cr.recordsRootGroups)
	default:
		// Skip
	}
	if cr.err != nil {
		return nil
	}

	// Short circuits:

	// If "Classifier" is set, this is not an executable jar.
	if cr.out.Classifier != "" {
		markDiscard(&cr.notJar)
	}
	// If an Android archive, skip.
	if cr.out.FileExtension == "aar" {
		markDiscard(&cr.android)
	}
	// If some other artifact, skip.
	if cr.out.FileExtension != "" && !strings.HasSuffix(cr.out.FileExtension, "ar") {
		markDiscard(&cr.notJar)
	}

Done:
	// What's happening with this record?
	switch {
	case cr.fields == 0 && cr.out.Kind == KindArtifactAdd && cr.out.hasChecksum():
		fallthrough
	case cr.fields == 0 && cr.out.Kind == KindArtifactRemove:
		return emitRecord
	case cr.fields == 0 && cr.out.Kind == KindArtifactAdd && !cr.out.hasChecksum():
		cr.missingChecksums.Add(1)
		fallthrough
	case cr.fields == 0 && cr.out.Kind == KindInvalid:
		return discardRecord
	default:
		// Continue processing it.
	}
	// Next field
	return readField
}

// EmitRecord calls "yield". Forwards to [resetState].
//
// Transitions to:
//   - nil
//   - [readRecord]
func emitRecord(ctx context.Context, cr *ChunkReader, yield yieldRecord) stateFn {
	if !yield(cr.out.export(), nil) {
		return nil
	}
	return resetState(ctx, cr, nil)
}

// DiscardRecord discards the current record. Forwards to [resetState].
//
// Transitions to:
//   - nil
//   - [readRecord]
func discardRecord(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	cr.recordsDiscarded.Add(1)
	return resetState
}

// Not a real state. Used for common logic at the end of record processing.
func resetState(ctx context.Context, cr *ChunkReader, _ yieldRecord) stateFn {
	cr.out = ImportRecord{}
	cr.err = ctx.Err()
	if cr.err != nil {
		return nil
	}
	return readRecord
}

// List of keys that don't mean the record should be skipped, but don't need to
// be processed.
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
	"sha256":                              {}, // Never populated on maven central for some reason.
}

// List of keys that mean the record should be skipped.
var skipRecordKeys = map[string]struct{}{
	"DESCRIPTOR": {},
	"allGroups":  {},
	"rootGroups": {},
}
