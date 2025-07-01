package mavenindex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"iter"
	"strings"
	"unicode/utf8"
	"unique"
)

// Lexer is the record lexer.
//
// Unexported methods are helpers for the lexer.
// All methods save [lexer.error] modify the internal Reader state.
type lexer struct {
	rd *bufio.Reader

	step stateFn
	err  error

	cur recordState
}

// NewLexer initializes and returns a lexer.
func newLexer(rd *bufio.Reader) *lexer {
	return &lexer{
		rd:   rd,
		step: readRecord,
		cur: recordState{
			SHA1: make([]byte, 0, 160/8),
		},
	}
}

// All runs the record lexer until EOF or an error is reported.
//
// The iterator is single-use because it mutates this buffer.
//
// To remove this restriction, you'd need to have an [io.ReaderAt], which
// would make streaming data impossible, and the uncompressed data would
// need to be buffered. For the initial/full index, this is much too large.
func (l *lexer) All(ctx context.Context) iter.Seq2[Record, error] {
	return func(yield func(Record, error) bool) {
		for {
			for l.step != nil {
				l.step = l.step(ctx, l)
			}
			switch {
			case l.err == nil:
				out := Record{
					Artifact: unique.Make(Artifact{
						GroupID:    l.cur.GroupID,
						ArtifactID: l.cur.ArtifactID,
					}).Value(),
					Version: l.cur.Version,
				}
				if len(l.cur.SHA1) != 0 {
					out.SHA1 = make([]byte, 160/8)
					copy(out.SHA1, l.cur.SHA1)
				}
				if !yield(out, nil) {
					return
				}
				fallthrough
			case errors.Is(l.err, errSkipRecord):
				l.err = nil
				l.step = readRecord
			case errors.Is(l.err, io.EOF):
				return
			default:
				yield(Record{}, l.err)
				return
			}
		}
	}
}

// ErrSkipRecord is reported when the processed record should not be emitted.
var errSkipRecord = errors.New("skip this record")

// All numbers in the index format are big-endian.
var be = binary.BigEndian

// Read an "int" (a 32-bit integer).
func (l *lexer) readInt() (int, error) {
	const sz = 4
	b, err := l.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer l.rd.Discard(sz)
	return int(be.Uint32(b)), nil
}

// Read a "short" (a 16-bit integer).
func (l *lexer) readShort() (int, error) {
	const sz = 2
	b, err := l.rd.Peek(sz)
	if err != nil {
		return 0, err
	}
	defer l.rd.Discard(sz)
	return int(be.Uint16(b)), nil
}

// ReadString builds a string of "sz" bytes in "buf" from the current read
// position and reports any errors.
//
// The encoded strings are actually [modified UTF8], but this currently panics
// if the encoding edge cases are hit.
//
// [modified UTF8]: https://docs.oracle.com/javase/8/docs/api/java/io/DataInput.html#modified-utf-8
func (l *lexer) readString(buf *bytes.Buffer, sz int) error {
	buf.Reset()
	if _, err := io.CopyN(buf, l.rd, int64(sz)); err != nil {
		return err
	}
	if !utf8.Valid(buf.Bytes()) {
		// The non-standard parts are:
		//
		// 	- Allowing NULLs in strings by packing them into a two-byte encoding.
		// 	- Disallowing encodings > 3 bytes
		// 	- Possibly encoding some astral-plane characters not in minimal form.
		panic("TODO: custom utf8 unpacking")
	}
	return nil
}

// Error records the provided error, turning [io.EOF] into
// [io.ErrUnexpectedEOF].
func (l *lexer) error(err error) stateFn {
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	l.err = err
	return nil
}

// StateFn is a lexer state.
//
// The [context.Context] is threaded through but largely unused. Having it here
// from the jump makes it easier to add log messages in the future.
//
// Nil is used to denote the terminal state.
type stateFn func(context.Context, *lexer) stateFn

// The following free functions are the lexer states. The documentation comments
// should note the exit transitions.

// ReadRecord is the start for building a new Record.
//
// Transitions to:
//   - nil
//   - [readField]
func readRecord(_ context.Context, l *lexer) stateFn {
	l.cur.Reset()
	l.cur.fields, l.err = l.readInt()
	if l.err != nil {
		return nil
	}
	return readField
}

// ReadField decides whether this field should be read or skipped.
//
// Transitions to:
//   - [skipKey]
//   - [readKey]
func readField(_ context.Context, l *lexer) stateFn {
	switch {
	case l.cur.fields < 0:
		return skipKey
	case l.cur.fields > 0:
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
func readKey(_ context.Context, l *lexer) stateFn {
	l.rd.Discard(1) // Flags, ignored.
	sz, err := l.readShort()
	if err != nil {
		return l.error(err)
	}
	buf := &l.cur.key

	buf.Reset()
	if err := l.readString(buf, sz); err != nil {
		return l.error(err)
	}

	key := buf.String()
	if _, skip := skipRecordKeys[key]; skip {
		l.cur.fields *= -1
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
func skipKey(_ context.Context, l *lexer) stateFn {
	l.rd.Discard(1) // Flags, ignored.
	sz, err := l.readShort()
	if err != nil {
		return l.error(err)
	}
	l.rd.Discard(sz)
	return skipValue
}

// ReadValue reads in this field's value.
//
// Transitions to:
//   - nil
//   - [fieldDone]
func readValue(_ context.Context, l *lexer) stateFn {
	sz, err := l.readInt()
	if err != nil {
		return l.error(err)
	}
	buf := &l.cur.val

	buf.Reset()
	switch err := l.readString(buf, sz); {
	case err == nil:
	case errors.Is(err, io.EOF):
	default:
		return l.error(err)
	}

	return fieldDone
}

// SkipValue advances the read stream over the value.
//
// Transitions to:
//   - nil
//   - [fieldDone]
func skipValue(_ context.Context, l *lexer) stateFn {
	sz, err := l.readInt()
	if err != nil {
		return l.error(err)
	}
	l.rd.Discard(sz)
	return fieldDone
}

// FieldDone marks the field as done and determines if the remaining fields need
// to be read and if the record is complete.
//
// Transitions to:
//   - nil
//   - [readField]
func fieldDone(_ context.Context, l *lexer) stateFn {
	cur := &l.cur
	var err error

	switch {
	case cur.fields == 0:
		panic("unreachable")
	case cur.fields > 0:
		cur.fields--
	case cur.fields < 0:
		cur.fields++
		goto Done
	}

	switch cur.key.String() {
	case `del`:
		cur.kind = kindRemove
		err = cur.parseUinfo(cur.val.String())
		// We now have all the needed information.
		cur.fields *= -1
	case `i`:
		err = cur.parseInfo(cur.val.String())
	case `u`:
		cur.kind = kindAdd
		err = cur.parseUinfo(cur.val.String())
	case `1`:
		// A lot of early entries are malformed (they seem to be the wrong part
		// of `sha1sum` output), so just ignore an artifact that doesn't parse.

		// This slice will always have enough capacity, so just reslice it.
		cur.SHA1 = cur.SHA1[:160/8]
		if _, err := hex.Decode(cur.SHA1, cur.val.Bytes()); err != nil {
			// Remember to reset the length on failure.
			cur.SHA1 = cur.SHA1[:0]
			cur.fields *= -1
		}
	default:
		// Skip
	}
	if err != nil {
		return l.error(err)
	}

	// Short circuits:
	switch {
	// If "Classifier" is set, this is not an executable jar.
	case cur.Classifier != "":
		cur.fields *= -1
	// If an Android archive, skip.
	case cur.FileExtension == "aar":
		cur.fields *= -1
	// If some other artifact, skip.
	case cur.FileExtension != "" && !strings.HasSuffix(cur.FileExtension, "ar"):
		cur.fields *= -1
	}

Done:
	if cur.fields == 0 { // If done with the record:
		switch {
		case cur.kind == kindAdd && len(cur.SHA1) == 0: // WTF?
			fallthrough
		case cur.kind == kindInvalid:
			l.err = errSkipRecord
		default: // Just return the current record.
		}
		return nil
	}
	// Otherwise, continue reading fields.
	return readField
}

// List of keys that don't mean the record should be skipped, but don't need to
// be processed.
var skipKeys = map[string]struct{}{
	// Name
	`n`: {},
	// Modified timestamp
	`m`: {},
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

// RecordState is the bag of lexer state that's reset between records.
type recordState struct {
	// abs(fields) is the number of fields in the current record. If negative,
	// the fields should be skipped instead of read and processed.
	fields int
	key    bytes.Buffer
	val    bytes.Buffer
	kind   recordKind

	GroupID       string
	ArtifactID    string
	Version       string
	Classifier    string
	Packaging     string
	FileExtension string
	SHA1          []byte
}

// Reset resets the receiver.
func (s *recordState) Reset() {
	s.fields = 0
	s.key.Reset()
	s.val.Reset()
	s.kind = kindInvalid

	s.GroupID = ""
	s.ArtifactID = ""
	s.Version = ""
	s.Classifier = ""
	s.Packaging = ""
	s.FileExtension = ""
	s.SHA1 = s.SHA1[:0]
}

// RecordKind tracks the kind of record that will ultimately be emitted.
type recordKind int

const (
	kindInvalid recordKind = iota
	kindAdd
	kindRemove
)

const (
	fieldSeparator = `|`
	notAvailable   = `NA`
)

// ParseUinfo parses a "uinfo" string and stores the relevant values in the
// receiver.
func (s *recordState) parseUinfo(u string) error {
	if u == "" {
		return nil
	}
	fs := strings.Split(u, fieldSeparator)
	s.GroupID = fs[0]
	s.ArtifactID = fs[1]
	s.Version = fs[2]
	switch {
	case fs[3] != notAvailable && len(fs) > 4:
		s.FileExtension = fs[4]
		fallthrough
	case fs[3] != notAvailable:
		s.Classifier = fs[3]
	case fs[3] == notAvailable && len(fs) > 4:
		s.Packaging = fs[4]
	}
	return nil
}

// ParseInfo parses an "info" string and stores the relevant values in the
// receiver.
func (s *recordState) parseInfo(i string) error {
	if i == "" {
		return nil
	}
	fs := strings.Split(i, fieldSeparator)
	if fs[0] == notAvailable {
		return nil
	}

	s.Packaging = fs[0]
	if len(fs) > 6 { // ???
		s.FileExtension = fs[6]
	} else {
		ext := "jar" // Guess
		if p := s.Packaging; s.Classifier != "" || p == "pom" || p == "war" || p == "ear" {
			ext = p
		}
		s.FileExtension = ext
	}

	return nil
}
