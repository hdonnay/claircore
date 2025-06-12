// Package hashids implements hashids/[sqid]s -like ID obfuscation.
//
// A re-implementation is done for a few reasons:
//
//   - Fewer allocations
//   - More ergonomic API
//
// This will probably not work with a multibyte alphabet.
//
// [sqid]: https://sqids.org/
package hashids

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

// DefaultAlphabet is the default sqid alphabet.
const defaultAlphabet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

// EmptyRegexp is used as a sentinel to signal the blocklist was explicitly
// configured to be empty.
//
// This regexp will actually match any (non-empty?) string, and so can't be used
// directly.
var emptyRegexp = regexp.MustCompile(``)

// Generator is the configuration for handling IDs via [Encode] and [Decode].
type Generator struct {
	disallowed  *regexp.Regexp // the blocklist is compiled to this regexp
	encAlphabet []rune
	minLen      int
}

// Option is an option to configure a [Generator].
type Option func(*Generator) error

// WithAlphabet sets the alphabet a generator will use.
//
// If not provided to [New], [defaultAlphabet] will be used.
func WithAlphabet(s string) Option {
	return func(g *Generator) error {
		if len(s) == 0 {
			return errors.New("hashids: invalid alphabet")
		}
		g.encAlphabet = []rune(s)
		return nil
	}
}

// WithBlocklist sets the list of strings disallowed to appear in IDs.
//
// If not provided to [New], a default blocklist will be used. To disable the
// blocklist, pass a 0-length slice. The returned [Option] makes a copy of the
// slice during the [New] function.
func WithBlocklist(b []string) Option {
	return func(g *Generator) error {
		return g.setBlocklist(b)
	}
}

// WithMinLen sets the minimum length of IDs from a generator.
//
// If not provided to [New], there is no minimum length.
func WithMinLen(l int) Option {
	return func(g *Generator) error {
		g.minLen = l
		return nil
	}
}

// New creates a [Generator], using the provided [Option]s. If none are
// provided, suitable defaults will be used.
func New(opts ...Option) (*Generator, error) {
	var g Generator

	for _, opt := range opts {
		if err := opt(&g); err != nil {
			return nil, err
		}
	}

	if g.encAlphabet == nil {
		g.encAlphabet = []rune(defaultAlphabet)
	}
	if g.disallowed == nil {
		if err := g.setBlocklist(defaultBlocklist()); err != nil {
			return nil, err
		}
	}

	// Shuffle the input alphabet once.
	shuffle(g.encAlphabet)
	return &g, nil
}

// Shuffle is the specified sqids alphabet shuffle algorithm.
func shuffle(rs []rune) {
	var p int
	for i, j := 0, len(rs)-1; j > 0; i, j = i+1, j-1 {
		p = (i*j + int(rs[i]) + int(rs[j])) % len(rs)
		rs[i], rs[p] = rs[p], rs[i]
	}
}

// DisallowedID is used to reject disallowed IDs.
//
// Empty IDs and IDs on the configured blocklist report "true".
func (g *Generator) disallowedID(id string) bool {
	return len(id) == 0 || (g.disallowed != emptyRegexp && g.disallowed.MatchString(id))
}

// SetBlocklist takes the list and compiles it to a regexp to be used by the
// [Generator].
func (g *Generator) setBlocklist(l []string) error {
	// Clean the blocklist:
	re, err := regexp.Compile(`[^` + regexp.QuoteMeta(string(g.encAlphabet)) + `]`)
	if err != nil {
		return err
	}
	// Turn the list into a regexp:
	var b strings.Builder
	for _, s := range l {
		if len(s) < 3 || re.MatchString(s) {
			continue
		}
		if b.Len() != 0 {
			b.WriteByte('|')
		}
		b.WriteString(regexp.QuoteMeta(s))
	}
	if b.Len() != 0 {
		g.disallowed, err = regexp.Compile(b.String())
		if err != nil {
			return err
		}
	} else {
		g.disallowed = emptyRegexp
	}
	return nil
}

// Int is a type parameter describing the numbers accepted by [Encode] and
// [Decode].
type Int interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

// Offset calculates the initial alphabet offset.
func offset[N Int](g *Generator, ns []N, inc int) int {
	sz := int64(len(g.encAlphabet))

	offset := int64(len(ns))
	for i, v := range ns {
		offset += int64(g.encAlphabet[int64(v)%sz]) + int64(i)
	}
	offset %= sz

	return int((offset + int64(inc)) % sz)
}

// Encode takes the numbers and produces an ID using the configuration in
// [Generator].
func Encode[N Int](g *Generator, numbers ...N) (string, error) {
	if len(numbers) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.Grow(g.minLen)

	// "A" is the alphabet for an iteration.
	a := make([]rune, len(g.encAlphabet))
	for i := 0; g.disallowedID(b.String()); i++ {
		if i > len(g.encAlphabet) {
			return "", errors.New("hashids: reached max attempts to regenerate ID")
		}
		b.Reset()
		off := offset(g, numbers, i)

		// Copy the rotated encoding alphabet.
		copy(a[copy(a, g.encAlphabet[off:]):], g.encAlphabet[:off])
		b.WriteRune(a[0]) // prefix
		slices.Reverse(a)

		for i, n := range numbers {
			// work set
			w := a[1:]
			m := int64(len(w))
			r := make([]rune, 0, int(n)/len(w))

			for n := int64(n); ; {
				r = append(r, w[(n%m)])
				n = n / m
				if n <= 0 {
					break
				}
			}
			// reverse the order they were collected in:
			for i := len(r) - 1; i >= 0; i-- {
				b.WriteRune(r[i])
			}
			if i+1 != len(numbers) {
				b.WriteRune(a[0]) // separator
				shuffle(a)
			}
		}

		// Two separators indicates the rest encodes nothing
		if g.minLen > b.Len() {
			b.WriteRune(a[0]) // separator
			for rem := g.minLen - b.Len(); rem > 0; rem = g.minLen - b.Len() {
				shuffle(a)
				l := min(rem, len(a))
				s := string(a[:l])
				b.WriteString(s)
			}
		}
	}

	return b.String(), nil
}

// Decode takes an ID generated by a similarly configured [Generator] and
// returns the numbers.
//
// If the type parameter is smaller than the type used to encode the numbers,
// the results will be incorrect.
func Decode[N Int](g *Generator, id string) ([]N, error) {
	var ret []N
	// If the ID is an empty string or the id contains a character is not in the
	// alphabet, return an empty slice.
	if id == "" || strings.Trim(id, string(g.encAlphabet)) != "" {
		return ret, nil
	}
	// Work alphabet
	a := make([]rune, len(g.encAlphabet))
	// Take the prefix rune and work out the alphabet offset:
	prefix := []rune(id)[0]
	off := slices.Index(g.encAlphabet, prefix)
	// Populate the alphabet
	copy(a[copy(a, g.encAlphabet[off:]):], g.encAlphabet[:off])
	slices.Reverse(a)
	// Discard the prefix.
	id = id[1:]

	var c string
	var ok bool
	for id != "" {
		sep, dec := string(a[0]), a[1:]
		c, id, ok = strings.Cut(id, sep)
		if ok && c == "" {
			break
		}
		var n uint64
		for _, v := range c {
			n = n*uint64(len(dec)) + uint64(slices.Index(dec, v))
		}
		ret = append(ret, N(n))
		if ok { // Only shuffle if another round will be needed.
			shuffle(a)
		}
	}
	return ret, nil
}
