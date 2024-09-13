// Package hashids implements hashids/sqids -like ID obfuscation.
//
// A reimplementation is done for a few reasons:
//
// - Fewer allocations
// - More ergonomic API
// - Multibyte alphabet support
package hashids

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
)

type Generator struct {
	blocklist   map[string]struct{}
	encAlphabet []rune
	minLen      int
	mask        uint64
}

type Option func(*Generator) error

const defaultAlphabet = `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`

func WithAlphabet(s string) Option {
	return func(g *Generator) error {
		if len(s) == 0 {
			return errors.New("hashids: invalid alphabet")
		}
		g.encAlphabet = []rune(s)
		return nil
	}
}

func WithBlocklist(b iter.Seq[string]) Option {
	return func(g *Generator) error {
		g.blocklist = make(map[string]struct{})
		for s := range b {
			g.blocklist[s] = struct{}{}
		}
		return nil
	}
}

func WithMinLen(l int) Option {
	return func(g *Generator) error {
		g.minLen = l
		return nil
	}
}

func New(opts ...Option) (*Generator, error) {
	var g Generator
	g.mask = ^uint64(0)

	for _, opt := range opts {
		if err := opt(&g); err != nil {
			return nil, err
		}
	}

	if g.encAlphabet == nil {
		g.encAlphabet = []rune(defaultAlphabet)
	}
	if g.blocklist == nil {
		g.blocklist = defaultBlocklist
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

func (g *Generator) Encode(numbers ...int64) (string, error) {
	if len(numbers) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.Grow(g.minLen)

	for i := 0; ; i++ {
		if i > len(g.encAlphabet) {
			return "", errors.New("hashids: reached max attempts to regenerate ID")
		}
		b.Reset()
		off := g.offset(numbers, i)

		a := append(g.encAlphabet[off:], g.encAlphabet[:off]...)
		b.WriteRune(a[0]) // prefix
		slices.Reverse(a)

		for i, n := range numbers {
			// work set
			w := a[1:]
			m := int64(len(w))
			r := make([]rune, 0, int(n)/len(w))

			for n := n; ; {
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
			println(fmt.Sprintf("n: %d: min: %d, len: %d", numbers[0], g.minLen, b.Len()))
			b.WriteRune(a[0]) // separator
			for g.minLen-b.Len() > 0 {
				shuffle(a)
				l := min(g.minLen-b.Len(), len(a))
				println(fmt.Sprintf("n: %d: a[:%d]", numbers[0], l))
				s := string(a[:l])
				b.WriteString(s)
			}
		}
		if _, bad := g.blocklist[b.String()]; !bad {
			break
		}
	}

	return b.String(), nil
}

func (g *Generator) offset(ns []int64, inc int) int {
	sz := int64(len(g.encAlphabet))

	offset := int64(len(ns))
	for i, v := range ns {
		offset += int64(g.encAlphabet[v%sz]) + int64(i)
	}
	offset %= sz

	return int((offset + int64(inc)) % sz)
}

func (g *Generator) hashi(key uint64) uint64 {
	var tmp uint64

	// Invert key = key + (key << 31)
	tmp = (key - (key << 31))
	key = (key - (tmp << 31)) & g.mask

	// Invert key = key ^ (key >> 28)
	tmp = key ^ key>>28
	key = key ^ tmp>>28

	// Invert key *= 21
	key = (key * 14933078535860113213) & g.mask

	// Invert key = key ^ (key >> 14)
	tmp = key ^ key>>14
	tmp = key ^ tmp>>14
	tmp = key ^ tmp>>14
	key = key ^ tmp>>14

	// Invert key *= 265
	key = (key * 15244667743933553977) & g.mask

	// Invert key = key ^ (key >> 24)
	tmp = key ^ key>>24
	key = key ^ tmp>>24

	// Invert key = (~key) + (key << 21)
	tmp = ^key
	tmp = ^(key - (tmp << 21))
	tmp = ^(key - (tmp << 21))
	key = ^(key - (tmp << 21)) & g.mask

	return key
}

func (g *Generator) hash(key uint64) uint64 {
	key = (^key + (key << 21)) & g.mask // key = (key << 21) - key - 1;
	key = key ^ key>>24
	key = ((key + (key << 3)) + (key << 8)) & g.mask // key * 265
	key = key ^ key>>14
	key = ((key + (key << 2)) + (key << 4)) & g.mask // key * 21
	key = key ^ key>>28
	key = (key + (key << 31)) & g.mask
	return key
}

func (g *Generator) EncodeID(id int64) string {
	b := binary.LittleEndian.AppendUint64(nil, g.hash(uint64(id)))
	return base64.StdEncoding.EncodeToString(b)
}

func (g *Generator) DecodeID(enc string) (int64, error) {
	h, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return -1, err
	}
	id := g.hashi(binary.LittleEndian.Uint64(h))
	return int64(id), nil
}
