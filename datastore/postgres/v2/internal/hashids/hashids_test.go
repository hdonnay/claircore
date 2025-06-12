package hashids

import (
	"bufio"
	"iter"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestShuffle(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		Name     string
		In, Want []string
	}{
		{
			Name: "Default",
			In:   []string{`abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789`},
			Want: []string{`fwjBhEY2uczNPDiloxmvISCrytaJO4d71T0W3qnMZbXVHg6eR8sAQ5KkpLUGF9`},
		},
		{
			Name: "Numbers",
			In:   []string{`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`},
			Want: []string{`ec38UaynYXvoxSK7RV9uZ1D2HEPw6isrdzAmBNGT5OCJLk0jlFbtqWQ4hIpMgf`},
		},
		{
			Name: "Cascade",
			In: []string{
				`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`,
				`1023456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`,
			},
			Want: []string{
				`ec38UaynYXvoxSK7RV9uZ1D2HEPw6isrdzAmBNGT5OCJLk0jlFbtqWQ4hIpMgf`,
				`xI3RUayk1MSolQK7e09zYmFpVXPwHiNrdfBJ6ZAT5uCWbntgcDsEqjv4hLG28O`,
			},
		},
		{
			Name: "CascadeRev",
			In: []string{
				`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ`,
				`0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY`,
			},
			Want: []string{
				`ec38UaynYXvoxSK7RV9uZ1D2HEPw6isrdzAmBNGT5OCJLk0jlFbtqWQ4hIpMgf`,
				`x038UaykZMSolIK7RzcbYmFpgXEPHiNr1d2VfGAT5uJWQetjvDswqn94hLC6BO`,
			},
		},
		{
			Name: "Short",
			In:   []string{`0123456789`},
			Want: []string{`4086517392`},
		},
		{
			Name: "Tiny",
			In:   []string{`12345`},
			Want: []string{`24135`},
		},
		{
			Name: "Lower",
			In:   []string{`abcdefghijklmnopqrstuvwxyz`},
			Want: []string{`lbfziqvscptmyxrekguohwjand`},
		},
		{
			Name: "Upper",
			In:   []string{`ABCDEFGHIJKLMNOPQRSTUVWXYZ`},
			Want: []string{`ZXBNSIJQEDMCTKOHVWFYUPLRGA`},
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			for i := range tc.In {
				rs := []rune(tc.In[i])
				shuffle(rs)
				got := string(rs)
				want := tc.Want[i]
				t.Logf("got:  %s", got)
				t.Logf("want: %s", want)
				if got != want {
					t.Fail()
				}
			}
		})
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	ms, err := filepath.Glob("testdata/*.list")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("Encode", func(t *testing.T) {
		t.Parallel()
		for _, m := range ms {
			n := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
			t.Run(n, func(t *testing.T) {
				t.Parallel()
				g, lines := openList(t, m)

				var i int64
				for lineNo, want := range lines {
					ns := []int64{i, i * 1000}
					got, err := Encode(g(), ns...)
					i++
					if err != nil {
						t.Errorf("unable to create ID: %v", err)
						continue
					}
					if got != want {
						t.Errorf("%04d: %v: got: %#q, want: %#q", lineNo, ns, got, want)
					}

					if i%20 == 0 && t.Failed() {
						return
					}
				}
			})
		}
	})

	t.Run("Decode", func(t *testing.T) {
		t.Parallel()
		for _, m := range ms {
			n := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
			t.Run(n, func(t *testing.T) {
				t.Parallel()
				g, lines := openList(t, m)

				var i int64
				for lineNo, in := range lines {
					want := []int64{i, i * 1000}
					got, err := Decode[int64](g(), in)
					i++
					if err != nil {
						t.Errorf("unable to decode ID: %v", err)
						continue
					}

					if !slices.Equal(got, want) {
						t.Errorf("%04d: %v: got: %#v, want: %#v", lineNo, in, got, want)
					}

					if i%20 == 0 && t.Failed() {
						return
					}
				}
			})
		}
	})
}

// OpenList is a helper to load a test fixture of a list of IDs.
func openList(t testing.TB, filename string) (func() *Generator, iter.Seq2[int, string]) {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	s := bufio.NewScanner(f)
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
		if err := s.Err(); err != nil {
			t.Error(err)
		}
	})

	// Use an option slice and OnceValue to defer construction and let the test
	// fixture manipulate the options.
	var opts []Option
	g := sync.OnceValue(func() *Generator {
		g, err := New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		return g
	})

	lineNo := 0
	for s.Scan() {
		lineNo++
		if s.Bytes()[0] != '#' {
			break
		}

		l := strings.TrimSpace(s.Text()[1:])
		directive, arg, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		arg = strings.TrimSpace(arg)
		switch directive {
		case "alphabet":
			if len(arg) == 0 {
				break
			}
			opts = append(opts, WithAlphabet(arg))
			t.Logf("alphabet set: %#q", arg)
		case "min":
			if len(arg) == 0 {
				break
			}
			l, err := strconv.ParseInt(arg, 10, 16)
			if err != nil {
				t.Fatalf("parsing minimum length: %v", err)
			}
			opts = append(opts, WithMinLen(int(l)))
			t.Logf("minimum length set: %d", l)
		case "blocklist":
			if len(arg) == 0 {
				break
			}
			var bl []string
			if arg == "[]" {
				bl = []string{}
			} else {
				bl = strings.Fields(arg)
			}
			opts = append(opts, WithBlocklist(bl))
			t.Logf("blocklist set: %d entries", len(bl))
		default:
			t.Fatalf("unknown directive")
		}
	}

	seq := func(yield func(int, string) bool) {
		if !yield(lineNo, s.Text()) {
			return
		}
		for s.Scan() {
			lineNo++
			if s.Bytes()[0] == '#' {
				continue
			}
			if !yield(lineNo, s.Text()) {
				return
			}
		}
	}

	return g, seq
}
