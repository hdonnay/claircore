package hashids

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestShuffle(t *testing.T) {
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

func TestLists(t *testing.T) {
	ms, err := filepath.Glob("testdata/*.list")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		n := strings.TrimSuffix(filepath.Base(m), filepath.Ext(m))
		t.Run(n, func(t *testing.T) {
			t.Parallel()
			testList(t, m)
		})
	}
}

func testList(t *testing.T, filename string) {
	// t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	}()

	s := bufio.NewScanner(f)
	defer func() {
		if err := s.Err(); err != nil {
			t.Error(err)
		}
	}()

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

	var missCt int
	for i := int64(0); s.Scan() && missCt < 20; {
		if s.Bytes()[0] == '#' {
			l := strings.TrimSpace(s.Text()[1:])
			directive, arg, ok := strings.Cut(l, ":")
			if !ok {
				continue
			}
			arg = strings.TrimSpace(arg)
			switch directive {
			case "alphabet":
				if len(arg) != 0 {
					opts = append(opts, WithAlphabet(arg))
					t.Logf("alphabet set: %#q", arg)
				}
			case "min":
				if len(arg) != 0 {
					l, err := strconv.ParseInt(arg, 10, 16)
					if err != nil {
						t.Fatalf("parsing minimum length: %v", err)
					}
					opts = append(opts, WithMinLen(int(l)))
					t.Logf("minimum length set: %d", l)
				}
			case "blocklist":
				if len(arg) != 0 {
					t.Log("blocklist not implemented")
					t.FailNow()
				}
			default:
				t.Fatalf("unknown directive")
			}
			continue
		}

		ns := []int64{i, i * 1000}
		got, err := g().Encode(ns...)
		i++
		if err != nil {
			t.Errorf("unable to create ID: %v", err)
			continue
		}
		want := s.Text()
		if got != want {
			t.Errorf("%04d: %v: got: %#q, want: %#q", i, ns, got, want)
			missCt++
		}
	}
}
