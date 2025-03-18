package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"net/http"
	"path"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

const scraperoot = `https://repo.maven.apache.org/maven2/ant/`

type IndexScraper struct {
	c *http.Client
}

type TODO any

func (s *IndexScraper) Run(ctx context.Context) (TODO, error) {
	return nil, nil
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

func main() {
	ctx := context.Background()
	flag.Parse()

	// TODO(hank) Rework this to do a depth-first walk.
	var c http.Client
	eg, ctx := errgroup.WithContext(ctx)
	lim := rate.NewLimiter(4, 4)

	var chase func(string) func() error
	var leaf func(string, []string) func() error

	chase = func(p string) func() error {
		return func() error {
			if err := lim.Wait(ctx); err != nil {
				return err
			}

			u := scraperoot + p
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				return err
			}
			fmt.Printf("request: %q\n", u)
			res, err := c.Do(req)
			if err != nil {
				return err
			}
			if res.StatusCode != http.StatusOK {
				return fmt.Errorf("%q: unexpected status: %v", u, res.Status)
			}
			defer res.Body.Close()
			r := bufio.NewReader(res.Body)
			rd, err := newPageReader(ctx, r)
			if err != nil {
				return err
			}

			var files []string
			for l := range rd.Links() {
				switch {
				case strings.HasPrefix(l, "."):
					continue
				case strings.HasSuffix(l, "/"):
					eg.Go(chase(path.Join(p, l)))
				case strings.HasSuffix(l, `.xml`) ||
					strings.HasSuffix(l, `.md5`) ||
					strings.HasSuffix(l, `.sha1`):
					continue
				default:
					files = append(files, l)
				}
			}
			if len(files) != 0 {
				eg.Go(leaf(p, files))
			}
			return nil
		}
	}
	leaf = func(p string, fs []string) func() error {
		return func() error {
			if err := lim.Wait(ctx); err != nil {
				return err
			}
			for _, f := range fs {
				fmt.Println(scraperoot + path.Join(p, f))
			}
			return nil
		}
	}

	eg.Go(func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scraperoot, nil)
		if err != nil {
			return err
		}
		fmt.Printf("request: %q\n", scraperoot)
		res, err := c.Do(req)
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("%q: unexpected status: %v", scraperoot, res.Status)
		}
		defer res.Body.Close()
		r := bufio.NewReader(res.Body)
		rd, err := newPageReader(ctx, r)
		if err != nil {
			return err
		}

		for l := range rd.Links() {
			if !strings.HasSuffix(l, "/") || strings.HasPrefix(l, ".") {
				continue
			}
			eg.Go(chase(l))
		}
		return nil
	})
	if err := eg.Wait(); err != nil {
		panic(err)
	}
}
