package redhat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"

	"github.com/quay/claircore/internal/httputil"
)

type Layout struct {
	Root *url.URL
}

func (l *Layout) ArchiveURL(ctx context.Context, c *http.Client) (*url.URL, error) {
	uri, err := l.Root.Parse(`archive_latest.txt`)
	if err != nil {
		return nil, err
	}
	req := newRequest(ctx, uri)
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	err = httputil.CheckResponse(res, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("unexpected response from archive_latest.txt: %w", err)
	}
	b, err := io.ReadAll(res.Body) // Fine to use; expecting small number of bytes.
	if err != nil {
		return nil, err
	}
	ref := string(bytes.TrimSpace(b))

	uri, err = l.Root.Parse(ref)
	if err != nil {
		return nil, err
	}
	return uri, nil
}

func (l *Layout) Changes(ctx context.Context, c *http.Client, match string, cutoff, reqTime time.Time) (iter.Seq2[ChangesEntry, error], error) {
	const ref = `changes.csv`
	uri, err := l.Root.Parse(ref)
	if err != nil {
		return nil, err
	}
	req := newRequest(ctx, uri)
	if match != "" {
		req.Header.Add(`If-None-Match`, match)
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	root := l.Root

	seq := func(yield func(ChangesEntry, error) bool) {
		defer res.Body.Close()

		rd := csv.NewReader(bufio.NewReader(res.Body))
		rd.FieldsPerRecord = 2
		rd.ReuseRecord = true
		l := 0
		for rec, err := rd.Read(); err == nil; rec, err = rd.Read() {
			l++
			year, err := strconv.ParseInt(path.Dir(rec[0]), 10, 64)
			if err != nil {
				err = fmt.Errorf("%s:%d: error parsing year: %w", ref, l, err)
				if !yield(ChangesEntry{}, err) {
					return
				}
				continue
			}
			y := int(year)
			if y < cutoff.Year() {
				continue
			}
			t, err := time.Parse(time.RFC3339, rec[1])
			if err != nil {
				err = fmt.Errorf("%s:%d: error parsing time: %w", ref, l, err)
				if !yield(ChangesEntry{}, err) {
					return
				}
				continue
			}
			if t.Before(reqTime) {
				continue
			}
			u, err := root.Parse(rec[0])
			if err != nil {
				err = fmt.Errorf("%s:%d: error parsing ref: %w", ref, l, err)
				if !yield(ChangesEntry{}, err) {
					return
				}
				continue
			}

			ent := ChangesEntry{
				URL:     u,
				Year:    y,
				Updated: t,
			}
			if !yield(ent, nil) {
				return
			}
		}
	}
	return seq, nil
}

type ChangesEntry struct {
	URL     *url.URL
	Year    int
	Updated time.Time
}

func (l *Layout) Deletions(ctx context.Context, c *http.Client, match string, cutoff, reqTime time.Time) (iter.Seq2[DeletionsEntry, error], error) {
	const ref = `deletions.csv`
	uri, err := l.Root.Parse(ref)
	if err != nil {
		return nil, err
	}
	req := newRequest(ctx, uri)
	if match != "" {
		req.Header.Add(`If-None-Match`, match)
	}
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	seq := func(yield func(DeletionsEntry, error) bool) {
		defer res.Body.Close()

		rd := csv.NewReader(bufio.NewReader(res.Body))
		rd.FieldsPerRecord = 2
		rd.ReuseRecord = true
		l := 0
		for rec, err := rd.Read(); err == nil; rec, err = rd.Read() {
			l++
			year, err := strconv.ParseInt(path.Dir(rec[0]), 10, 64)
			if err != nil {
				err = fmt.Errorf("%s:%d: error parsing year: %w", ref, l, err)
				if !yield(DeletionsEntry{}, err) {
					return
				}
				continue
			}
			y := int(year)
			if y < cutoff.Year() {
				continue
			}
			t, err := time.Parse(time.RFC3339, rec[1])
			if err != nil {
				err = fmt.Errorf("%s:%d: error parsing time: %w", ref, l, err)
				if !yield(DeletionsEntry{}, err) {
					return
				}
				continue
			}
			if t.Before(reqTime) {
				continue
			}

			ent := DeletionsEntry{
				Ref:     rec[0],
				Updated: t,
			}
			if !yield(ent, nil) {
				return
			}
		}
	}
	return seq, nil
}

type DeletionsEntry struct {
	Ref     string
	Updated time.Time
}
