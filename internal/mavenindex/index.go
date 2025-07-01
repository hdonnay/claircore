package mavenindex

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// LocalState describes the state of a local index.
type LocalState struct {
	Chain string
	Last  int
}

// NewIndexReader creates an IndexReader that can iterate over index chunks to
// update the local state.
func NewIndexReader(ctx context.Context, local LocalState, remoteRoot *url.URL) (*IndexReader, error) {
	ir := IndexReader{
		root:  remoteRoot,
		local: local,
	}

	req, err := ir.makeRequest(ctx, ".properties")
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	default:
		return nil, fmt.Errorf("unexpected response status: %s", res.Status)
	}

	if err := ir.remote.Parse(res.Body); err != nil {
		return nil, err
	}

	switch ir.local.Chain {
	case "":
		slog.InfoContext(ctx, "no local chain specified, adopting the remote chain")
		ir.local.Chain = ir.remote.Chain
	case "-":
		slog.InfoContext(ctx, "forcibly adopting the remote chain")
		ir.local.Chain = ir.remote.Chain
	}
	if l, r := ir.local.Chain, ir.remote.Chain; l != r {
		return nil, fmt.Errorf("chain mismatch: local: %q, remote: %q", l, r)
	}

	slog.InfoContext(ctx, "local state", "chain", ir.local.Chain, "last_index", ir.local.Last)
	slog.InfoContext(ctx, "remote state", "chain", ir.remote.Chain, "last_index", ir.remote.Last, "increments", ir.remote.Incremental)
	slog.DebugContext(ctx, "status", "can_incremental", ir.Incremental())

	return &ir, nil
}

// IndexReader reads from a remote index export, returning chunks
// ([ChunkReader]s) containing changes ([Record]s) that will bring the local
// index into the same state as the export.
//
// Callers should use [IndexReader.Incremental] to determine the best strategy
// for updating the persisted representation of the index.
type IndexReader struct {
	root   *url.URL
	local  LocalState
	remote RemoteState
}

func (i *IndexReader) makeRequest(ctx context.Context, suffix string) (*http.Request, error) {
	const (
		indexFilePrefix = `nexus-maven-repository-index`
		userAgent       = `github.com/quay/claircore/internal/mavenindex@v0`
	)
	u := i.root.JoinPath(indexFilePrefix + suffix)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add(`user-agent`, userAgent)
	return req, nil
}

// Incremental reports if the local index can be updated incrementally.
//
// If false, the whole compacted index will be returned. Callers may want to
// drop any previous data and start from scratch.
func (i *IndexReader) Incremental() bool {
	if i.local.Chain != i.remote.Chain {
		return false
	}
	if i.local.Last == i.remote.Last {
		return true
	}

	return slices.Contains(i.remote.Incremental, i.local.Last+1)
}

// ChainID reports the chain ID of this index.
//
// Different ChainIDs are different indexes.
func (i *IndexReader) ChainID() string {
	return i.local.Chain
}

// LastIndex reports the incremental index counter of this Index.
//
// After successfully consuming the iterator returned by [IndexReader.Chunks],
// callers should record this and pass it into the next call to
// [NewIndexReader].
func (i *IndexReader) LastIndex() int {
	return i.local.Last
}

// Chunks returns an iterator over index chunks.
//
// This may be called multiple times, but the returned iterators are not safe
// for concurrent use.
func (i *IndexReader) Chunks(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	if i.local.Last == i.remote.Last {
		slog.InfoContext(ctx, "already up to date")
		// Empty iterator.
		return func(_ func(*ChunkReader, error) bool) {}
	}
	if !i.Incremental() {
		return i.fullIndex(ctx)
	}
	return i.incrementalIndex(ctx)
}

// FullIndex streams the full index from the remote and returns a single
// [ChunkReader].
func (i *IndexReader) fullIndex(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	return func(yield func(*ChunkReader, error) bool) {
		req, err := i.makeRequest(ctx, ".gz")
		if err != nil {
			yield(nil, fmt.Errorf("unable to construct request: %w", err))
			return
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			yield(nil, fmt.Errorf("unable to execute request: %w", err))
			return
		}
		// NB Close not deferred.
		switch res.StatusCode {
		case http.StatusOK:
		default:
			res.Body.Close()
			yield(nil, fmt.Errorf("unexpected response status: %s", res.Status))
			return
		}

		cr, err := NewChunkReader(res.Body)
		if err != nil {
			i.local.Last = i.remote.Last
			slog.DebugContext(ctx, "full chunk reader created")
		}
		yield(cr, err)
	}
}

// IncrementalIndex streams incremental indexes in order, returning a
// [ChunkReader] over each.
func (i *IndexReader) incrementalIndex(ctx context.Context) iter.Seq2[*ChunkReader, error] {
	done := errors.New("iteration done")

	return func(yield func(*ChunkReader, error) bool) {
		// Incremental checks that the value is actually here.
		off := slices.Index(i.remote.Incremental, i.local.Last+1)
		for _, n := range i.remote.Incremental[off:] {
			err := func() error {
				slog.DebugContext(ctx, "processing incremental index", "number", n)
				req, err := i.makeRequest(ctx, fmt.Sprintf(`.%d.gz`, n))
				if err != nil {
					return fmt.Errorf("unable to construct request: %w", err)
				}
				res, err := http.DefaultClient.Do(req)
				if err != nil {
					return fmt.Errorf("unable to execute request: %w", err)
				}
				// NB Close not deferred.
				switch res.StatusCode {
				case http.StatusOK:
				default:
					res.Body.Close()
					return fmt.Errorf("unexpected response status: %s", res.Status)
				}

				cr, err := NewChunkReader(res.Body)
				slog.DebugContext(ctx, "incremental chunk reader created", "error", err)
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
			i.local.Last = n
		}
	}
}

// RemoteState describes the state of an index export.
type RemoteState struct {
	ID        string
	Creation  time.Time
	Published time.Time
	Chain     string

	Last        int
	Incremental []int
}

// ParseRemoteState allocates a [RemoteState] and calls Parse on it.
func ParseRemoteState(rd io.Reader) (*RemoteState, error) {
	var r RemoteState
	return &r, r.Parse(rd)
}

// Parse parses the java-style properties file describing the index and stores
// the result in the receiver.
func (r *RemoteState) Parse(rd io.Reader) error {
	const layout = `20060102150405.000 Z0700`
	s := bufio.NewScanner(rd)
	for s.Scan() {
		if b := s.Bytes(); b[0] == '#' || len(b) == 0 {
			continue
		}
		key, value, ok := strings.Cut(s.Text(), "=")
		if !ok { // ???
			return fmt.Errorf("bad/unknown line: %q", s.Text())
		}
		key = strings.TrimPrefix(key, `nexus.index.`)

		var err error
		switch key {
		case `id`:
			r.ID = value
		case `chain-id`:
			r.Chain = value
		case `timestamp`:
			r.Published, err = time.Parse(layout, value)
		case `time`:
			r.Creation, err = time.Parse(layout, value)
		case `last-incremental`:
			r.Last, err = strconv.Atoi(value)
		default:
			if strings.HasPrefix(key, `incremental-`) {
				var n int
				n, err = strconv.Atoi(value)
				if err != nil {
					break
				}
				r.Incremental = append(r.Incremental, n)
			}
		}
		if err != nil {
			return err
		}
	}
	if err := s.Err(); err != nil {
		return err
	}

	slices.Sort(r.Incremental)

	return nil
}
