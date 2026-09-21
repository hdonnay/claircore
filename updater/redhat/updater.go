package redhat

import (
	"archive/tar"
	"bufio"
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"sync"

	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/toolkit/types/cvss"
	"github.com/quay/claircore/updater/driver"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore/internal/httputil"
	"github.com/quay/claircore/internal/zreader"
)

var _ driver.Updater = (*Updater)(nil)

type Updater struct {
	Layout     *Layout
	CutoffYear int
}

// UpdateAdvisories implements [driver.Updater].
func (u *Updater) UpdateAdvisories(ctx context.Context, c *http.Client, upd driver.UpdateBuilder) error {
	meta, _, err := upd.PreviousOp(ctx)
	if err != nil {
		return err
	}
	if meta == nil {
		return u.ColdStart(ctx, c, upd)
	}
	return u.Incremental(ctx, c, upd)
}

// ColdStart is the "cold start" flow: there are no previous updates, so ingest
// just the archive.
func (u *Updater) ColdStart(ctx context.Context, c *http.Client, upd driver.UpdateBuilder) error {
	ar, err := u.Layout.ArchiveURL(ctx, c)
	if err != nil {
		return err
	}
	req := newRequest(ctx, ar)
	res, err := c.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if err := httputil.CheckResponse(res, http.StatusOK); err != nil {
		return err
	}

	pool := &sync.Pool{
		New: func() any {
			var b bytes.Buffer
			b.Grow(1 << 20)
			return &b
		},
	}
	eg, ctx := errgroup.WithContext(ctx)
	eg.SetLimit(max(4, runtime.GOMAXPROCS(0)))
	// Art is a concurrency-safe caching layer for "artifacts".
	art := new(ArtifactCache)
	// DoOne is the function called for every CSAF document. The passed
	// [*bytes.Buffer] comes from [pool]. The returned function is run in its
	// own errgroup goroutine.
	var doOne func(buf *bytes.Buffer) func() error
	// CreateAdvisory is the function called once the CSAF JSON has been parsed.
	var createAdvisory func(ctx context.Context, doc *csaf.CSAF, adv driver.AdvisoryBuilder) error

	doOne = func(buf *bytes.Buffer) func() error {
		return func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			ctx, done := context.WithCancel(ctx)
			defer done()
			doc, err := csaf.Parse(buf)
			if buf.Cap() <= 4<<20 {
				buf.Reset()
				pool.Put(buf)
			}
			if err != nil {
				return fmt.Errorf("error parsing CSAF: %w", err)
			}
			id := doc.Document.Tracking.ID
			adv, err := upd.CreateAdvisory(ctx, id)
			if err != nil {
				return err
			}
			if err := createAdvisory(ctx, doc, adv); err != nil {
				adv.Abandon(ctx, err)
				return err
			}
			if err := adv.Build(ctx); err != nil {
				return err
			}
			slog.DebugContext(ctx, "built advisory", "id", id)
			return nil
		}
	}

	createAdvisory = func(ctx context.Context, doc *csaf.CSAF, adv driver.AdvisoryBuilder) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := errors.Join(
			adv.Issued(ctx, doc.Document.Tracking.InitialReleaseDate),
			adv.Updated(ctx, doc.Document.Tracking.CurrentReleaseDate),
		); err != nil {
			return err
		}
		if err := adv.Self(ctx, driver.Alias{}); err != nil { // TODO(hank)
			return err
		}

		if l := len(doc.Vulnerabilities); l != 1 {
			return fmt.Errorf("unexpected number of vulnerabilities: %d", l)
		}
		v := &doc.Vulnerabilities[0]
		adv.Description(ctx, v.Description())
		//adv.Title(ctx, "") // TODO(hank) Add "title" member to the csaf type.

		for which, seq := range statuses(ctx, doc, v) {
			var create CreateArtifactFunc
			switch which {
			case csaf.ProductStatusFixed:
				create = func(ctx context.Context, art driver.ArtifactBuilder, st *status) error {
					err := errors.Join(
						art.State(ctx, driver.ArtifactStateVulnerable),
						art.Purl(ctx, st.PURL),
						art.CPE(ctx, st.WFN),
					)
					if err != nil {
						return err
					}
					var normsev driver.Severity
					if t := st.Threat; t != nil {
						normsev = normalizeSeverity(t.Details)
					}
					origsev := cmp.Or(
						func() string {
							if v := st.Score.CVSSV4; v != nil {
								return v.VectorString
							}
							return ""
						}(),
						func() string {
							if v := st.Score.CVSSV3; v != nil {
								return v.VectorString
							}
							return ""
						}(),
						func() string {
							if v := st.Score.CVSSV2; v != nil {
								return v.VectorString
							}
							return ""
						}(),
					)
					if err = art.Severity(ctx, origsev, normsev); err != nil {
						return err
					}
					if sc := st.Score; sc != nil {
						const msg = `unable to parse CVSS vector`
						if v4 := st.Score.CVSSV4; v4 != nil {
							vec, err := cvss.ParseV4(v4.VectorString)
							if err != nil {
								slog.WarnContext(ctx, msg, "version", v4.Version, "vector", v4.VectorString, "reason", err)
							} else {
								if err := art.CVSSv4(ctx, vec); err != nil {
									return err
								}
							}
						}
						if v3 := st.Score.CVSSV3; v3 != nil {
							vec, err := cvss.ParseV3(v3.VectorString)
							if err != nil {
								slog.WarnContext(ctx, msg, "version", v3.Version, "vector", v3.VectorString, "reason", err)
							} else {
								if err := art.CVSSv3(ctx, vec); err != nil {
									return err
								}
							}
						}
					}
					return nil
				}
			case csaf.ProductStatusKnownAffected:
				continue
			case csaf.ProductStatusKnownNotAffected:
				continue
			default:
				continue
			}

			for st, err := range seq {
				if err != nil {
					slog.DebugContext(ctx, "unable to process product", "reason", err)
					continue
				}
				switch which {
				case csaf.ProductStatusFixed:
					if v, ok := qualifier(st.PURL, `arch`); ok && (v == `src` || v == `nosrc`) {
						continue
					}
				}

				h, err := art.Get(ctx, upd, &st, create)
				if err != nil {
					return err
				}
				if err := adv.AddArtifact(ctx, h); err != nil {
					return err
				}
			}
		}

		return nil
	}

	eg.Go(func() error {
		// BUG(hank) This code only handles 4-digit CE years. CVEs from before
		// the eleventh or beyond hundredth century are simply inexpressible in
		// this package.
		cutoff := strconv.Itoa(u.CutoffYear)
		zr, err := zreader.Reader(bufio.NewReader(res.Body))
		if err != nil {
			return err
		}
		defer zr.Close()
		tr := tar.NewReader(zr)

		h, err := tr.Next()
		for ; err == nil; h, err = tr.Next() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if h.Typeflag != tar.TypeReg {
				continue
			}
			dir := path.Dir(h.Name)
			if dir < cutoff {
				continue
			}

			buf := pool.Get().(*bytes.Buffer)
			if _, err := io.Copy(buf, tr); err != nil {
				return err
			}
			eg.Go(doOne(buf))
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}
	return driver.ErrAgain // Request an immediate incremental update.
}

func (u *Updater) Incremental(ctx context.Context, c *http.Client, upd driver.UpdateBuilder) error {
	return errors.ErrUnsupported
}
