// Package gobin implements a package scanner that pulls go runtime and
// dependency information out of a compiled executable.
package gobin

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"path/filepath"
	"runtime/trace"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"
	"golang.org/x/sync/errgroup"

	"github.com/quay/claircore"
)

type Scanner struct{}

func (s *Scanner) Name() string { return "gobin" }

func (s *Scanner) Version() string { return "1" }

func (s *Scanner) Kind() string { return "package" }

const toobig = 30 * (1024 * 1024) // 30MiB

// Scan performs a package scan on the given layer and returns all
// the found packages
func (s *Scanner) Scan(ctx context.Context, l *claircore.Layer) ([]*claircore.Package, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	trace.Log(ctx, "layer", l.Hash.String())
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "scanner/gobin/Scanner.Scan"),
		label.String("version", s.Version()),
		label.Stringer("layer", l.Hash))
	zlog.Debug(ctx).Msg("start")
	defer zlog.Debug(ctx).Msg("done")

	rd, err := l.Reader()
	if err != nil {
		return nil, err
	}
	defer rd.Close()

	var out []*claircore.Package
	ch := make(chan *exe, 4) // guess at buffering
	eg, ctx := errgroup.WithContext(ctx)

	// Tar-handling goroutine.
	eg.Go(func() error {
		defer close(ch)
		tr := tar.NewReader(rd)
		var h *tar.Header
		peek := make([]byte, 4)
		for h, err = tr.Next(); err == nil; h, err = tr.Next() {
			if ctx.Err() != nil {
				return nil
			}
			fi := h.FileInfo()
			m := fi.Mode()
			switch {
			case !m.IsRegular():
				continue
			case m.Perm()&0555 == 0:
				// Not executable
				continue
			}
			if _, err := io.ReadFull(tr, peek); err != nil {
				return err
			}
			if !bytes.HasPrefix(peek, []byte("\x7fELF")) && !bytes.HasPrefix(peek, []byte("MZ")) {
				// not an ELF or PE binary
				continue
			}
			if fi.Size() > toobig {
				zlog.Info(ctx).
					Int64("size", fi.Size()).
					Int64("threshold", toobig).
					Str("path", fi.Name()).
					Msg("large executable getting truncated")
			}

			b := make([]byte, min(fi.Size(), toobig))
			copy(b, peek)
			if _, err := io.ReadFull(tr, b[len(peek):]); err != nil {
				return err
			}
			exe, err := mkExe(filepath.Join(".", h.Name), b)
			if err != nil {
				zlog.Info(ctx).
					Str("path", fi.Name()).
					Err(err).
					Msg("unable to open executable")
				continue
			}
			ch <- exe
		}
		if err != io.EOF {
			return err
		}
		return nil
	})

	// exe handling goroutine
	eg.Go(func() error {
		for exe := range ch {
			ctx := baggage.ContextWithValues(ctx,
				label.String("exe", exe.name))

			ver, mod, err := exe.Info()
			if err != nil {
				zlog.Warn(ctx).
					Err(err).
					Msg("unable to interpret executable file")
				continue
			}
			if ver == "" {
				zlog.Debug(ctx).
					Err(err).
					Msg("no version found, skipping")
				continue
			}
			if len(mod) == 0 {
				zlog.Debug(ctx).
					Err(err).
					Msg("no module information found, skipping")
				continue
			}
			out = append(out, &claircore.Package{
				Kind:      claircore.BINARY,
				Name:      "runtime",
				Version:   ver,
				PackageDB: "go:" + exe.name,
			})
			ev := zlog.Debug(ctx)
			vs := map[string]string{
				"runtime": ver,
			}
			for _, l := range mod {
				switch l[0] {
				case "path":
					// "Path" provides us with the main package's package path.
					// Packages aren't versioned, just modules, so this isn't
					// very helpful.
				case "mod", "dep":
					// "Mod" is the module that contains the main package. If
					// built from source, it will always be "(devel)".
					// "Dep" is a dependency.
					if ev.Enabled() {
						vs[l[1]] = l[2]
					}
					out = append(out, &claircore.Package{
						Kind:      claircore.BINARY,
						PackageDB: "go:" + exe.name,
						Name:      l[1],
						Version:   l[2],
					})
				}
			}
			ev.
				Interface("versions", vs).
				Msg("analyzed exe")
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return out, err
	}
	return out, nil
}

func min(a, b int64) int {
	if a < b {
		return int(a)
	}
	return int(b)
}
