package main

import (
	"cmp"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"time"

	"github.com/quay/claircore/internal/mavenindex"
	"golang.org/x/exp/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const Trace = slog.LevelDebug - 4

var rec = trace.NewFlightRecorder()

func main() {
	ctx := context.Background()
	var logLevel slog.LevelVar
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: &logLevel,
	})))

	var databasePath string
	var indexRoot string
	var chainOverride string
	var lastIndexOverride int
	debugLogFlag := flag.Bool("D", false, "debug logging")
	traceLogFlag := flag.Bool("DD", false, "trace logging")
	traceFlag := flag.Bool("trace", false, "write execution trace when sent USR1")
	flag.StringVar(&databasePath, "db", "repository.db", "SQLite database")
	flag.StringVar(&indexRoot, "index", `https://repo.maven.apache.org/maven2/.index/`, "index root URL")
	flag.StringVar(&chainOverride, "override-chainid", "", "override the chain id in the SQLite database")
	flag.IntVar(&lastIndexOverride, "override-lastindex", lastIndexOverride, "override the id of the last incremental updated consumed")
	flag.Parse()
	switch {
	case *debugLogFlag:
		logLevel.Set(slog.LevelDebug)
	case *traceLogFlag:
		logLevel.Set(Trace)
	}

	var wg sync.WaitGroup
	ctx, done := context.WithCancel(ctx)
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, unix.SIGINT, unix.SIGTERM)
	wg.Add(1)
	// Create a goroutine that immediately restores the default signal handler,
	// so ^C^C exits immediately.
	go func() {
		<-ctx.Done()
		stop()
		slog.Debug("exiting")
		wg.Done()
	}()

	if *traceFlag {
		rec.SetSize(16 << 20)
		usr1 := make(chan os.Signal, 1)
		signal.Notify(usr1, unix.SIGUSR1)
		wg.Add(2)
		go func() {
			// On context cancellation, stop listening for USR1 and close the
			// channel relaying that signal.
			<-ctx.Done()
			signal.Stop(usr1)
			rec.Stop()
			close(usr1)
			wg.Done()
		}()
		go func() {
			// Read from the USR1 relay channel until closed.
			// Context cancellation is propagated from the above goroutine.
			defer wg.Done()
			n := 0
			for range usr1 {
				name := fmt.Sprintf("trace.out.%04d", n)
				l := slog.With("name", name)
				f, err := os.Create(name)
				if err != nil {
					l.ErrorContext(ctx, "unable to create trace output", "error", err)
					continue
				}
				n++
				if _, err := rec.WriteTo(f); err != nil {
					l.ErrorContext(ctx, "unable to write trace output", "error", err)
				}
				if err := f.Close(); err != nil {
					l.ErrorContext(ctx, "unable to close trace output", "error", err)
				}
				l.InfoContext(ctx, "wrote trace output")
			}
		}()
		rec.Start()
	}

	var err error
	go func() {
		defer done()
		var remoteRoot *url.URL
		remoteRoot, err = url.Parse(indexRoot)
		if err != nil {
			return
		}

		var out *LocalIndex
		out, err = NewLocalIndex(ctx, databasePath)
		if err != nil {
			return
		}
		var chain string
		chain, err = out.ReadChainID(ctx)
		if err != nil {
			return
		}
		var last int
		last, err = out.ReadLastIndex(ctx)
		if err != nil {
			return
		}

		local := mavenindex.LocalState{
			Chain: cmp.Or(chain, chainOverride),
			Last:  cmp.Or(last, lastIndexOverride),
		}
		err = Main(ctx, out, local, remoteRoot)
	}()

	wg.Wait()
	if err != nil {
		slog.Error("unexpected exit", "reason", err)
		os.Exit(1)
	}
}

func Main(ctx context.Context, out *LocalIndex, local mavenindex.LocalState, remoteRoot *url.URL) error {
	ir, err := mavenindex.NewIndexReader(ctx, local, remoteRoot)
	if err != nil {
		slog.ErrorContext(ctx, "unable to create index reader", "error", err)
		return err
	}
	slog.InfoContext(ctx, "attempting index update", "incremental", ir.Incremental())

	eg, egCtx := errgroup.WithContext(ctx)
	ch := make(chan mavenindex.Record, runtime.NumCPU()*8)
	defer func() {
		if err := out.Close(ctx); err != nil {
			slog.ErrorContext(ctx, "unable to close index writer", "error", err)
		}
	}()

	eg.Go(func() error {
		defer close(ch)
		eg, ctx := errgroup.WithContext(egCtx)
		eg.SetLimit(min(runtime.GOMAXPROCS(0), 4))
		n := 0
		for cr, err := range ir.Chunks(ctx) {
			if err != nil {
				slog.ErrorContext(egCtx, "unable to read chunk", "error", err)
				return err
			}
			n++
			n := n // copy for the closure
			eg.Go(func() error {
				for r, err := range cr.All(ctx) {
					if err != nil {
						slog.ErrorContext(egCtx, "unable to read record", "error", err)
						return err
					}
					select {
					case <-ctx.Done():
						return context.Cause(ctx)
					case ch <- r:
					}
				}
				slog.DebugContext(egCtx, "chunk done", "number", n)
				return nil
			})
		}
		return eg.Wait()
	})
	// Importer goroutine
	eg.Go(func() error {
		ct := 0
		start := time.Now()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		emitLog := func() {
			rps := math.Round(float64(ct) / time.Since(start).Seconds())
			slog.InfoContext(ctx, "wrote records",
				"count", ct,
				"records_per_second", rps,
				"runtime", time.Since(start).Round(time.Second),
			)
		}
		defer func() {
			if ct != 0 { // Skip this if there were no chunks.
				emitLog()
			}
		}()

	Recv:
		for {
			select {
			case r, ok := <-ch:
				if !ok {
					break Recv
				}
				out.Enqueue(r)
				ct++
				if out.Len() > 16*1024 {
					if err := out.Flush(ctx); err != nil {
						return err
					}
				}
			case <-tick.C:
				emitLog()
			}
		}

		if err := out.Flush(ctx); err != nil {
			return err
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// Write back the current index state.
	if err := out.WriteLastIndex(ctx, ir.LastIndex()); err != nil {
		return err
	}

	return nil
}
