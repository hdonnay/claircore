package main

import (
	"cmp"
	"context"
	"errors"
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

	"golang.org/x/exp/trace"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
	_ "modernc.org/sqlite" // register the sqlite driver
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
	flag.StringVar(&databasePath, "db", "index.db", "current state database")
	flag.StringVar(&indexRoot, "index", `https://repo.maven.apache.org/maven2/.index/`, "index root URL")
	flag.StringVar(&chainOverride, "override-chainid", "", "override the chain id stored in the database (pass \"-\" to forcibly reset)")
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
		var root *url.URL
		root, err = url.Parse(indexRoot)
		if err != nil {
			return
		}

		var db *DB
		db, err = OpenDB(ctx, databasePath)
		if err != nil {
			return
		}
		defer db.Close()

		var dbChain string
		var dbIndex int
		dbChain, err = db.ReadChainID(ctx)
		if err != nil {
			return
		}
		dbIndex, err = db.ReadLastIndex(ctx)
		if err != nil {
			return
		}

		cur := LocalState{
			Chain: cmp.Or(chainOverride, dbChain),
			Last:  cmp.Or(lastIndexOverride, dbIndex),
		}
		err = Main(ctx, db, cur, root)
	}()

	wg.Wait()
	if err != nil {
		slog.Error("unexpected exit", "reason", err)
		os.Exit(1)
	}
}

func Main(ctx context.Context, db *DB, cur LocalState, root *url.URL) error {
	ir, err := NewIndexReader(ctx, cur, root)
	if err != nil {
		slog.ErrorContext(ctx, "unable to create index reader", "error", err)
		return err
	}
	slog.InfoContext(ctx, "attempting index update", "incremental", ir.Incremental())

	eg, egCtx := errgroup.WithContext(ctx)
	ch := make(chan Record, runtime.NumCPU())

	eg.Go(func() error {
		defer close(ch)
		for cr, err := range ir.Chunks(egCtx) {
			if err != nil {
				slog.ErrorContext(egCtx, "unable to read chunk", "error", err)
				return err
			}
			for r, err := range cr.All(egCtx) {
				if err != nil {
					slog.ErrorContext(egCtx, "unable to read record", "error", err)
					return err
				}
				select {
				case <-egCtx.Done():
					return context.Cause(egCtx)
				case ch <- r:
				}
			}
		}
		return nil
	})
	// Importer goroutine
	eg.Go(func() error {
		ct := 0
		start := time.Now()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		defer func() {
			if ct == 0 { // Skip this if there were no chunks.
				return
			}
			// Use the "outer" context here, on purpose.
			if err := db.CommitRecords(ctx); err != nil {
				slog.ErrorContext(ctx, "unexpected commit error while exiting", "error", err)
			}
			rps := float64(ct) / time.Since(start).Seconds()
			slog.InfoContext(ctx, "wrote records", "count", ct, "records_per_second", rps)
		}()
	Recv:
		for {
			select {
			case r, ok := <-ch:
				if !ok {
					break Recv
				}
				if err := db.WriteRecord(egCtx, r); err != nil {
					return err
				}
				ct++
			case <-tick.C:
				rps := float64(ct) / time.Since(start).Seconds()
				start := time.Now()
				if err := db.CommitRecords(egCtx); err != nil {
					return err
				}
				slog.InfoContext(egCtx, "committed records", "count", ct, "records_per_second", math.Round(rps), "commit_dur", time.Since(start))
			}
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return err
	}

	// Write back the current index state.
	if err := errors.Join(
		db.WriteChainID(ctx, ir.ChainID()),
		db.WriteLastIndex(ctx, ir.LastIndex()),
	); err != nil {
		return err
	}

	return nil
}
