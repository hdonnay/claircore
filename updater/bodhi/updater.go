package bodhi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/pkg/tmp"
)

var (
	_ driver.Updater      = (*Updater)(nil)
	_ driver.Configurable = (*Updater)(nil)
)

// Updater ...
type Updater struct {
	// Unconfigurable, set at construction.
	release release

	// Configured in the Configure method; also passed down from construction.
	root *url.URL
	c    *http.Client
}

func (u *Updater) client() client {
	return client{Root: u.root, Client: u.c}
}

// UpdaterConfig ...
type UpdaterConfig struct {
	API string `json:"api" yaml:"api"`
}

func (u *Updater) Configure(ctx context.Context, f driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "updater/bodhi/Updater.Configure"),
		label.String("updater", u.Name()),
	)
	var cfg UpdaterConfig
	if err := f(&cfg); err != nil {
		return err
	}

	if cfg.API != "" {
		api, err := url.Parse(cfg.API)
		if err != nil {
			return err
		}
		u.root = api
		zlog.Info(ctx).
			Msg("configured API URL")
	}
	u.c = c
	zlog.Info(ctx).
		Msg("configured HTTP client")
	return nil
}

// Name implements driver.Updater.
func (u *Updater) Name() string { return fmt.Sprintf("bodhi-%s", u.release) }

type fingerprint struct {
	Since time.Time `json:"since"`
}

// Fetch implements driver.Updater.
func (u *Updater) Fetch(ctx context.Context, prev driver.Fingerprint) (io.ReadCloser, driver.Fingerprint, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "updater/bodhi/Updater.Configure"),
		label.String("updater", u.Name()),
	)
	var fp fingerprint
	if err := json.Unmarshal([]byte(prev), &fp); len(prev) != 0 && err != nil {
		zlog.Warn(ctx).
			Err(err).
			Msg("unable to make sense of previous fingerprint")
		prev = ""
	}
	c := u.client()

	more, err := c.AnySince(ctx, &u.release, fp.Since)
	if err != nil {
		return nil, prev, err
	}
	if !more {
		return nil, prev, driver.Unchanged
	}

	out, err := tmp.NewFile("", "bodhi.")
	if err != nil {
		return nil, prev, err
	}
	fp.Since = time.Now()
	if err := c.Fetch(ctx, &u.release, out); err != nil {
		out.Close()
		return nil, prev, err
	}
	fpb, err := json.Marshal(fp)
	if err != nil {
		out.Close()
		return nil, prev, err
	}
	return out, driver.Fingerprint(string(fpb)), nil
}

// Parse implements driver.Updater.
func (u *Updater) Parse(ctx context.Context, rc io.ReadCloser) ([]*claircore.Vulnerability, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "updater/bodhi/Updater.Configure"),
		label.String("updater", u.Name()),
	)
	panic("not implemented") // TODO: Implement
}

func (u *Updater) checkArchived(vs []*claircore.Vulnerability, err error) ([]*claircore.Vulnerability, error) {
	if err == nil && u.release.Archived() {
		vs = append(vs, &claircore.Vulnerability{}) // TODO(hank) Something that marks a whole distro as vulnerable.
	}
	return vs, err
}
