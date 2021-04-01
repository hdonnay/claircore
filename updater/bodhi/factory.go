package bodhi

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/quay/zlog"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/label"

	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Configurable      = (*Factory)(nil)
	_ driver.UpdaterSetFactory = (*Factory)(nil)
)

// Factory ...
type Factory struct {
	root *url.URL
	c    *http.Client
}

// FactoryConfig ...
type FactoryConfig struct {
	API string `json:"api" yaml:"api"`
}

// UpdaterSet implements driver.UpdaterSetFactory.
func (f *Factory) UpdaterSet(ctx context.Context) (driver.UpdaterSet, error) {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "updater/bodhi/Factory.Configure"),
	)
	s := driver.NewUpdaterSet()
	if f.root == nil || f.c == nil {
		return s, errors.New("bodhi: Factory unconfigured")
	}

	c := client{Root: f.root, Client: f.c}
	rs, err := c.GetReleases(ctx)
	if err != nil {
		return s, err
	}
	for _, r := range rs {
		if r.Pending() {
			zlog.Debug(ctx).
				Stringer("release", r).
				Msg("release marked as pending, skipping")
			continue
		}
		if err := s.Add(&Updater{
			release: r,
			c:       f.c,
			root:    f.root,
		}); err != nil {
			zlog.Warn(ctx).
				Stringer("release", r).
				Err(err).
				Msg("unable to add updater")
		}
	}

	return s, nil
}

// Configure implement driver.Configurable.
func (f *Factory) Configure(ctx context.Context, cf driver.ConfigUnmarshaler, c *http.Client) error {
	ctx = baggage.ContextWithValues(ctx,
		label.String("component", "updater/bodhi/Factory.Configure"),
	)
	f.root = defaultAPI
	var cfg FactoryConfig
	if err := cf(&cfg); err != nil {
		return err
	}

	if cfg.API != "" {
		u, err := url.Parse(cfg.API)
		if err != nil {
			return err
		}
		f.root = u
		zlog.Info(ctx).
			Msg("configured API URL")
	}
	f.c = c
	zlog.Info(ctx).
		Msg("configured HTTP client")

	return nil
}
