package redhat

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/quay/claircore/updater/driver"
	"github.com/quay/claircore/updater/driver/drivertest"
	"go.uber.org/mock/gomock"
)

func TestUpdater(t *testing.T) {
	t.Parallel()
	t.Run("ColdStart", testUpdaterColdStart)
}

func testUpdaterColdStart(t *testing.T) {
	const cutoffYear = 2026

	ctrl := gomock.NewController(t)
	matchCtx := gomock.AssignableToTypeOf(reflect.TypeFor[context.Context]())
	matchString := gomock.AssignableToTypeOf(reflect.TypeFor[string]())
	matchTime := gomock.Cond(func(at time.Time) bool {
		return at.Year() >= cutoffYear
	})
	upd := drivertest.NewUpdateBuilder(ctrl)
	rec := upd.EXPECT()
	rec.CreateAdvisory(matchCtx, matchString).
		DoAndReturn(func(ctx context.Context, id string) (driver.AdvisoryBuilder, error) {
			t.Log(id)
			adv := drivertest.NewAdvisoryBuilder(ctrl)
			rec := adv.EXPECT()
			rec.Issued(matchCtx, matchTime)
			rec.Updated(matchCtx, matchTime)
			rec.Self(matchCtx, gomock.Any())
			rec.Description(matchCtx, matchString)
			rec.Build(matchCtx).MaxTimes(1)
			rec.Abandon(matchCtx, gomock.Any()).MaxTimes(1)
			return adv, nil
		}).
		AnyTimes()
	rec.CreateArtifact(matchCtx).
		DoAndReturn(func(ctx context.Context) (driver.ArtifactBuilder, error) {
			art := drivertest.NewArtifactBuilder(ctrl)
			rec := art.EXPECT()
			rec.State(matchCtx, gomock.Any()).Return(errors.ErrUnsupported)
			rec.Purl(matchCtx, gomock.Any()).Return(errors.ErrUnsupported)
			rec.CPE(matchCtx, gomock.Any()).Return(errors.ErrUnsupported)
			rec.Build(matchCtx).MaxTimes(1)
			rec.Abandon(matchCtx, gomock.Any()).MaxTimes(1)
			return art, nil
		}).
		AnyTimes()

	u := &Updater{
		Layout: &Layout{
			Root: func() *url.URL {
				u, err := url.Parse("https://security.access.redhat.com/data/csaf/v2/vex-feed/")
				if err != nil {
					t.Fatal(err)
				}
				return u
			}(),
		},
		CutoffYear: cutoffYear,
	}
	ctx := t.Context()
	if err := u.ColdStart(ctx, http.DefaultClient, upd); err != nil {
		t.Error(err)
	}
}
