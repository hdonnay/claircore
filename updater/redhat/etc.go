package redhat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore/toolkit/types/csaf"
	"github.com/quay/claircore/toolkit/types/cvss"
	"github.com/quay/claircore/updater/driver"
)

func newRequest(ctx context.Context, u *url.URL) *http.Request {
	return (&http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       nil,
		Host:       u.Host,
	}).WithContext(ctx)
}

func cvssBaseScoreFromScore(sc *csaf.Score) float64 {
	switch {
	case sc.CVSSV4 != nil:
		return sc.CVSSV4.BaseScore
	case sc.CVSSV3 != nil:
		return sc.CVSSV3.BaseScore
	case sc.CVSSV2 != nil:
		return sc.CVSSV2.BaseScore
	default:
		return 0.0
	}
}

func cvssVectorFromScore(sc *csaf.Score) (vec string, err error) {
	switch {
	case sc == nil:
		err = errors.New("no Score object")
	case sc.CVSSV4 != nil:
		_, err = cvss.ParseV4(sc.CVSSV4.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		vec = sc.CVSSV4.VectorString
	case sc.CVSSV3 != nil:
		_, err = cvss.ParseV3(sc.CVSSV3.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv3 vector string %w", err)
			return
		}
		vec = sc.CVSSV3.VectorString
	case sc.CVSSV2 != nil:
		_, err = cvss.ParseV2(sc.CVSSV2.VectorString)
		if err != nil {
			err = fmt.Errorf("could not parse CVSSv4 vector string %w", err)
			return
		}
		vec = sc.CVSSV2.VectorString
	default:
		err = errors.New("could not find a valid CVSS object")
	}
	return
}

// Qualifier returns the value of the indicated qualifier and whether it was
// found.
//
// Using this rather than the [packageurl.Qualifiers.Map] method exploits the
// fact that the [packageurl.Qualifiers] is sorted, so we don't need to
// construct a new map to do an efficient lookup.
func qualifier(p *packageurl.PackageURL, key string) (string, bool) {
	qs := p.Qualifiers
	cmp := func(q packageurl.Qualifier, key string) int {
		return strings.Compare(q.Key, key)
	}
	i, ok := slices.BinarySearchFunc(qs, key, cmp)
	if !ok {
		return "", false
	}
	return qs[i].Value, true
}

// NormalizeSeverity maps Red Hat severity strings to claircore's normalized
// severity levels.
func normalizeSeverity(severity string) driver.Severity {
	switch strings.ToLower(severity) {
	case "none":
		return driver.SeverityNegligible
	case "low":
		return driver.SeverityLow
	case "moderate":
		return driver.SeverityMedium
	case "important":
		return driver.SeverityHigh
	case "critical":
		return driver.SeverityCritical
	default:
		return driver.SeverityUnknown
	}
}
