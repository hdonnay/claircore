//go:build skip

package postgres

import (
	"context"
	"iter"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/quay/claircore/updater/driver/v1"
)

type advisorySource struct {
	next func() (driver.Vulnerability, error, bool)
	stop func()

	v   driver.Vulnerability
	err error
}

var _ pgx.CopyFromSource = (*advisorySource)(nil)

func advisoryCopySource(ctx context.Context, vs iter.Seq2[driver.Vulnerability, error]) *advisorySource {
	next, stop := iter.Pull2(vs)
	src := &advisorySource{
		next: next,
		stop: stop,
	}
	return src
}

func (src *advisorySource) Names() []string {
	return advisorySourceNames
}

/*
CREATE TYPE advisory_import_row AS (
	-- id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
	advisory_id BIGINT,
	advisory matcher_v2_import.advisory,
	reference matcher_v2_import.reference[],
	package matcher_v2_import.package[],
	attr matcher_v2_import.attr[]
);
*/

var (
	advisorySourceNames = []string{
		"advisory",
		"reference",
		"package",
		"attr",
	}

	advisorySourceOrd = struct {
		Advisory  int
		Reference int
		Package   int
		Attr      int
	}{
		0, 1, 2, 3,
	}
)

var onlyDigit = regexp.MustCompile(`^\d+$`)

/*
func formatRange(r *driver.Range) (string, error) {
	var b strings.Builder
	char := []byte{0x00, '[', '(', ']', ')'}
	endpt := func(e driver.RangeEndpoint, lower bool) {
		i := e.Bound
		if !lower {
			i += 2
		}
		b.WriteByte(char[i])
	}
	fmtval := func(e driver.RangeEndpoint) error {
		const strdelim = `$v$`
		b.WriteByte('{')
		for _, s := range e.Value {
			if onlyDigit.MatchString(s) {
				i, err := strconv.Atoi(s)
				if err != nil {
					return err
				}
				fmt.Fprintf(&b, "'%010d'", i)
				continue
			} else {
				b.WriteString(strdelim)
				b.WriteString(s)
				b.WriteString(strdelim)
			}
			b.WriteByte(',')
		}
		b.WriteString("NULL}")
		return nil
	}

	endpt(r.Lower, true)
	if err := fmtval(r.Lower); err != nil {
		return "", err
	}
	b.WriteByte(',')
	if err := fmtval(r.Upper); err != nil {
		return "", err
	}
	endpt(r.Upper, false)
	return b.String(), nil
}
*/

func (src *advisorySource) Next() (ok bool) {
	src.v, src.err, ok = src.next()
	return ok && src.err != nil
}

func (src *advisorySource) Values() ([]interface{}, error) {
	ord := advisorySourceOrd
	row := make([]interface{}, len(advisorySourceNames))
	row[ord.Advisory] = make([]interface{}, 10)
	row[ord.Reference] = make([]interface{}, 10)
	row[ord.Package] = make([]interface{}, 10)
	row[ord.Attr] = make([]interface{}, 10)

	row[ord["name"]] = src.v.Name
	row[ord["issued"]] = src.v.Issued
	row[ord["summary"]] = src.v.Summary
	row[ord["description"]] = src.v.Description
	row[ord["uri"]] = src.v.URI
	row[ord["severity"]] = src.v.Severity.Upstream
	row[ord["normalized_severity"]] = src.v.Severity.Normalized.String()
	// now, refs:
	v.Reference(func(r driver.Reference, err error) bool {
		if err != nil {
			src.err = err
			return false
		}
		src.row[ord["ref_namespace"]] = append(src.row[ord["ref_namespace"]].([]string), r.Namespace)
		src.row[ord["ref_name"]] = append(src.row[ord["ref_name"]].([]string), r.Name)
		src.row[ord["ref_uri"]] = append(src.row[ord["ref_uri"]].([][]string), r.URLs)
		return true
	})
	if src.err != nil {
		return false
	}
	// now, packages:
	v.Package(func(p driver.Package, err error) bool {
		if err != nil {
			src.err = err
			return false
		}
		src.row[ord["pkg_name"]] = append(src.row[ord["pkg_name"]].([]string), p.Name)
		src.row[ord["pkg_kind"]] = append(src.row[ord["pkg_kind"]].([]string), p.Kind.String())
		src.row[ord["pkg_arch"]] = append(src.row[ord["pkg_arch"]].([][]string), p.Arch)
		src.row[ord["pkg_version_kind"]] = append(src.row[ord["pkg_version_kind"]].([]string), p.VersionKind)
		src.row[ord["pkg_name"]] = append(src.row[ord["pkg_name"]].([]string), p.Name)
		upst := make([]string, len(p.Version))
		rng := make([]string, len(p.Version))
		for _, v := range p.Version {
			upst = append(upst, v.Upstream)
			s, err := formatRange(&v)
			if err != nil {
				src.err = err
				return false
			}
			rng = append(rng, s)
		}
		src.row[ord["pkg_version_upstream"]] = append(src.row[ord["pkg_version_upstream"]].([][]string), upst)
		src.row[ord["pkg_version_range"]] = append(src.row[ord["pkg_version_range"]].([][]string), rng)
		return true
	})
	if src.err != nil {
		return false
	}
	// now, attrs:
	v.Attr(func(a driver.Attr, err error) bool {
		if err != nil {
			src.err = err
			return false
		}
		src.row[ord["attr_mediatype"]] = append(src.row[ord["attr_mediatype"]].([]string), a.Kind)
		if len(a.Data) == 0 {
			src.row[ord["attr_data"]] = append(src.row[ord["attr_data"]].([][]byte), nil)
		} else {
			src.row[ord["attr_data"]] = append(src.row[ord["attr_data"]].([][]byte), a.Data)
		}
		return true
	})
	if src.err != nil {
		return false
	}

	return row, src.err
}

func (src *advisorySource) Err() error {
	return src.err
}

/*
CREATE TYPE advisory AS (
	name TEXT,
	issued TIMESTAMPTZ,
	summary TEXT,
	description TEXT,
	uri TEXT,
	severity TEXT,
	normalized_severity matcher_v2.Severity

);
*/

type advisory struct {
	Name               string
	Issued             time.Time
	Summary            string
	Description        string
	URI                string
	Severity           string
	NormalizedSeverity string
}

/*
CREATE TYPE reference AS (
	namespace TEXT,
	name TEXT,
	uri TEXT[]
);

CREATE TYPE package AS (
	name TEXT,
	kind matcher_v2.PackageKind,
	arch matcher_v2.Architecture[],
	vulnerable_range matcher_v2.VersionMultiRange,
	version_upstream TEXT[],
	version_kind TEXT,
	purl TEXT,
	cpe TEXT
);

CREATE TYPE attr AS (
	mediatype TEXT,
	data JSONB
);
*/
