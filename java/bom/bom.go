// Package bom implements consuming Red Hat's java-flavored BOMs.
package bom

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"iter"
	"slices"
	"strings"
	"unique"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore/toolkit/types/cpe"
)

func Load(ctx context.Context, r io.ReaderAt) (iter.Seq2[Package, error], error) {
	var doc cyclonedx.BOM
	dec := cyclonedx.NewBOMDecoder(io.NewSectionReader(r, 0, -1), cyclonedx.BOMFileFormatJSON)
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	root := doc.Metadata.Component
	if root == nil {
		return nil, errors.New("no root component")
	}
	if doc.Components == nil || len(*doc.Components) == 0 {
		return nil, errors.New("no components")
	}
	if doc.Dependencies == nil || len(*doc.Dependencies) == 0 {
		return nil, errors.New("no dependencies")
	}
	wfn, err := cpe.Unbind(root.CPE)
	if err != nil {
		return nil, fmt.Errorf("root component %q: %w", root.BOMRef, err)
	}
	cmps := *doc.Components
	deps := *doc.Dependencies

	seq := func(yield func(Package, error) bool) {
		c := make(map[string]*cyclonedx.Component, len(cmps))
		for i := range cmps {
			r := &cmps[i]
			c[r.BOMRef] = r
		}
		depidx := slices.IndexFunc(deps, func(d cyclonedx.Dependency) bool {
			return d.Ref == root.BOMRef
		})
		if depidx == -1 {
			err := fmt.Errorf("missing dependencies of root component %q", root.BOMRef)
			yield(Package{}, err)
			return
		}
		dep := &deps[depidx]
	YieldPackages:
		for _, ref := range *dep.Dependencies {
			if strings.HasPrefix(ref, `pkg:generic/`) {
				continue
			}
			cm := c[ref]
			purl, err := packageurl.FromString(cm.PackageURL)
			if err != nil {
				if !yield(Package{}, err) {
					return
				}
				continue
			}
			var hashes map[unique.Handle[string]][]byte
			if cm.Hashes != nil {
				hs := *cm.Hashes
				hashes = make(map[unique.Handle[string]][]byte, len(hs))
				for _, h := range hs {
					k, known := hashnames[h.Algorithm]
					if !known {
						continue
					}
					// Assume everything is encoded as hex:
					v, err := hex.DecodeString(h.Value)
					if err != nil {
						if !yield(Package{}, err) {
							return
						}
						continue YieldPackages
					}
					hashes[k] = v
				}
			}
			var loc string
			if ev := cm.Evidence; ev != nil {
				if ocs := ev.Occurrences; ocs != nil {
				Occurrence:
					for _, oc := range *ocs {
						if oc.Location != "" {
							loc = oc.Location
							break Occurrence
						}
					}
				}
			}

			pkg := Package{
				CPE:      &wfn,
				PURL:     purl,
				Hashes:   hashes,
				Location: loc,
			}
			if !yield(pkg, nil) {
				return
			}
		}
	}

	return seq, nil
}

var hashnames = map[cyclonedx.HashAlgorithm]unique.Handle[string]{
	cyclonedx.HashAlgoSHA256: HashSHA256,
	cyclonedx.HashAlgoSHA1:   HashSHA1,
}

type Package struct {
	CPE      *cpe.WFN
	PURL     packageurl.PackageURL
	Hashes   map[unique.Handle[string]][]byte
	Location string
}

var (
	HashSHA1   = unique.Make(`sha1`)
	HashSHA256 = unique.Make(`sha256`)
)
