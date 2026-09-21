package redhat

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"iter"
	"slices"
	"sync"

	"github.com/package-url/packageurl-go"
	"github.com/quay/claircore/toolkit/types/cpe"
	"github.com/quay/claircore/toolkit/types/csaf"
)

var (
	errMissingRelationship = errors.New("no such product_id (relationship)")
	errMissingRepository   = errors.New("no such product_id (repository)")
	errMissingPackage      = errors.New("no such product_id (package)")
	errMissingScoring      = errors.New("missing scoring or threat information")
)

func statuses(ctx context.Context, doc *csaf.CSAF, v *csaf.Vulnerability) iter.Seq2[string, iter.Seq2[status, error]] {
	relidx := newDefaultComponentIndex()
	prdidx := newProductIndex()
	scoreidx := newScoreIndex()
	threatidx := newThreatImpactIndex()
	remidx := newRemediationIndex()
	relidx.Reset(doc)
	prdidx.Reset(doc)
	scoreidx.Reset(doc)
	threatidx.Reset(doc)
	remidx.Reset(doc)

	return func(yield func(string, iter.Seq2[status, error]) bool) {
		for st, ids := range v.ProductStatus {
			seq := func(yield func(status, error) bool) {
				for _, id := range ids {
					// Step 1: Get the relevant relationship.
					rel := relidx.Get(id)
					if rel == nil {
						// It's possible to get here due to middleware not having a
						// defined component-to-package relationship. RHEL VEX requires
						// products to have relationships.
						err := fmt.Errorf("id %q: %w", id, errMissingRelationship)
						if !yield(status{}, err) {
							return
						}
						continue
					}

					// Step 2: Resolve the relationship to a "package" and
					// "repository" (left- and right-most children, respectively).
					const relMax = 5
					var relDepth int
					var pkgID, repoID string
					for pkgID, relDepth = rel.ProductRef, 0; relDepth < relMax; relDepth++ {
						r := relidx.Get(pkgID)
						if r == nil {
							break
						}
						pkgID = r.ProductRef
					}
					for repoID, relDepth = rel.RelatesToProductRef, 0; relDepth < relMax; relDepth++ {
						r := relidx.Get(repoID)
						if r == nil {
							break
						}
						repoID = r.RelatesToProductRef
					}
					pkg := prdidx.Get(pkgID)
					if pkg == nil {
						err := fmt.Errorf("id %q: %w", id, errMissingPackage)
						if !yield(status{}, err) {
							return
						}
						continue
					}
					repo := prdidx.Get(repoID)
					if repo == nil {
						err := fmt.Errorf("id %q: %w", id, errMissingRepository)
						if !yield(status{}, err) {
							return
						}
						continue
					}

					// Step 3: Turn the "package" and "repository" objects into
					// a purl and a CPE Name.
					var purl *packageurl.PackageURL
					var wfn *cpe.WFN
					if s, ok := repo.IdentificationHelper["cpe"]; ok {
						v, err := cpe.Unbind(s)
						if err != nil {
							if !yield(status{}, err) {
								return
							}
							continue
						}
						wfn = &v
					}
					if s, ok := pkg.IdentificationHelper["purl"]; ok {
						v, err := packageurl.FromString(s)
						if err != nil {
							if !yield(status{}, err) {
								return
							}
							continue
						}
						// TODO(hank) check purl
						purl = &v
					}

					// Step 4: Extract the other, optional data.
					score := scoreidx.Get(id)
					threat := threatidx.Get(id)
					if threat == nil && score != nil && cvssBaseScoreFromScore(score) == 0.0 {
						// This has no threat object and 0 score: disregard.
						err := fmt.Errorf("id %q: %w", id, errMissingScoring)
						if !yield(status{}, err) {
							return
						}
						continue
					}
					remediation := remidx.Get(id)

					// Step 5: Do fixups for specific statuses.
					switch st {
					case csaf.ProductStatusKnownNotAffected:
						purl.Version = ""
						purl.Qualifiers = slices.DeleteFunc(purl.Qualifiers, func(q packageurl.Qualifier) bool {
							return q.Key == "epoch" || q.Key == "tag"
						})
					}
					st := status{
						ID:           id,
						PackageID:    pkgID,
						RepositoryID: repoID,
						PURL:         purl,
						WFN:          wfn,
						Score:        score,
						Threat:       threat,
						Remediation:  remediation,
					}
					if !yield(st, nil) {
						return
					}
				}
			}

			if !yield(st, seq) {
				return
			}
		}
	}
}

// Status is an individual "product status" that's well-formed according to Red
// Hat's guidelines.
//
// [Score], [Threat], and [Remediation] may be nil, but [PURL] and [WFN] will
// not be.
type status struct {
	ID           string
	PackageID    string
	RepositoryID string
	PURL         *packageurl.PackageURL
	WFN          *cpe.WFN
	Score        *csaf.Score
	Threat       *csaf.ThreatData
	Remediation  *csaf.RemediationData
}

// Key returns a local-process-only unique integer.
func (s *status) Key() uint64 {
	h := getHasher()
	defer putHasher(h)

	// The purl is normalized when constructed, so this should all be stable:
	h.WriteString(s.PURL.Type)
	h.WriteString(s.PURL.Name)
	h.WriteString(s.PURL.Namespace)
	h.WriteString(s.PURL.Subpath)
	// Type specific shenanigans around the Version:
	switch s.PURL.Type {
	case packageurl.TypeOCI: // Skip
	default:
		h.WriteString(s.PURL.Version)
	}
	for _, q := range s.PURL.Qualifiers {
		switch q.Key {
		case "arch":
			continue
		default:
		}
		h.WriteString(q.Key)
		h.WriteString(q.Value)
	}

	// A little ad-hoc hashing scheme for the WFN.
	for _, a := range s.WFN.Attr {
		switch a.Kind {
		case cpe.ValueUnset:
			h.WriteByte(0x00)
		case cpe.ValueNA:
			h.WriteByte(0x01)
		case cpe.ValueAny:
			h.WriteByte(0x02)
		case cpe.ValueSet:
			h.WriteByte(0xFF)
			h.WriteString(a.V)
		}
	}

	return h.Sum64()
}

var (
	seed     = maphash.MakeSeed()
	hashPool = sync.Pool{}
)

func getHasher() *maphash.Hash {
	v := hashPool.Get()
	if v == nil {
		h := new(maphash.Hash)
		h.SetSeed(seed)
		return h
	}
	return v.(*maphash.Hash)
}

func putHasher(h *maphash.Hash) {
	h.Reset()
	hashPool.Put(h)
}
