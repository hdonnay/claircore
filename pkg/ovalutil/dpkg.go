package ovalutil

import (
	"context"
	"errors"
	"fmt"

	"github.com/quay/goval-parser/oval"
	"github.com/rs/zerolog"

	"github.com/quay/claircore"
)

// DpkgDefsToVulns iterates over the definitions in an oval root and assumes DpkgInfo objects and states.
//
// Each Criterion encountered with an EVR string will be translated into a claircore.Vulnerability
func DpkgDefsToVulns(ctx context.Context, root *oval.Root, protoVulns ProtoVulnsFunc) ([]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "ovalutil/DpkgDefsToVulns").
		Logger()
	ctx = log.WithContext(ctx)
	vulns := make([]*claircore.Vulnerability, 0, 10000)
	pkgcache := map[string]*claircore.Package{}
	cris := []*oval.Criterion{}
	for _, def := range root.Definitions.Definitions {
		// create our prototype vulnerability
		protoVulns, err := protoVulns(def)
		if err != nil {
			log.Debug().
				Err(err).
				Str("def_id", def.ID).
				Msg("could not create prototype vulnerabilities")
			continue
		}
		// recursively collect criterions for this definition
		cris := cris[:0]
		walkCriterion(ctx, &def.Criteria, &cris)
		// unpack criterions into vulnerabilities
		for _, criterion := range cris {
			var noVersion bool
			// lookup test
			test, err := TestLookup(root, criterion.TestRef, nil)
			if err != nil {
				log.Debug().
					Err(err).
					Str("test_ref", criterion.TestRef).
					Msg("test ref lookup failure. moving to next criterion")
				continue
			}
			objRefs := test.ObjectRef()
			stateRefs := test.StateRef()
			switch {
			case len(cris) == 1:
				// If this is the only criterion it probably means
				// that this definition is just "package installed".
				noVersion = true
			case len(objRefs) == 1 && len(stateRefs) == 0:
				// We always take an object reference to imply the existence of
				// that object, so just skip tests with a single object reference
				// and no associated state object.
				continue
			case len(objRefs) != len(stateRefs):
				log.Debug().Str("test_ref", criterion.TestRef).Msg("object refs and state refs are not in pairs. moving to next criterion")
				continue
			}
			// look at each object,state pair the test references
			// and create a vuln if an evr tag is found
			for i := 0; i < len(objRefs); i++ {
				objRef := objRefs[i].ObjectRef
				object, err := dpkgObjectLookup(root, objRef)
				switch {
				case errors.Is(err, nil):
				case errors.Is(err, errObjectSkip):
					// We only handle dpkginfo_objects.
					continue
				default:
					if err != nil {
						log.Debug().
							Err(err).
							Str("object_ref", objRef).
							Msg("failed object lookup. moving to next object,state pair")
						continue
					}
				}

				// NB This may not be populated for the rest of the loop. The
				// noVersion bool controls whether that's OK or not.
				var state *oval.DpkgInfoState
				if i < len(stateRefs) { // Index check needed because we may have gotten here with noVersion set.
					stateRef := stateRefs[i].StateRef
					state, err = dpkgStateLookup(root, stateRef)
					if !noVersion && err != nil {
						log.Debug().
							Err(err).
							Str("state_ref", stateRef).
							Msg("failed state lookup. moving to next object,state pair")
						continue
					}
				}
				// if EVR tag not present this is not a linux package
				// see oval definitions for more details
				if state != nil && state.EVR == nil {
					continue
				}

				for _, protoVuln := range protoVulns {
					name := object.Name

					// if the dpkginfo_object>name field has a var_ref it indicates
					// a variable lookup for all packages affected by this vuln is necessary.
					//
					// if the name.Ref field is empty it indicates a single package is affected
					// by the vuln and that package's name is in name.Body.
					var ns []string
					if len(name.Ref) > 0 {
						_, i, err := root.Variables.Lookup(name.Ref)
						if err != nil {
							log.Error().Err(err).Msg("could not lookup variable id")
							continue
						}
						consts := root.Variables.ConstantVariables[i]
						for _, v := range consts.Values {
							ns = append(ns, v.Body)
						}
					} else {
						ns = append(ns, name.Body)
					}
					for _, n := range ns {
						vuln := *protoVuln
						if state != nil {
							vuln.FixedInVersion = state.EVR.Body
							if state.Arch != nil {
								vuln.ArchOperation = mapArchOp(state.Arch.Operation)
								vuln.Package.Arch = state.Arch.Body
							}
						}
						if pkg, ok := pkgcache[n]; !ok {
							p := &claircore.Package{
								Name: n,
								Kind: claircore.BINARY,
							}
							pkgcache[n] = p
							vuln.Package = p
						} else {
							vuln.Package = pkg
						}
						vulns = append(vulns, &vuln)
					}
				}
			}
		}
	}
	return vulns, nil
}

func dpkgStateLookup(root *oval.Root, ref string) (*oval.DpkgInfoState, error) {
	kind, i, err := root.States.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "dpkginfo_state" {
		return nil, fmt.Errorf("oval: got kind %q: %w", kind, errStateSkip)
	}
	return &root.States.DpkgInfoStates[i], nil
}

func dpkgObjectLookup(root *oval.Root, ref string) (*oval.DpkgInfoObject, error) {
	kind, i, err := root.Objects.Lookup(ref)
	if err != nil {
		return nil, err
	}
	if kind != "dpkginfo_object" {
		return nil, fmt.Errorf("oval: got kind %q: %w", kind, errObjectSkip)
	}
	return &root.Objects.DpkgInfoObjects[i], nil
}
