package driver

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/url"
	"time"

	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/toolkit/types/cpe"
)

// AdvisoryName is just an identifier for an advisory.
type AdvisoryName struct {
	Name string
}

// Advisory is all per-vulnerability or advisory information.
//
// This is similar to the [claircore.Vulnerability] in previous Updater
// interfaces.
type Advisory struct {
	Refs     func(context.Context) (iter.Seq2[Reference, error], error)
	Packages func(context.Context) (iter.Seq2[Package, error], error)
	Attrs    func(context.Context) (iter.Seq2[Attr, error], error)

	Issued time.Time
	AdvisoryName
	Summary     string
	Description string
	URI         string
	Severity    Severity
}

// Severity is severity information.
type Severity struct {
	// Upstream should be the value the upstream database provides.
	Upstream string
	// Normalized should be one of the proscribed Severity values.
	// They roughly correlate to CVSSv3 severity levels.
	Normalized types.Severity
}

// Package describes a package.
//
// A Package is a specialized form of [Attr].
type Package struct {
	PURL    *url.URL
	CPE     *cpe.WFN
	Name    string
	Version Versions
	Arch    []Architecture
	Kind    types.PackageKind
}

// TODO(hank) See if any of these should be lifted into toolkit/types.

type Reference struct {
	Namespace string
	Name      string
	URI       []string
}

func (r *Reference) String() string {
	return fmt.Sprintf("%s-%s%v", r.Namespace, r.Name, r.URI)
}

type Architecture int

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type Architecture -linecomment

const (
	ArchAny      Architecture = iota // any
	Arch386                          // 386
	ArchAMD64                        // amd64
	ArchArm                          // arm
	ArchArm64                        // arm64
	ArchMips                         // mips
	ArchMipsLE                       // mipsle
	ArchMips64                       // mips64
	ArchMips64LE                     // mips64le
	ArchPPC64                        // ppc64
	ArchPPC64LE                      // ppc64le
	ArchRiscV64                      // riscv64
	ArchS390X                        // s390x
)

type Versions struct {
	Kind     string
	Upstream []string
	Ranges   []VersionRange
}

type VersionRange struct {
	Lower, Upper VersionEndpoint
}

type VersionEndpoint struct {
	Components []string
	Inclusive  bool
}

type Attr struct {
	Kind  string
	Value json.RawMessage
}
