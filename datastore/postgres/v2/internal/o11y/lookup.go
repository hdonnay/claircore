package o11y

import (
	"unique"
	_ "unsafe" // needed for linkname tricks
)

// NameLookup is literally the same as [github.com/quay/claircore/datastore/postgres/v2.NameLookup].
//
// This uses linker tricks to avoid an import cycle.
//
//go:linkname nameLookup github.com/quay/claircore/datastore/postgres/v2.NameLookup
var nameLookup map[unique.Handle[string]]string
