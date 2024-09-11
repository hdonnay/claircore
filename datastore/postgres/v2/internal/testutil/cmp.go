package testutil

import (
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// CmpOpts is default  [cmp.Options].
var CmpOpts = cmp.Options{
	cmpopts.EquateApproxTime(time.Second),
	cmp.Comparer(CmpErrorText),
}

// CmpErrorText compares errors based on their text rather than the value
// contained in the interface.
func CmpErrorText(a, b error) bool {
	switch {
	case a == nil && b == nil:
		return true
	case a == nil && b != nil, a != nil && b == nil:
		return false
	default:
		return a.Error() == b.Error()
	}
}
