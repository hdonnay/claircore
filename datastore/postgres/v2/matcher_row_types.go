package postgres

import (
	"github.com/jackc/pgx/v5/pgtype"
)

var _ pgtype.CompositeIndexGetter = removeWrapper("")

type removeWrapper string

// Index implements [pgtype.CompositeIndexGetter].
func (r removeWrapper) Index(i int) any {
	switch i {
	case 0:
		return (*string)(&r)
	case 1:
		return nil
	case 2:
		return nil
	case 3:
		return nil
	case 4:
		return nil
	case 5:
		return nil
	case 6:
		return nil
	default:
		panic("bad index")
	}
}

// IsNull implements [pgtype.CompositeIndexGetter].
func (r removeWrapper) IsNull() bool { return r == "" }
