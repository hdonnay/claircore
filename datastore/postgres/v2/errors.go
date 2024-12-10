package postgres

import (
	"errors"
	"fmt"
)

// ErrPre is a prefix for error strings.
const errPre = `postgres/v2: `

// Errorf wraps [fmt.Errorf] and ensures a common prefix.
func errorf(format string, v ...any) error {
	return fmt.Errorf(errPre+format, v...)
}

// PrefixedErr returns a function wrapping [fmt.Errorf] and ensures both the
// common package-level and provided prefixes are used.
func prefixedErr(pre string) func(string, ...any) error {
	p := errPre + pre + `: `
	return func(format string, v ...any) error {
		return fmt.Errorf(p+format, v...)
	}
}

var (
	ErrDatabaseAppConfig = errors.New("database-stored application configuration is in a bad state")

	ErrNoHistory error = (*historyError)(nil)
)

type historyError struct{}

func (*historyError) Error() string {
	return errPre + `system not configured to retain update history`
}

func (*historyError) Is(tgt error) bool {
	_, same := tgt.(*historyError)
	return same || tgt == errors.ErrUnsupported
}
