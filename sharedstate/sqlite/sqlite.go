package sqlite

import (
	_ "modernc.org/sqlite"
)

type Config struct {
	URI string
}
