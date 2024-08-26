package postgres

//go:generate find . -name *sql -exec go run github.com/wasilibs/go-sql-formatter/cmd/sql-formatter@latest --fix --language postgresql {} +
//go:generate go run ./internal/cmd/embed
