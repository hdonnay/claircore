package postgres

//go:generate bash -ec "command -v pg_format >/dev/null; find query -name '*.sql' | xargs pg_format -i -u 2 -U 2 -f 1 -L -T"
//go:generate go run ./internal/cmd/embed
