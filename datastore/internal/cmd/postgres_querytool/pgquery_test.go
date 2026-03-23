package main

import (
	"testing"

	pg_query "github.com/wasilibs/go-pgquery"
)

func TestPGQuery(t *testing.T) {
	input := `SELECT id FROM "table" WHERE true;`
	tree, err := pg_query.Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	for _, stmt := range tree.Stmts {
		for n := range findNodes(stmt, predOps) {
			t.Log(opName(n), n)
		}
	}
}
