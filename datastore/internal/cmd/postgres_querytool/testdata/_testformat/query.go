package test

import _ "embed"

// All these documentation blocks needed some non-directive lines to get my
// editor to stop messing with them.

const (
	// A
	//
	//i14n:testonly
	a = `a`
	b = `b`
)

// C
//
//i14n:testonly
const c = `c`

var (
	// D
	//
	//i14n:testonly
	d = `d`
	e = `e`
)

// F
//
//i14n:testonly
var f = `f`

// G
//
//i14n:testonly
//go:embed g.txt
var g string

// Format test
//
//i14n:operation SELECT
var wantReformat = /* want "SQL query not formatted" */ `SELECT

version()

;`
