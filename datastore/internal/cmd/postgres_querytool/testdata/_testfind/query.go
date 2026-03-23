// Package test is for testing the querytool.
package test

import _ "embed"

// All these documentation blocks needed some non-directive lines to get my
// editor to stop messing with them.

const (
	// A
	//
	//i14n:testonly
	a = `SELECT
  NULL;`
	b = `notsql`
)

// C
//
//i14n:testonly
const c = `SELECT
  NULL;`

var (
	// D
	//
	//i14n:testonly
	d = `SELECT
  NULL;`
	e = `notsql`
)

// F
//
//i14n:testonly
var f = `SELECT
  NULL;`

// G
//
//i14n:testonly
//go:embed g.txt
var g string

// Exercise annotations
//
//i14n:operation SELECT
var getVersion = `SELECT
  version();`

func init() {
	_ = a
	_ = b
	_ = c
	_ = d
	_ = e
	_ = f
	_ = g
	_ = getVersion
}
