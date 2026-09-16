module github.com/quay/claircore/updater/driver

go 1.26.0

require (
	github.com/google/uuid v1.6.0
	github.com/package-url/packageurl-go v0.1.7
	github.com/quay/claircore/toolkit v1.7.0
)

require (
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

replace github.com/quay/claircore/toolkit => ../../toolkit

tool golang.org/x/tools/cmd/stringer
