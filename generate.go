package claircore

//go:generate -command stringer go tool stringer
//go:generate stringer -type=ArchOp -linecomment
//go:generate stringer -type=Severity

// Using "go run" instead of "go tool" is explicitly suggested by the buf docs.
// It should avoid dependency conflicts for buf, which would only exist at
// generate-time.
//go:generate -command buf go run github.com/bufbuild/buf/cmd/buf@v1.72.0

//go:generate buf format --write
//go:generate buf lint
////go:generate buf breaking --exclude-imports --against proto/image.json
//go:generate buf build --exclude-source-info --exclude-source-retention-options --output proto/image.json
//go:generate buf generate
