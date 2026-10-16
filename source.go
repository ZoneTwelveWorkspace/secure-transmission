// Package projectsource carries the source needed to build personalized clients.
package projectsource

import "embed"

// Files contains only project source and module checksums, never runtime state.
//
//go:embed go.mod go.sum source.go cmd/client/*.go internal/transfer/*.go
var Files embed.FS
