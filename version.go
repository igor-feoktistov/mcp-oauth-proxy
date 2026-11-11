// Package mcpoauthproxy exposes the build metadata shared by the command, the
// container image and the Helm chart.
package mcpoauthproxy

import (
	_ "embed"
	"strings"
)

// versionFile is the VERSION file at the repository root, which is the single
// source of truth for the release version. Embedding it means a binary built
// with a plain `go build` or `go run` reports the same version as the released
// image, instead of a placeholder that only the Makefile and Dockerfile know
// how to replace.
//
// go:embed cannot reach outside its own package directory, which is why this
// file sits at the root next to VERSION rather than under internal/.
//
//go:embed VERSION
var versionFile string

// Version returns the release version recorded in the VERSION file.
func Version() string { return strings.TrimSpace(versionFile) }
