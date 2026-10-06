// Package version carries the FoxyVPN release metadata stamped into every
// binary at build time (see scripts/build-windows.ps1).
package version

import (
	"fmt"
	"runtime"
)

// Values overridden via -ldflags "-X firefox-vpn-client/internal/version.GitCommit=...".
var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildDate = "unknown"
)

// String returns a single-line banner used by CLI, service and UI About pages.
func String() string {
	return fmt.Sprintf("FoxyVPN %s (%s, built %s, %s/%s)",
		Version, GitCommit, BuildDate, runtime.GOOS, runtime.GOARCH)
}

// Short returns just the semantic version.
func Short() string { return Version }
