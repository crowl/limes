// Package buildinfo reports identifying information injected into release builds.
package buildinfo

import "fmt"

var (
	Version  = "dev"
	Revision = "unknown"
)

// String returns the executable name, version, and source revision.
func String() string {
	return fmt.Sprintf("limes %s (%s)", Version, Revision)
}
