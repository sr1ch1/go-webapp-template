// Package version exposes build metadata stamped at link time.
//
// Version, Commit, and BuildTime are set by the linker via -ldflags when the
// binary is built by scripts/build.py or the Dockerfile.
package version

// Build metadata. These variables are overwritten at link time.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = ""
)

// Info returns the build metadata as a map.
func Info() map[string]string {
	return map[string]string{
		"version":    Version,
		"commit":     Commit,
		"build_time": BuildTime,
	}
}
