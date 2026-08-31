// Package version carries the build identity, stamped by the Makefile.
package version

import "runtime/debug"

// Version is set at build time with -ldflags. It falls back to the module
// version recorded by the go tool, so a `go install` build still identifies
// itself.
var Version = ""

// Commit is the git revision, set at build time.
var Commit = ""

// String is the one-line version banner.
func String() string {
	v := Version
	if v == "" {
		v = moduleVersion()
	}
	if Commit != "" {
		return v + " (" + Commit + ")"
	}
	return v
}

func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" {
		return "dev"
	}
	return info.Main.Version
}
