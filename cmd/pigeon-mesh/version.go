//go:build linux

package main

import (
	"fmt"
	"runtime/debug"
)

// set via -ldflags -X main.version; plain go build falls back to the embedded VCS revision.
var version = "dev"

func runVersion([]string) int {
	fmt.Println(versionString())
	return 0
}

func versionString() string {
	if version != "dev" {
		return "pigeon-mesh " + version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, dirty string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if rev != "" {
			return "pigeon-mesh dev (" + rev + dirty + ")"
		}
	}
	return "pigeon-mesh dev"
}
