///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - version.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

// Version reporting

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var nameReplacements = []struct{ old, new string }{
	{"pub/linux/libs/security", "..."},
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printVersionTable() {
	type row struct{ Name, Version string }
	var rows []row

	if info, ok := debug.ReadBuildInfo(); ok {
		orig := info.Main.Version
		v := trimVersion(orig, info.Main.Sum)

		if strings.Contains(orig, "+dirty") {
			v += "*"
		}

		rows = append(rows, row{
			Name:    sanitizeName(stripHost(info.Main.Path)),
			Version: v,
		})

		for _, dep := range info.Deps {
			orig := dep.Version
			v := trimVersion(orig, dep.Sum)

			if strings.Contains(orig, "+dirty") {
				v += "*"
			}

			rows = append(rows, row{
				Name:    sanitizeName(stripHost(dep.Path)),
				Version: v,
			})
		}
	}

	raw := runtime.Version()
	hasDirty := strings.Contains(raw, "+dirty")

	compVer := raw
	if idx := strings.IndexFunc(raw, func(r rune) bool {
		return r >= '0' && r <= '9'
	}); idx >= 0 {
		compVer = "v" + raw[idx:]
	}

	compVer = formatCompilerVersion(compVer)
	if runtime.Compiler == "gc" {
		if i := strings.Index(compVer, " "); i != -1 {
			compVer = compVer[:i]
		}
	}

	if hasDirty {
		compVer += "*"
	}

	rows = append(rows, row{
		Name:    fmt.Sprintf("Go compiler (%s)", runtime.Compiler),
		Version: compVer,
	})

	maxName, maxVer := 0, 0
	for _, r := range rows {
		if len(r.Name) > maxName {
			maxName = len(r.Name)
		}

		if len(r.Version) > maxVer {
			maxVer = len(r.Version)
		}
	}

	border := fmt.Sprintf(
		"+=%s=+=%s=+\n", strings.Repeat("=", maxName), strings.Repeat("=", maxVer),
	)

	fmt.Print(border)
	fmt.Printf("| %-*s | %-*s |\n", maxName, "Component", maxVer, "Version")
	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("| %-*s | %-*s |\n", maxName, r.Name, maxVer, r.Version)
	}

	fmt.Print(border)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func sanitizeName(name string) string {
	for _, rep := range nameReplacements {
		name = strings.ReplaceAll(name, rep.old, rep.new)
	}

	return name
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func stripHost(path string) string {
	for _, h := range []string{"github.com/", "gitlab.com/"} {
		if strings.HasPrefix(path, h) {
			return strings.TrimPrefix(path, h)
		}
	}

	return path
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func trimVersion(version, sum string) string {
	if sum == "" {
		if i := strings.Index(version, "-"); i != -1 {
			return version[:i]
		}
	}

	return version
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func formatCompilerVersion(ver string) string {
	ver = strings.ReplaceAll(ver, " gccgo ", " ")
	ver = strings.ReplaceAll(ver, " (GCC) ", ", GCC v")
	count := 0

	for i, r := range ver {
		if r == ' ' {
			count++

			if count == 3 {
				return ver[:i]
			}
		}
	}

	return ver
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getMainModuleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}

	orig := info.Main.Version
	v := trimVersion(orig, info.Main.Sum)

	if strings.Contains(orig, "+dirty") {
		v += "*"
	}

	return v
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
