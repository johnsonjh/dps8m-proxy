///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - version.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 4dc282c4-6bd2-11f0-a475-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"unicode/utf8"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var nameReplacements = []struct{ old, new string }{
	{"pub/linux/libs/security", "..."},
	{"github.com/", ""},
	{"gitlab.com/", ""},
}

///////////////////////////////////////////////////////////////////////////////////////////////////

var versionReplacements = []struct{ old, new string }{
	{"v0.3.29-0.20250514124927-a2d8f7790eac", "v0.3.29* (2025-May-14, ga2d8f77)"},
	{"v1.0.11-0.20251007101450-6fcfbc9910e1", "v1.0.11* (2025-Oct-07, g6fcfbc9)"},
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printVersionTable() {
	type row struct{ Name, Version string }
	var rows []row

	info, ok := debug.ReadBuildInfo()
	if ok {
		orig := info.Main.Version
		v := trimVersion(orig, info.Main.Sum)

		if strings.Contains(orig, "+dirty") {
			v += "*"
		}

		rows = append(rows, row{
			Name:    sanitizeName(info.Main.Path),
			Version: sanitizeVersion(v),
		})

		for _, dep := range info.Deps {
			orig := dep.Version
			v := trimVersion(orig, dep.Sum)

			if strings.Contains(orig, "+dirty") {
				v += "*"
			}

			rows = append(rows, row{
				Name:    sanitizeName(dep.Path),
				Version: sanitizeVersion(v),
			})
		}
	}

	raw := runtime.Version()
	hasDirty := strings.Contains(raw, "+dirty")

	compVer := raw

	idx := strings.IndexFunc(raw, func(r rune) bool {
		return r >= '0' && r <= '9'
	})
	if idx >= 0 {
		compVer = "v" + raw[idx:]
	}

	compVer = formatCompilerVersion(compVer)

	if runtime.Compiler == "gc" {
		i := strings.Index(compVer, " ")
		if i != -1 {
			compVer = compVer[:i]
		}
	}

	if hasDirty {
		compVer += "*"
	}

	rows = append(rows, row{
		Name: fmt.Sprintf("Go compiler (%s)",
			runtime.Compiler),
		Version: compVer,
	})

	var componentName string

	componentRuneWidthAdj := 0

	if haveUTF8console {
		componentName = "📦 Component"
		componentRuneWidthAdj = 1
	} else {
		componentName = "Component"
	}

	componentVersion := "Version"

	maxName, maxVer := 0, 0
	for _, r := range rows {
		nameLen := utf8.RuneCountInString(r.Name)
		verLen := utf8.RuneCountInString(r.Version)

		if nameLen > maxName {
			maxName = nameLen
		}

		if verLen > maxVer {
			maxVer = verLen
		}
	}

	nameLen := utf8.RuneCountInString(componentName)
	if nameLen > maxName {
		maxName = nameLen
	}

	verLen := utf8.RuneCountInString(componentVersion)
	if verLen > maxVer {
		maxVer = verLen
	}

	border := fmt.Sprintf("+=%s=+=%s=+\r\n",
		strings.Repeat("=", maxName), strings.Repeat("=", maxVer),
	)

	fmt.Print(border)

	fmt.Printf("| %-*s | %-*s |\r\n",
		maxName-componentRuneWidthAdj, componentName, maxVer, componentVersion)

	fmt.Print(border)

	for _, r := range rows {
		fmt.Printf("| %-*s | %-*s |\r\n",
			maxName, r.Name, maxVer, r.Version)
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

func sanitizeVersion(version string) string {
	for _, rep := range versionReplacements {
		version = strings.ReplaceAll(version, rep.old, rep.new)
	}

	return version
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func trimVersion(version, sum string) string {
	if sum == "" {
		i := strings.Index(version, "-")
		if i != -1 {
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

	return sanitizeVersion(v)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
