///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - version_test.go
// Copyright (c) 2025-2026 Jeffrey H. Johnson
// Copyright (c) 2025-2026 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: a2f33500-3b42-11f1-b5ba-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"runtime/debug"
	"testing"

	"go.uber.org/goleak"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestGetMainModuleVersion(t *testing.T) { //nolint:paralleltest,tparallel,nolintlint
	if enableGops {
		gopsClose()
	}

	defer goleak.VerifyNone(t)

	originalVersionText := versionText
	originalReadBuildInfo := readBuildInfo

	defer func() {
		versionText = originalVersionText
		readBuildInfo = originalReadBuildInfo
	}()

	t.Run("Priority of versionText", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = "v9.9.9\n"
			got := getMainModuleVersion()

			want := "v9.9.9"
			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	t.Run("Dev version", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = "v1.1.8-0.20260424221546-c497c3506794"
			got := getMainModuleVersion()

			want := "v1.1.8-dev"
			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	t.Run("Dirty dev version", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = "v1.1.8-0.20260424221546-c497c3506794+dirty"
			got := getMainModuleVersion()

			want := "v1.1.8*-dev"
			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	const prettyVersion = "v1.1.9 (2026-Apr-27 g443ff0e)"

	t.Run("Pretty version", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = prettyVersion
			got := getMainModuleVersion()

			want := prettyVersion
			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	const v119 = "v1.1.9"

	t.Run("Fallback to BuildInfo (No VCS)", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = ""
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main: debug.Module{
						Version: v119,
					},
				}, true
			}

			got := getMainModuleVersion()
			want := v119

			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	t.Run("Fallback to BuildInfo (With VCS)", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = ""
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main: debug.Module{
						Version: v119,
					},
					Settings: []debug.BuildSetting{
						{
							Key:   "vcs.revision",
							Value: "1234567890abcdef1234567890abcdef12345678",
						},
						{
							Key:   "vcs.time",
							Value: "2026-04-27T12:00:00Z",
						},
					},
				}, true
			}

			got := getMainModuleVersion()

			want := v119

			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	const devel = "(devel)"

	t.Run("BuildInfo (Devel)", //nolint:paralleltest,nolintlint
		func(t *testing.T) {
			versionText = ""
			readBuildInfo = func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{
					Main: debug.Module{
						Version: devel,
					},
				}, true
			}

			got := getMainModuleVersion()
			want := devel

			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestPrintVersion_Mocked(_ *testing.T) { //nolint:paralleltest,nolintlint
	originalVersionText := versionText
	originalReadBuildInfo := readBuildInfo
	originalShowVersion := showVersion

	defer func() {
		versionText = originalVersionText
		readBuildInfo = originalReadBuildInfo
		showVersion = originalShowVersion
	}()

	showVersion = false

	const prettyVersion = "v1.1.9 (2026-Apr-27 g443ff0e)"

	versionText = prettyVersion
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{
				Version: "v1.1.9",
			},
			Settings: []debug.BuildSetting{
				{
					Key:   "vcs.revision",
					Value: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
				},
				{
					Key:   "vcs.time",
					Value: "2026-01-01T00:00:00Z",
				},
			},
		}, true
	}

	printVersion(true)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
