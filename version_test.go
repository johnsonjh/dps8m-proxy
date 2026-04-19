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
	"strings"
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

	defer func() {
		versionText = originalVersionText
	}()

	t.Run("Priority of versionText",
		func(t *testing.T) {
			t.Parallel()

			versionText = "v9.9.9\n"
			got := getMainModuleVersion()

			want := "v9.9.9"
			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)

	t.Run("Fallback to BuildInfo",
		func(t *testing.T) {
			t.Parallel()

			versionText = ""
			got := getMainModuleVersion()

			info, ok := debug.ReadBuildInfo()
			if !ok {
				t.Skip("Build info not available")
			}

			want := sanitizeVersion(trimVersion(info.Main.Version, info.Main.Sum))
			if strings.Contains(info.Main.Version, "+dirty") {
				want += "*"
			}

			if got != want {
				t.Errorf("getMainModuleVersion() = %q, want %q",
					got, want)
			}
		},
	)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
