#!/usr/bin/env sh
###############################################################################
# DPS8M Proxy - .lintsetup.sh
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0
# scspell-id: 776ab862-930a-11f0-aecf-80ee73e9b8e7
###############################################################################

###############################################################################
# Strict

set -eu

###############################################################################
# Latest or master?

if [ "${BRANCH:-}" = "latest" ]; then
  printf '%s' 'Installing "latest" linters'
else
  BRANCH="master"
  printf '%s' 'Installing "master" linters'
fi

###############################################################################
# Configuration

GO="$(command -v go || printf '%s\n' "go")"
GOTOOLCHAIN="$(grep '^go .*$' go.mod | tr -cd 'go0-9.\n')+auto"
GOSUMDB='sum.golang.org'
GOPROXY='proxy.golang.org,direct'
GOPATH="${HOME:-}/go"
GOEXE="${GOPATH:?}/bin"
TZ=UTC

export GO GOTOOLCHAIN GOSUMDB GOPROXY GOPATH GOEXE TZ

###############################################################################
# Ensure GOEXE directory exists and report

mkdir -p "${GOEXE:?}"
printf '%s\n' " to '${GOEXE:?}'..."

###############################################################################
# Verbose

set -x

###############################################################################
# Install individual linters

${GO:?} install -v "github.com/boyter/scc/v3@${BRANCH:-}"
${GO:?} install -v "github.com/kisielk/errcheck@${BRANCH:-}"
${GO:?} install -v "github.com/mgechev/revive@${BRANCH:-}"
${GO:?} install -v "golang.org/x/vuln/cmd/govulncheck@${BRANCH:-}"
${GO:?} install -v "honnef.co/go/tools/cmd/staticcheck@${BRANCH:-}"
${GO:?} install -v "mvdan.cc/gofumpt@${BRANCH:-}"
${GO:?} install -v "mvdan.cc/sh/v3/cmd/shfmt@${BRANCH:-}"

###############################################################################
# Install gopls (always @latest)

${GO:?} install -v "golang.org/x/tools/gopls@latest"

###############################################################################
# Install golangci-lint

if [ "${BRANCH:-}" = "master" ]; then
  go install -v "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@main"
else
  # shellcheck disable=SC2312
  curl -fsSL \
    "https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh" \
    | ${SHELL:-/bin/sh} -s -- -b "$(go env GOPATH)/bin" latest
fi

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
