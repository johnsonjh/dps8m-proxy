#!/usr/bin/env sh
###############################################################################
# DPS8M Proxy - .lintsetup.sh
# Copyright (c) 2025-2026 Jeffrey H. Johnson
# Copyright (c) 2025-2026 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0
# scspell-id: 776ab862-930a-11f0-aecf-80ee73e9b8e7
###############################################################################

###############################################################################
# Strict

set -eu

###############################################################################
# Verbose?

if [ -n "${VERBOSE+x}" ]; then
  V="-v=1"
else
  V="-v=0"
fi

###############################################################################
# Latest or master?

if [ "${BRANCH:-}" != "latest" ]; then
  BRANCH="master"
fi

env printf 'Installing "%s" linters' "${BRANCH:?}"

###############################################################################
# Configuration

GO="$(command -v go || printf '%s\n' "go")"
GOTOOLCHAIN="$(grep '^go .*$' go.mod | tr -cd 'go0-9.\n')+auto"
GOSUMDB='sum.golang.org'
TZ=UTC

if [ -z "${GOPROXY+x}" ]; then
  if [ -n "${DIRECT+x}" ]; then
    GOPROXY='direct,proxy.golang.org'
  else
    GOPROXY='proxy.golang.org,direct'
  fi
fi

if [ -z "${GOPATH+x}" ]; then
  GOPATH="${HOME:-}/go"
fi

if [ -z "${GOEXE+x}" ]; then
  GOEXE="${GOPATH:?}/bin"
fi

export GO GOTOOLCHAIN GOSUMDB GOPROXY GOPATH GOEXE TZ

###############################################################################
# Ensure GOEXE directory exists and report

mkdir -p "${GOEXE:?}"
env printf '%s\n' " to '${GOEXE:?}'..."

###############################################################################
# Verbose

set -x

###############################################################################
# Install tag generators (always @master)

case "$(uname -s 2> /dev/null)" in
*CYGWIN*)
  NOT_CYGWIN=0
  ;;
*)
  NOT_CYGWIN=1
  ;;
esac

env CGO_ENABLED="${NOT_CYGWIN:?}" \
  CGO_CFLAGS="-Dpread64=pread -Dpwrite64=pwrite -Doff64_t=off_t" \
  "${GO:?}" install "${V:-}" "github.com/jstemmer/gotags@master" \
  || env CGO_ENABLED=0 "${GO:?}" install "${V:-}" \
    "github.com/jstemmer/gotags@master"

env CGO_ENABLED="${NOT_CYGWIN:?}" \
  CGO_CFLAGS="-Dpread64=pread -Dpwrite64=pwrite -Doff64_t=off_t" \
  "${GO:?}" install "${V:-}" "github.com/juntaki/gogtags@master" \
  || env CGO_ENABLED=0 "${GO:?}" install "${V:-}" \
    "github.com/juntaki/gogtags@master"

###############################################################################
# Install individual linters

"${GO:?}" install "${V:-}" "github.com/boyter/scc/v3@${BRANCH:-}"
"${GO:?}" install "${V:-}" "github.com/kisielk/errcheck@${BRANCH:-}"
"${GO:?}" install "${V:-}" "github.com/mgechev/revive@${BRANCH:-}"
"${GO:?}" install "${V:-}" "golang.org/x/tools/cmd/deadcode@${BRANCH:?}"
"${GO:?}" install "${V:-}" "golang.org/x/vuln/cmd/govulncheck@${BRANCH:-}"
"${GO:?}" install "${V:-}" "honnef.co/go/tools/cmd/staticcheck@${BRANCH:-}"
"${GO:?}" install "${V:-}" "mvdan.cc/gofumpt@${BRANCH:-}"
"${GO:?}" install "${V:-}" "mvdan.cc/sh/v3/cmd/shfmt@${BRANCH:-}"

###############################################################################
# Install gopls (always @latest)

"${GO:?}" install "${V:-}" "golang.org/x/tools/gopls@latest"

###############################################################################
# Install nilaway and golangci-lint

if [ "${BRANCH:-}" = "master" ]; then
  "${GO:?}" install "${V:-}" "go.uber.org/nilaway/cmd/nilaway@main"
  "${GO:?}" install "${V:-}" \
    "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@main"
else
  "${GO:?}" install "${V:-}" "go.uber.org/nilaway/cmd/nilaway@latest"
  # shellcheck disable=SC2312
  curl -fsSL \
    "https://raw.githubusercontent.com/golangci/golangci-lint/HEAD/install.sh" \
    | ${SHELL:-/bin/sh} -s -- -b "$(go env GOPATH)/bin" latest
fi

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
