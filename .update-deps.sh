#!/usr/bin/env sh
###############################################################################
# DPS8M Proxy - .update-deps.sh
# Copyright (c) 2025-2026 Jeffrey H. Johnson
# Copyright (c) 2025-2026 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0
# scspell-id: 3a9014e8-9335-11f0-85bd-80ee73e9b8e7
###############################################################################

###############################################################################
# Strict

set -eu

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

export GO GOTOOLCHAIN GOSUMDB GOPROXY TZ

###############################################################################
# Verbose

set -x

###############################################################################
# Update deps

${GO:?} get -u github.com/google/gops@master
${GO:?} mod tidy

${GO:?} get -u github.com/arl/statsviz@latest
${GO:?} mod tidy

${GO:?} get -u github.com/hashicorp/mdns@latest
${GO:?} mod tidy

${GO:?} get -u github.com/klauspost/compress@latest
${GO:?} mod tidy

${GO:?} get -u github.com/sorairolake/lzip-go@latest
${GO:?} mod tidy

${GO:?} get -u github.com/spf13/pflag@master
${GO:?} mod tidy

${GO:?} get -u github.com/ulikunitz/xz@latest
${GO:?} mod tidy

${GO:?} get -u go.etcd.io/bbolt@latest
${GO:?} mod tidy

${GO:?} get -u go.uber.org/goleak@master
${GO:?} mod tidy

${GO:?} get -u golang.org/x/crypto@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/term@latest
${GO:?} mod tidy

${GO:?} get -u kernel.org/pub/linux/libs/security/libcap/cap@latest
${GO:?} mod tidy

${GO:?} get -u kernel.org/pub/linux/libs/security/libcap/psx@latest
${GO:?} mod tidy

${GO:?} get -u github.com/gorilla/websocket@latest
${GO:?} mod tidy

${GO:?} get -u github.com/miekg/dns@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/mod@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/net@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/sync@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/sys@latest
${GO:?} mod tidy

${GO:?} get -u golang.org/x/tools@latest
${GO:?} mod tidy

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
