#!/bin/sh
##############################################################################
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0

###############################################################################
# Strict

set -e

###############################################################################
# Cleanup

rm -rf ./cross.bin
mkdir -p ./cross.bin

###############################################################################
# Disable CGO

CGO_ENABLED=0
GOTOOLCHAIN=auto
export CGO_ENABLED GOTOOLCHAIN

###############################################################################
# Create script
# Exclude ios/*, android/{386,amd64,arm}

# shellcheck disable=SC2016
_S=$(go tool dist list \
  | grep -Ev '^js/wasm$|^wasip1/wasm$|^ios/|^android/(386|amd64|arm)$' \
  | awk 'BEGIN { FS="/" } /\// { print "GOOS="$1" GOARCH="$2 }' \
  | xargs -I{} printf '%s\n' '
      export {} && printf "🧩 %s/%s\n" "${GOOS:?}" "${GOARCH:?}" &&
      go build -trimpath -o ./cross.bin/proxy."${GOOS:?}"."${GOARCH:?}";')

###############################################################################
# Disable strict

set +e

###############################################################################
# Run script

eval "${_S}"

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
