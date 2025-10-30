#!/bin/sh
###############################################################################
# DPS8M Proxy - .cross-android.sh
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0
# scspell-id: de55e65e-b5e3-11f0-9604-80ee73e9b8e7
###############################################################################

# Cross-compile android/arm/386/amd64 binaries using the Android NDK.

###############################################################################
# Strict

set -e

###############################################################################
# Cleanup

mkdir -p ./cross.bin

###############################################################################
# Setup Go

GO="$(command -v go 2> /dev/null || printf '%s\n' 'go')"
GOFLAGS="-ldflags=-s -w"
CGO_ENABLED=1
GOTOOLCHAIN=auto
# shellcheck disable=SC2015
"${GO:?}" env 2>&1 | grep -q "GOSUMDB=.*off.*" \
  && GOSUMDB='sum.golang.org' || true
export GO GOFLAGS CGO_ENABLED GOTOOLCHAIN GOSUMDB

###############################################################################
# Setup Android NDK

NDKHOME="${HOME:-}/x-tools/android-ndk/"
NDKPATH="${NDKHOME:?}/toolchains/llvm/prebuilt/linux-x86_64/bin"

###############################################################################
# Android cross-compilation (uses Android NDK)

"${MAKE:-make}" clean
env "${MAKE:-make}" \
  CC="${NDKPATH:?}/armv7a-linux-androideabi21-clang" \
  GOOS="android" \
  GOARCH="arm" \
  CGO_ENABLED="${CGO_ENABLED:-1}" \
  GOTOOLCHAIN=auto
mv -f "./proxy" "./proxy.android.arm"

# android/386
"${MAKE:-make}" clean
env "${MAKE:-make}" \
  CC="${NDKPATH:?}/i686-linux-android21-clang" \
  GOOS="android" \
  GOARCH="386" \
  CGO_ENABLED="${CGO_ENABLED:-1}" \
  GOTOOLCHAIN=auto
mv -f "./proxy" "./proxy.android.386"

# android/amd64
"${MAKE:-make}" clean
env "${MAKE:-make}" \
  CC="${NDKPATH:?}/x86_64-linux-android21-clang" \
  GOOS="android" \
  GOARCH="amd64" \
  CGO_ENABLED="${CGO_ENABLED:-1}" \
  GOTOOLCHAIN=auto
mv -f "./proxy" "./proxy.android.amd64"

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
