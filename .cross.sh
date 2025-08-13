#!/bin/sh
###############################################################################
# DPS8M Proxy - .cross.sh
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT-0
# scspell-id: 3fdac6e0-6bd1-11f0-8c81-80ee73e9b8e7
###############################################################################

###############################################################################
# Strict

set -e

###############################################################################
# Cleanup

rm -rf ./cross.bin
mkdir -p ./cross.bin

###############################################################################
# Setup Go

GO="$(command -v go 2> /dev/null || printf '%s\n' 'go')"
CGO_ENABLED=0
GOTOOLCHAIN=auto
# shellcheck disable=SC2015
"${GO:?}" env 2>&1 | grep -q "GOSUMDB=.*off.*" \
  && GOSUMDB='sum.golang.org' || true
export GO CGO_ENABLED GOTOOLCHAIN GOSUMDB

###############################################################################
# Create script
# Exclude ios/*, android/{386,amd64,arm}

# shellcheck disable=SC2016
_S=$("${GO:?}" tool dist list \
  | grep -Ev '^ios/|^android/(386|amd64|arm)$' \
  | awk 'BEGIN { FS="/" } /\// { print "GOOS="$1" GOARCH="$2 }' \
  | xargs -I{} printf '%s\n' '
      export {} && printf "🧩 %s/%s\n" "${GOOS:?}" "${GOARCH:?}" &&
      "${GO:?}" build -trimpath \
        -o ./cross.bin/proxy."${GOOS:?}"."${GOARCH:?}";')

###############################################################################
# Maximum jobs

if [ -n "${MAX_CPU:-}" ]; then
  max="${MAX_CPU:?}"
else
  max=$(nproc 2> /dev/null \
    || getconf NPROCESSORS_ONLN 2> /dev/null \
    || getconf _NPROCESSORS_ONLN 2> /dev/null \
    || getconf NPROCESSORS_CONF 2> /dev/null \
    || getconf _NPROCESSORS_CONF 2> /dev/null \
    || printf '%s\n' "1")
fi

# shellcheck disable=SC2249
case ${max:-} in
'' | *[!0-9]* | 0) {
  printf '%s\n' "❗ Invalid MAX_CPU value detected, using default of 1."
  max=1
} ;;
esac

###############################################################################
# Inform of parallelism

test -z "${MAX_CPU:-}" && {
  printf '%s\n' \
    "🧠 Set environment variable MAX_CPU to override detected parallelism."
}

if [ "${max:?}" -eq 1 ]; then
  printf '%s\n' "💻 Build parallelism is disabled."
else
  printf '%s\n' \
    "💻 Forking up to ${max:?} concurrent builds for parallel compilation..."
fi

###############################################################################
# Create semaphore

fifo="/tmp/${$}.fifo"
trap 'rm -f "${fifo:?}"' EXIT
mkfifo "${fifo:?}"
exec 3<> "${fifo:?}"
i=0

while [ "${i:?}" -lt "${max:?}" ]; do
  printf '%s\n' "" >&3
  i=$((i + 1))
done

###############################################################################
# Disable strict

set +e

###############################################################################
# Run script

OLDIFS=${IFS:-}
# nosemgrep: bash.lang.security.ifs-tampering.ifs-tampering
IFS=';'

for chunk in ${_S}; do
  cmd=$(printf '%s' "${chunk:?}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
  [ -z "${cmd:?}" ] && continue
  read -r _ <&3
  (
    sh -c "${cmd:?}"
    printf '%s\n' "" >&3
  ) &
done

# nosemgrep: bash.lang.security.ifs-tampering.ifs-tampering
IFS=${OLDIFS:?}

wait
exec 3>&- 3<&-

###############################################################################
# Build linux/mipssf

export GOOS=linux GOARCH=mips GOMIPS=softfloat \
  && printf "🧩 %s/%s\n" "${GOOS:?}" "${GOARCH:?}sf" \
  && "${GO:?}" build -trimpath \
    -o ./cross.bin/proxy."${GOOS:?}"."${GOARCH:?}"sf

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
