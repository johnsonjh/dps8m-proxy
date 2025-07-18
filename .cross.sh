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

IFS=${OLDIFS:?}

wait
exec 3>&- 3<&-

###############################################################################
# vim: set ft=sh expandtab tabstop=2 cc=80 :
###############################################################################
