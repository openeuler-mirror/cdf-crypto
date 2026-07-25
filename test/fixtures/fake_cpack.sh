#!/usr/bin/env bash

set -Eeuo pipefail

: "${CDF_FAKE_CMAKE_LOG:?CDF_FAKE_CMAKE_LOG is required}"
printf 'cpack %s\n' "$*" >>"${CDF_FAKE_CMAKE_LOG}"

# Simulate a successful CPack process that fails to produce an artifact.
exit 0
