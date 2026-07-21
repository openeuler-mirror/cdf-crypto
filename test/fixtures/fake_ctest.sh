#!/usr/bin/env bash

set -Eeuo pipefail

: "${CDF_FAKE_CMAKE_LOG:?CDF_FAKE_CMAKE_LOG is required}"
printf 'ctest %s\n' "$*" >>"${CDF_FAKE_CMAKE_LOG}"
