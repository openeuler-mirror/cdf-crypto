#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=$(mktemp -d /tmp/cdf-fuzz-config.XXXXXX)
trap 'rm -rf "${BUILD_DIR}"' EXIT

if [[ -e "${PROJECT_ROOT}/cmake/deps/secodefuzz.cmake" ]]; then
    echo "unused secodefuzz dependency configuration still exists" >&2
    exit 1
fi

cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_TEST=ON \
    -DBUILD_FUZZ=ON \
    -DBUILD_ASAN=ON \
    -DENABLE_MODULES=authorization \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null
cmake --build "${BUILD_DIR}" --parallel 2 >/dev/null

grep -q -- '-fsanitize-coverage=trace-pc,trace-cmp' \
    "${BUILD_DIR}/compile_commands.json"
nm "${BUILD_DIR}/libcdf_fuzz_runtime.a" | \
    grep -q ' W __sanitizer_cov_trace_pc$'

echo "fuzz configuration tests passed"
