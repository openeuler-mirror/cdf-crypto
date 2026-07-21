#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d /tmp/cdf-test-coverage.XXXXXX)
trap 'rm -rf "${TEST_ROOT}"' EXIT

coverage_module="${PROJECT_ROOT}/cmake/SetupCoverage.cmake"
grep -q 'gcovr is required when BUILD_COVERAGE=ON' "${coverage_module}"
grep -Fq 'Coverage 仅支持 GCC' "${PROJECT_ROOT}/docs/build.md"
grep -Fq 'Coverage supports GCC only' "${PROJECT_ROOT}/docs/build.en.md"
if grep -Eq 'LCOV_PATH|GENHTML_PATH|lcov|genhtml' "${coverage_module}"; then
    echo "coverage configuration still exposes an incomplete lcov fallback" >&2
    exit 1
fi

cmake -S "${PROJECT_ROOT}/test/cmake/coverage_project" \
    -B "${TEST_ROOT}/coverage" \
    -DCDF_SOURCE_DIR="${PROJECT_ROOT}" \
    -DGCOV_PATH="$(command -v cmake)" \
    -DGCOVR_PATH="$(command -v cmake)" >/dev/null

cmake_executable=$(command -v cmake)
grep -Fq "GCOV_PATH:FILEPATH=${cmake_executable}" \
    "${TEST_ROOT}/coverage/CMakeCache.txt"
grep -Fq "GCOVR_PATH:FILEPATH=${cmake_executable}" \
    "${TEST_ROOT}/coverage/CMakeCache.txt"

if grep -q 'LD_PRELOAD=' "${PROJECT_ROOT}/test/CMakeLists.txt"; then
    echo "test configuration still contains an architecture-specific LD_PRELOAD" >&2
    exit 1
fi
if grep -q 'add_custom_target(build_test' "${PROJECT_ROOT}/test/CMakeLists.txt"; then
    echo "test configuration still bypasses CTest through build_test" >&2
    exit 1
fi

cmake -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/main" \
    -DBUILD_TEST=ON \
    -DENABLE_MODULES=rand \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null

ctest_output=$(cd "${TEST_ROOT}/main" && ctest -N)
[[ "${ctest_output}" == *"cdf_ut_test_all"* ]]
[[ "${ctest_output}" == *"deploy_verify_rand"* ]]
grep -Eq 'build_native_make_tool.*SKIP_RETURN_CODE.*77' \
    "${TEST_ROOT}/main/test/CTestTestfile.cmake"

mkdir -p "${TEST_ROOT}/without-ninja"
ln -s "$(command -v dirname)" "${TEST_ROOT}/without-ninja/dirname"
set +e
PATH="${TEST_ROOT}/without-ninja" /usr/bin/bash \
    "${PROJECT_ROOT}/test/cmake/test_native_make_tool.sh" >/dev/null 2>&1
native_make_status=$?
set -e
[[ ${native_make_status} -eq 77 ]]

echo "test and coverage configuration tests passed"
