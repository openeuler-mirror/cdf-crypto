#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d /tmp/cdf-test-coverage.XXXXXX)
trap 'rm -rf "${TEST_ROOT}"' EXIT

coverage_module="${PROJECT_ROOT}/cmake/SetupCoverage.cmake"
grep -q 'lcov is required when BUILD_COVERAGE=ON' "${coverage_module}"
grep -q 'genhtml is required when BUILD_COVERAGE=ON' "${coverage_module}"
grep -q -- '--branch-coverage' "${coverage_module}"
grep -q 'genhtml_hi_limit=90' "${coverage_module}"
grep -q 'genhtml_med_limit=70' "${coverage_module}"
grep -q 'genhtml_line_hi_limit=90' "${coverage_module}"
grep -q 'genhtml_line_med_limit=70' "${coverage_module}"
grep -q 'genhtml_branch_hi_limit=60' "${coverage_module}"
grep -q 'genhtml_branch_med_limit=50' "${coverage_module}"
grep -q 'lcov_branch_coverage=1' "${coverage_module}"
grep -q 'genhtml_branch_coverage=1' "${coverage_module}"
grep -Fq 'Coverage 仅支持 GCC' "${PROJECT_ROOT}/docs/build.md"
grep -Fq 'Coverage supports GCC only' "${PROJECT_ROOT}/docs/build.en.md"
if grep -Eq 'GCOVR_PATH|gcovr' "${coverage_module}"; then
    echo "coverage configuration still depends on gcovr" >&2
    exit 1
fi

cmake -S "${PROJECT_ROOT}/test/cmake/coverage_project" \
    -B "${TEST_ROOT}/coverage" \
    -DCDF_SOURCE_DIR="${PROJECT_ROOT}" \
    -DGCOV_PATH="$(command -v cmake)" \
    -DLCOV_PATH="$(command -v cmake)" \
    -DGENHTML_PATH="$(command -v cmake)" >/dev/null

cmake_executable=$(command -v cmake)
grep -Fq "GCOV_PATH:FILEPATH=${cmake_executable}" \
    "${TEST_ROOT}/coverage/CMakeCache.txt"
grep -Fq "LCOV_PATH:FILEPATH=${cmake_executable}" \
    "${TEST_ROOT}/coverage/CMakeCache.txt"
grep -Fq "GENHTML_PATH:FILEPATH=${cmake_executable}" \
    "${TEST_ROOT}/coverage/CMakeCache.txt"
grep -Fq -- "--rc lcov_branch_coverage=1" \
    "${TEST_ROOT}/coverage/CMakeFiles/coverage.dir/build.make"
grep -Fq -- "--rc genhtml_branch_coverage=1" \
    "${TEST_ROOT}/coverage/CMakeFiles/coverage.dir/build.make"
if grep -Fq -- "--ignore-errors mismatch" \
    "${TEST_ROOT}/coverage/CMakeFiles/coverage.dir/build.make"; then
    echo "old lcov fallback still uses lcov 2.x mismatch ignore errors" >&2
    exit 1
fi
if grep -Fq -- "--ignore-errors unused" \
    "${TEST_ROOT}/coverage/CMakeFiles/coverage.dir/build.make"; then
    echo "old lcov fallback still uses lcov 2.x unused ignore errors" >&2
    exit 1
fi

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

ctest_output=$(ctest --test-dir "${TEST_ROOT}/main" -N)
[[ "${ctest_output}" == *"cdf_ut_base_utils.TestSupport.ScopedOverrideRestoresOriginalValue"* ]]
[[ "${ctest_output}" == *"cdf_ut_rand.RandTest.GetRand_NullBuffer_Fail"* ]]
[[ "${ctest_output}" == *"deploy_verify_rand"* ]]
[[ "${ctest_output}" != *"cdf_ut_cli."* ]]
[[ "${ctest_output}" != *"cdf_ut_authentication_"* ]]
[[ "${ctest_output}" != *"cdf_ut_key_management."* ]]

rand_label_output=$(ctest --test-dir "${TEST_ROOT}/main" -N \
    -L '^cdf_ut_rand$')
[[ "${rand_label_output}" == *"cdf_ut_rand.RandTest.GetRand_NullBuffer_Fail"* ]]
[[ "${rand_label_output}" != *"cdf_ut_base_utils."* ]]
[[ "${rand_label_output}" != *"deploy_verify_rand"* ]]
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
