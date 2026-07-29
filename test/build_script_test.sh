#!/usr/bin/env bash

#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
# Confidential Data defensive Framework is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf "${TEST_ROOT}"' EXIT

cp "${PROJECT_ROOT}/build.sh" "${TEST_ROOT}/build.sh"

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

expect_success() {
    local output
    output=$("$@" 2>&1) || fail "expected success: $*; output: ${output}"
    printf '%s' "${output}"
}

expect_failure_contains() {
    local expected=$1
    shift
    local output
    if output=$("$@" 2>&1); then
        fail "expected failure: $*"
    fi
    [[ "${output}" == *"${expected}"* ]] ||
        fail "expected output to contain '${expected}', got: ${output}"
}

help_output=$(expect_success bash "${TEST_ROOT}/build.sh" help)
[[ "${help_output}" == *"package rpm"* ]] || fail "help does not list package rpm"
[[ "${help_output}" == *"--profile"* ]] || fail "help does not list --profile"
[[ "${help_output}" != *"cicd_default"* ]] || fail "help still lists legacy commands"

expect_failure_contains "Unknown command 'all'" bash "${TEST_ROOT}/build.sh" all
expect_failure_contains "Unknown command 'output'" bash "${TEST_ROOT}/build.sh" output
expect_failure_contains "positive integer" bash "${TEST_ROOT}/build.sh" build --jobs 0
expect_failure_contains "Duplicate module 'rand'" \
    bash "${TEST_ROOT}/build.sh" build --modules rand,rand
expect_failure_contains "Unknown module 'cert'" \
    bash "${TEST_ROOT}/build.sh" build --modules cert
expect_failure_contains "does not accept --profile" \
    bash "${TEST_ROOT}/build.sh" coverage --profile debug
expect_failure_contains "does not accept --with-tests" \
    bash "${TEST_ROOT}/build.sh" test --with-tests
expect_failure_contains "does not accept --prefix" \
    bash "${TEST_ROOT}/build.sh" build --prefix output/custom

mkdir -p "${TEST_ROOT}/fake-bin"
cp "${PROJECT_ROOT}/test/fixtures/fake_cmake.sh" \
    "${TEST_ROOT}/fake-bin/cmake"
cp "${PROJECT_ROOT}/test/fixtures/fake_cpack.sh" \
    "${TEST_ROOT}/fake-bin/cpack"
cp "${PROJECT_ROOT}/test/fixtures/fake_ctest.sh" \
    "${TEST_ROOT}/fake-bin/ctest"
chmod +x "${TEST_ROOT}/fake-bin/cmake" "${TEST_ROOT}/fake-bin/cpack" \
    "${TEST_ROOT}/fake-bin/ctest"
fake_cmake_log="${TEST_ROOT}/fake-cmake.log"
mkdir -p "${TEST_ROOT}/build/debug/bin" "${TEST_ROOT}/build/debug/lib64"
touch "${TEST_ROOT}/build/debug/bin/stale-test" \
    "${TEST_ROOT}/build/debug/lib64/stale-library.so"
printf '%s\n' 'CMAKE_INSTALL_LIBDIR:PATH=lib64' > \
    "${TEST_ROOT}/build/debug/CMakeCache.txt"
CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
CDF_FAKE_CTEST_VERSION=3.20.6 \
PATH="${TEST_ROOT}/fake-bin:${PATH}" \
    expect_success bash "${TEST_ROOT}/build.sh" build \
        --profile debug \
        --modules rand,authorization \
        --fetch-deps \
        --enable-blake3 \
        --with-tests \
        --jobs 3 \
        --no-shared >/dev/null

fake_calls=$(<"${fake_cmake_log}")
[[ "${fake_calls}" == *"-B ${TEST_ROOT}/build/debug"* ]] ||
    fail "debug profile did not select build/debug"
[[ "${fake_calls}" == *"-DCMAKE_BUILD_TYPE=Debug"* ]] ||
    fail "debug profile did not select the Debug CMake build type"
[[ "${fake_calls}" == *"-DBUILD_TEST=ON"* ]] ||
    fail "--with-tests was not forwarded"
[[ "${fake_calls}" == *"-DENABLE_SHARED=OFF"* ]] ||
    fail "--no-shared was not forwarded"
[[ "${fake_calls}" == *"-DENABLE_DOWNLOAD_DEPENDENCY=ON"* ]] ||
    fail "--fetch-deps was not forwarded"
[[ "${fake_calls}" == *"-DENABLE_BLAKE3=ON"* ]] ||
    fail "--enable-blake3 was not forwarded"
[[ "${fake_calls}" == *"-DENABLE_MODULES=rand;authorization"* ]] ||
    fail "module list was not forwarded as a CMake list"
[[ "${fake_calls}" == *"--parallel 3"* ]] ||
    fail "--jobs was not forwarded to the build command"
[[ "${fake_calls}" == *"--config Debug"* ]] ||
    fail "the Debug configuration was not forwarded to the build command"
[[ ! -e "${TEST_ROOT}/build/debug/bin/stale-test" ]] ||
    fail "stale runtime artifacts were retained"
[[ ! -e "${TEST_ROOT}/build/debug/lib64/stale-library.so" ]] ||
    fail "stale library artifacts were retained"

: >"${fake_cmake_log}"
expect_failure_contains "CTest 3.21 or newer is required" \
    env CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
        CDF_FAKE_CTEST_VERSION=3.20.6 \
        PATH="${TEST_ROOT}/fake-bin:${PATH}" \
        bash "${TEST_ROOT}/build.sh" test \
            --profile debug --modules authorization --jobs 1
[[ ! -s "${fake_cmake_log}" ]] ||
    fail "an unsupported CTest version did not fail before configuration"

: >"${fake_cmake_log}"
expect_failure_contains "CTest 3.21 or newer is required" \
    env CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
        CDF_FAKE_CTEST_VERSION=3.20.6 \
        PATH="${TEST_ROOT}/fake-bin:${PATH}" \
        bash "${TEST_ROOT}/build.sh" coverage \
            --modules authorization --jobs 1
[[ ! -s "${fake_cmake_log}" ]] ||
    fail "coverage did not reject unsupported CTest before configuration"

: >"${fake_cmake_log}"
CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
PATH="${TEST_ROOT}/fake-bin:${PATH}" \
    expect_success bash "${TEST_ROOT}/build.sh" test \
        --profile debug --modules authorization --jobs 1 >/dev/null
fake_calls=$(<"${fake_cmake_log}")
test_results="${TEST_ROOT}/build/debug/Testing/test_results.xml"
[[ -s "${test_results}" ]] || fail "test did not produce JUnit XML"
[[ "${fake_calls}" == *"ctest -C Debug --output-on-failure --output-junit Testing/test_results.xml"* ]] ||
    fail "CTest was not asked to produce the profile JUnit report"

mkdir -p "$(dirname "${test_results}")"
printf '%s\n' stale >"${test_results}"
expect_failure_contains "CTest did not produce a non-empty JUnit report" \
    env CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
        CDF_FAKE_CTEST_WRITE_JUNIT=OFF \
        PATH="${TEST_ROOT}/fake-bin:${PATH}" \
        bash "${TEST_ROOT}/build.sh" test \
            --profile debug --modules authorization --jobs 1
[[ ! -e "${test_results}" ]] || fail "stale JUnit XML survived a test run"

set +e
CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
CDF_FAKE_CTEST_STATUS=7 \
PATH="${TEST_ROOT}/fake-bin:${PATH}" \
    bash "${TEST_ROOT}/build.sh" test \
        --profile debug --modules authorization --jobs 1 >/dev/null 2>&1
ctest_failure_status=$?
set -e
[[ ${ctest_failure_status} -eq 7 ]] ||
    fail "build.sh did not preserve the failing CTest status"
[[ -s "${test_results}" ]] ||
    fail "a failing CTest run did not retain its JUnit XML"

expect_failure_contains "without producing an RPM" \
    env CDF_FAKE_CMAKE_LOG="${fake_cmake_log}" \
        PATH="${TEST_ROOT}/fake-bin:${PATH}" \
        bash "${TEST_ROOT}/build.sh" package rpm \
            --modules authorization --jobs 1
fake_calls=$(<"${fake_cmake_log}")
[[ "${fake_calls}" == *"cpack --config ${TEST_ROOT}/build/release/CPackConfig.cmake -C Release -G RPM"* ]] ||
    fail "the Release configuration was not forwarded to CPack"

mkdir -p "${TEST_ROOT}/build" "${TEST_ROOT}/output" \
    "${TEST_ROOT}/package" "${TEST_ROOT}/external"
touch "${TEST_ROOT}/build/generated" "${TEST_ROOT}/external/keep"
expect_success bash "${TEST_ROOT}/build.sh" clean build >/dev/null
[[ ! -e "${TEST_ROOT}/build" ]] || fail "clean build did not remove build directory"
[[ -e "${TEST_ROOT}/external/keep" ]] || fail "clean build removed external content"

cp "${PROJECT_ROOT}/test/fixtures/minimal_build/CMakeLists.txt" \
    "${TEST_ROOT}/CMakeLists.txt"
cp "${PROJECT_ROOT}/test/fixtures/minimal_build/artifact.txt" \
    "${TEST_ROOT}/artifact.txt"
mkdir -p "${TEST_ROOT}/output/cdf"
touch "${TEST_ROOT}/output/cdf/stale-artifact"
expect_success bash "${TEST_ROOT}/build.sh" install --jobs 1 >/dev/null
[[ ! -e "${TEST_ROOT}/output/cdf/stale-artifact" ]] ||
    fail "default install prefix retained stale artifacts"
[[ -f "${TEST_ROOT}/output/cdf/artifact.txt" ]] ||
    fail "install did not populate the default prefix"

echo "build script tests passed"
