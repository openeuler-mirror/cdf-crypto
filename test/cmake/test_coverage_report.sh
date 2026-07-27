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

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-coverage-report.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT
SHADOW_ROOT="${TEST_ROOT}/project"
COVERAGE_BUILD_DIR="${SHADOW_ROOT}/build/coverage"

mkdir -p "${SHADOW_ROOT}" "${COVERAGE_BUILD_DIR}"
cp "${PROJECT_ROOT}/build.sh" "${SHADOW_ROOT}/build.sh"
for path in CMakeLists.txt cmake config.sh docs scripts src test; do
    cp -a "${PROJECT_ROOT}/${path}" "${SHADOW_ROOT}/${path}"
done
# Dependency source trees can be large and are read-only inputs to their
# isolated ExternalProject builds, so sharing them does not contaminate the
# developer's build or coverage report.
ln -s "${PROJECT_ROOT}/external" "${SHADOW_ROOT}/external"
touch "${COVERAGE_BUILD_DIR}/stale-coverage-marker"

bash "${SHADOW_ROOT}/build.sh" coverage --modules rand --jobs 2
[[ ! -e "${COVERAGE_BUILD_DIR}/stale-coverage-marker" ]]
TEST_RESULTS="${COVERAGE_BUILD_DIR}/Testing/test_results.xml"
[[ -s "${TEST_RESULTS}" ]]
grep -Fq 'name="cdf_ut_rand.RandTest.GetRand_NullBuffer_Fail"' \
    "${TEST_RESULTS}"
grep -Fq 'name="deploy_verify_rand"' "${TEST_RESULTS}"
grep -Fq 'name="build_script_contract"' "${TEST_RESULTS}"
[[ -f "${COVERAGE_BUILD_DIR}/report/index.html" ]]
grep -Fq 'low: &lt; 70 %' "${COVERAGE_BUILD_DIR}/report/index.html"
grep -Fq 'medium: &gt;= 70 %' "${COVERAGE_BUILD_DIR}/report/index.html"
[[ -f "${COVERAGE_BUILD_DIR}/report/coverage.info" ]]
grep -q '^SF:' "${COVERAGE_BUILD_DIR}/report/coverage.info"
grep -q '^BRDA:' "${COVERAGE_BUILD_DIR}/report/coverage.info"
grep -q '^BRF:' "${COVERAGE_BUILD_DIR}/report/coverage.info"
grep -q '^BRH:' "${COVERAGE_BUILD_DIR}/report/coverage.info"
grep -Fq -- "--gcov-tool $(command -v gcov)" \
    "${COVERAGE_BUILD_DIR}/build.ninja" 2>/dev/null || \
grep -Fq -- "--gcov-tool $(command -v gcov)" \
    "${COVERAGE_BUILD_DIR}/CMakeFiles/coverage.dir/build.make"
grep -Fq -- "--branch-coverage" \
    "${COVERAGE_BUILD_DIR}/build.ninja" 2>/dev/null || \
grep -Fq -- "lcov_branch_coverage=1" \
    "${COVERAGE_BUILD_DIR}/build.ninja" 2>/dev/null || \
grep -Fq -- "--branch-coverage" \
    "${COVERAGE_BUILD_DIR}/CMakeFiles/coverage.dir/build.make" || \
grep -Fq -- "lcov_branch_coverage=1" \
    "${COVERAGE_BUILD_DIR}/CMakeFiles/coverage.dir/build.make"

echo "coverage report tests passed"
