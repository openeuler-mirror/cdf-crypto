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
# NON-INFRINGEMENT, MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-krb5-policy.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT

mkdir -p "${TEST_ROOT}/src"
cp "${PROJECT_ROOT}/test/fixtures/krb5/aclocal-warning-flags.m4" \
    "${TEST_ROOT}/src/aclocal.m4"
cmake_bin=$(command -v cmake)
cc_bin=$(command -v cc)
cxx_bin=$(command -v c++)
git_bin=$(command -v git)
make_bin=$(command -v gmake || command -v make)
policy_script="${PROJECT_ROOT}/cmake/ApplyKrb5WarningPolicy.cmake"

"${cmake_bin}" -DKRB5_ACLOCAL_FILE="${TEST_ROOT}/src/aclocal.m4" \
    -P "${policy_script}"
"${cmake_bin}" -DKRB5_ACLOCAL_FILE="${TEST_ROOT}/src/aclocal.m4" \
    -P "${policy_script}"

grep -Fq \
    'error=incompatible-pointer-types discarded-qualifiers error=implicit-int' \
    "${TEST_ROOT}/src/aclocal.m4"
if grep -Fq 'error=discarded-qualifiers' "${TEST_ROOT}/src/aclocal.m4"; then
    echo 'discarded-qualifiers is still promoted to an error' >&2
    exit 1
fi

printf '%s\n' 'unexpected warning policy' >"${TEST_ROOT}/src/invalid.m4"
if "${cmake_bin}" -DKRB5_ACLOCAL_FILE="${TEST_ROOT}/src/invalid.m4" \
    -P "${policy_script}" >"${TEST_ROOT}/invalid.log" 2>&1; then
    echo 'unexpected krb5 warning policy was accepted' >&2
    exit 1
fi
grep -Fq 'does not contain the expected warning policy' \
    "${TEST_ROOT}/invalid.log"

trace_log="${TEST_ROOT}/krb5-configure.trace"
"${cmake_bin}" --trace-expand \
    --trace-source="${PROJECT_ROOT}/cmake/deps/krb5.cmake" \
    -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/build" \
    -DBUILD_TEST=OFF \
    -DENABLE_MODULES=authentication \
    -DCMAKE_C_COMPILER="${cc_bin}" \
    -DCMAKE_CXX_COMPILER="${cxx_bin}" \
    -DCMAKE_MAKE_PROGRAM="${make_bin}" \
    -DCMAKE_IGNORE_PATH='/usr/bin;/bin;/usr/sbin;/sbin' \
    -DCDF_NATIVE_MAKE_EXECUTABLE="${make_bin}" \
    -DGIT_EXECUTABLE="${git_bin}" \
    -DENABLE_DOWNLOAD_DEPENDENCY=ON >/dev/null 2>"${trace_log}"
grep -Eq \
    'ExternalProject_Add\(krb5 .*PATCH_COMMAND .*ApplyKrb5WarningPolicy\.cmake' \
    "${trace_log}"
if grep -Eq 'PATCH_COMMAND .*/patch([ ;]|$)' "${trace_log}"; then
    echo 'krb5 still invokes the external patch command' >&2
    exit 1
fi

echo 'krb5 warning policy tests passed'
