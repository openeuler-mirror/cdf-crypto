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
BUILD_DIR=$(mktemp -d /tmp/cdf-target-scopes.XXXXXX)
trap 'rm -rf "${BUILD_DIR}"' EXIT

cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
    -DBUILD_TEST=ON \
    -DENABLE_MODULES=rand \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null

global_flags=$(sed -n 's/^CMAKE_CXX_FLAGS:STRING=//p' "${BUILD_DIR}/CMakeCache.txt")
if [[ "${global_flags}" == *"-Werror"* || "${global_flags}" == *"-Wall"* ]]; then
    echo "project warnings leaked into CMAKE_CXX_FLAGS: ${global_flags}" >&2
    exit 1
fi

if ! grep -q -- '-Werror' "${BUILD_DIR}/compile_commands.json"; then
    echo "first-party compile commands do not contain -Werror" >&2
    exit 1
fi

if ! grep -q -- '-O2' "${BUILD_DIR}/compile_commands.json"; then
    echo "Release compile commands do not contain the historical -O2 option" >&2
    exit 1
fi

if grep -q -- '--coverage\|-fsanitize=address' "${BUILD_DIR}/compile_commands.json"; then
    echo "default build unexpectedly contains instrumentation" >&2
    exit 1
fi

if grep -q -- '-fno-omit-frame-pointer' "${BUILD_DIR}/compile_commands.json"; then
    echo "BUILD_TEST unexpectedly enabled ASan compile options" >&2
    exit 1
fi

if ! grep -Eq -- '-isystem [^ ]*/deps/include' "${BUILD_DIR}/compile_commands.json"; then
    echo "third-party dependency headers are not marked as system includes" >&2
    exit 1
fi

for executable_target in cdf_ut_base_utils cdf_ut_rand deploy_verify_rand; do
    link_command="${BUILD_DIR}/test/CMakeFiles/${executable_target}.dir/link.txt"
    [[ -f "${link_command}" ]] || {
        echo "missing link command for executable ${executable_target}" >&2
        exit 1
    }
    if ! grep -q -- '-rdynamic' "${link_command}"; then
        echo "executable ${executable_target} is missing -rdynamic" >&2
        exit 1
    fi
done

for unrelated_target in cdf_ut_cli cdf_ut_authentication_jwt \
    cdf_ut_authentication_kerberos cdf_ut_authorization cdf_ut_cryption \
    cdf_ut_key_management cdf_ut_psk_management; do
    if [[ -d "${BUILD_DIR}/test/CMakeFiles/${unrelated_target}.dir" ]]; then
        echo "rand-only build unexpectedly created ${unrelated_target}" >&2
        exit 1
    fi
done

if grep -q -- '-rdynamic' "${BUILD_DIR}/src/cdf/CMakeFiles/cdf.dir/link.txt" 2>/dev/null; then
    echo "executable-only -rdynamic leaked into the static library" >&2
    exit 1
fi

if command -v ninja >/dev/null 2>&1; then
    MULTI_CONFIG_BUILD_DIR="${BUILD_DIR}/multi-config"
    cmake -G "Ninja Multi-Config" -S "${PROJECT_ROOT}" \
        -B "${MULTI_CONFIG_BUILD_DIR}" \
        -DBUILD_TEST=OFF \
        -DENABLE_MODULES=cli_tool \
        -DENABLE_DOWNLOAD_DEPENDENCY=OFF \
        >"${MULTI_CONFIG_BUILD_DIR}.log"

    grep -Eq '^-- Build configurations +: .*(Debug|Release)' \
        "${MULTI_CONFIG_BUILD_DIR}.log"

    if grep -q '^CMAKE_BUILD_TYPE:.*=Release$' \
        "${MULTI_CONFIG_BUILD_DIR}/CMakeCache.txt"; then
        echo "multi-config generator was forced to a single build type" >&2
        exit 1
    fi
    if grep -q -- '-pie' \
        "${MULTI_CONFIG_BUILD_DIR}/CMakeFiles/impl-Debug.ninja"; then
        echo "Release-only PIE option leaked into Debug" >&2
        exit 1
    fi
    if ! grep -q -- '-pie' \
        "${MULTI_CONFIG_BUILD_DIR}/CMakeFiles/impl-Release.ninja"; then
        echo "Release CLI link options do not contain PIE" >&2
        exit 1
    fi
fi

echo "target scope tests passed"
