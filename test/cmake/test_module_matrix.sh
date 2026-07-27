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
TEST_ROOT=${CDF_MODULE_MATRIX_ROOT:-$(mktemp -d "${TMPDIR:-/tmp}/cdf-module-matrix.XXXXXX")}
if [[ -z "${CDF_MODULE_MATRIX_ROOT:-}" ]]; then
    trap 'rm -rf -- "${TEST_ROOT}"' EXIT
fi

readonly ALL_MODULES=(
    authentication
    authorization
    cryption
    cli_tool
    key_management
    rand
    psk_management
)

if [[ $# -gt 1 ]]; then
    echo "Usage: $0 [module]" >&2
    exit 2
fi

modules=("${ALL_MODULES[@]}")
if [[ $# -eq 1 ]]; then
    requested=$1
    supported=OFF
    for module in "${ALL_MODULES[@]}"; do
        if [[ "${module}" == "${requested}" ]]; then
            supported=ON
            break
        fi
    done
    if [[ "${supported}" == "OFF" ]]; then
        echo "Unknown module '${requested}'" >&2
        exit 2
    fi
    modules=("${requested}")
fi

for module in "${modules[@]}"; do
    build_dir="${TEST_ROOT}/${module}/build"
    install_dir="${TEST_ROOT}/${module}/install"
    echo "==> Testing module entrypoint: ${module}"
    cmake -S "${PROJECT_ROOT}" -B "${build_dir}" \
        -DCMAKE_INSTALL_PREFIX="${install_dir}" \
        -DBUILD_TEST=ON \
        -DENABLE_SHARED=ON \
        -DENABLE_MODULES="${module}" \
        -DENABLE_DOWNLOAD_DEPENDENCY=OFF
    cmake --build "${build_dir}" --parallel 2
    (cd "${build_dir}" && ctest --output-on-failure)
    cmake --build "${build_dir}" --target install --parallel 2

    find "${install_dir}" -type f -name 'libcdf_shared.so' -print -quit | grep -q .
    if [[ "${module}" == "cli_tool" ]]; then
        test -x "${install_dir}/bin/crypto_tool"
    fi
done

echo "module matrix tests passed"
