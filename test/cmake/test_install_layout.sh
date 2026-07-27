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
TEST_ROOT=$(mktemp -d /tmp/cdf-install-layout.XXXXXX)
trap 'rm -rf "${TEST_ROOT}"' EXIT

cmake -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="${TEST_ROOT}/install" \
    -DBUILD_TEST=OFF \
    -DENABLE_MODULES=authorization \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null
cmake --build "${TEST_ROOT}/build" --parallel 2 >/dev/null
cmake --build "${TEST_ROOT}/build" --target install >/dev/null

install_libdir=$(sed -n \
    's/^CMAKE_INSTALL_LIBDIR:PATH=//p' "${TEST_ROOT}/build/CMakeCache.txt")
[[ -n "${install_libdir}" ]] || {
    echo "CMAKE_INSTALL_LIBDIR is missing from CMakeCache.txt" >&2
    exit 1
}
library_dir="${TEST_ROOT}/install/${install_libdir}"
static_library="${library_dir}/libcdf.a"
shared_library="${library_dir}/libcdf_shared.so"
selected_header="${TEST_ROOT}/install/include/cdf/modules/authorization/whitelist_authorization.h"

[[ -f "${static_library}" ]] || {
    echo "static library was not installed" >&2
    exit 1
}
[[ -f "${shared_library}" ]] || {
    echo "shared library was not installed" >&2
    exit 1
}
[[ -f "${selected_header}" ]] || {
    echo "selected module headers were not installed" >&2
    exit 1
}
[[ ! -e "${TEST_ROOT}/install/include/cdf/modules/rand" ]] || {
    echo "disabled module headers were installed" >&2
    exit 1
}

[[ $(stat -c '%a' "${static_library}") == 550 ]] || {
    echo "static library did not retain historical mode 0550" >&2
    exit 1
}
[[ $(stat -c '%a' "${shared_library}") == 550 ]] || {
    echo "shared library did not retain historical mode 0550" >&2
    exit 1
}
[[ $(stat -c '%a' "${selected_header}") == 440 ]] || {
    echo "installed header did not retain historical mode 0440" >&2
    exit 1
}

echo "install layout tests passed"
