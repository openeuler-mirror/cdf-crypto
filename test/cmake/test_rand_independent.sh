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
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-rand-independent.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT

cmake -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/build" \
    -DCMAKE_INSTALL_PREFIX="${TEST_ROOT}/install" \
    -DBUILD_TEST=OFF \
    -DENABLE_SHARED=ON \
    -DENABLE_MODULES=rand \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF
cmake --build "${TEST_ROOT}/build" --parallel 2
cmake --build "${TEST_ROOT}/build" --target install --parallel 2

test -f "${TEST_ROOT}/install/include/cdf/base/crypt_error.h"
test ! -e "${TEST_ROOT}/install/include/cdf/modules/cryption"
test ! -e "${TEST_ROOT}/install/include/cdf/modules/key_management"

cmake -S "${PROJECT_ROOT}/test/fixtures/rand_consumer" \
    -B "${TEST_ROOT}/consumer" \
    -DCDF_PREFIX="${TEST_ROOT}/install"
cmake --build "${TEST_ROOT}/consumer" --parallel 2

echo "rand independent SDK test passed"
