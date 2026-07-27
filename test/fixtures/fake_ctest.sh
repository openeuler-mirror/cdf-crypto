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

: "${CDF_FAKE_CMAKE_LOG:?CDF_FAKE_CMAKE_LOG is required}"

if [[ "${1-}" == "--version" ]]; then
    printf 'ctest version %s\n' "${CDF_FAKE_CTEST_VERSION:-4.3.0}"
    exit 0
fi

printf 'ctest %s\n' "$*" >>"${CDF_FAKE_CMAKE_LOG}"

junit_path=
previous=
for argument in "$@"; do
    if [[ "${previous}" == "--output-junit" ]]; then
        junit_path=${argument}
        break
    fi
    previous=${argument}
done

if [[ -n "${junit_path}" &&
      "${CDF_FAKE_CTEST_WRITE_JUNIT:-ON}" == "ON" ]]; then
    mkdir -p "$(dirname "${junit_path}")"
    printf '%s\n' \
        '<?xml version="1.0" encoding="UTF-8"?>' \
        '<testsuite tests="1" failures="0">' \
        '  <testcase name="fake.test"/>' \
        '</testsuite>' >"${junit_path}"
fi

exit "${CDF_FAKE_CTEST_STATUS:-0}"
