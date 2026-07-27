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
printf '%s\n' "$*" >>"${CDF_FAKE_CMAKE_LOG}"

build_dir=
previous=
for argument in "$@"; do
    if [[ "${previous}" == "-B" ]]; then
        build_dir=${argument}
        break
    fi
    previous=${argument}
done

if [[ -n "${build_dir}" ]]; then
    mkdir -p "${build_dir}"
    {
        printf '%s\n' 'CMAKE_INSTALL_BINDIR:PATH=bin'
        printf '%s\n' 'CMAKE_INSTALL_LIBDIR:PATH=lib64'
    } >"${build_dir}/CMakeCache.txt"
fi
