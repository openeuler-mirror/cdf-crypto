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

native_make_executable=$(command -v gmake || command -v make || true)
if [[ -z "${native_make_executable}" ]]; then
    echo "SKIP: GNU Make is not available" >&2
    exit 77
fi

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-native-make.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT
fake_make="${TEST_ROOT}/fake-make"
cmake_executable=$(command -v cmake)
{
    printf '%s\n' '#!/usr/bin/env bash'
    printf 'exec %q "$@"\n' "${native_make_executable}"
} >"${fake_make}"
chmod +x "${fake_make}"

for dependency in openssl libboundscheck krb5; do
    if grep -q 'CMAKE_MAKE_PROGRAM' \
        "${PROJECT_ROOT}/cmake/deps/${dependency}.cmake"; then
        echo "${dependency} incorrectly uses the outer CMake generator tool" >&2
        exit 1
    fi
done

"${cmake_executable}" -G "Unix Makefiles" -S "${PROJECT_ROOT}" \
    -B "${TEST_ROOT}/build" \
    -DCMAKE_MAKE_PROGRAM="${fake_make}" \
    -DBUILD_TEST=ON \
    -DENABLE_MODULES=rand \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null

build_step="${TEST_ROOT}/build/deps/src/openssl-stamp/openssl-build-Release.cmake"
install_step="${TEST_ROOT}/build/deps/src/openssl-stamp/openssl-install-Release.cmake"
grep -Eq 'set\(command ".*/(g?make)"\)' "${build_step}"
grep -Eq 'set\(command ".*/(g?make);install"\)' "${install_step}"
if grep -Fq "${fake_make}" "${build_step}" "${install_step}"; then
    echo "OpenSSL incorrectly uses the outer CMake generator tool" >&2
    exit 1
fi

"${cmake_executable}" -Werror=dev -G "Unix Makefiles" -S "${PROJECT_ROOT}" \
    -B "${TEST_ROOT}/download-build" \
    -DCMAKE_MAKE_PROGRAM="${fake_make}" \
    -DBUILD_TEST=OFF \
    -DENABLE_MODULES=authentication \
    -DENABLE_DOWNLOAD_DEPENDENCY=ON >/dev/null

install_libdir=$(sed -n 's/^CMAKE_INSTALL_LIBDIR:PATH=//p' \
    "${TEST_ROOT}/download-build/CMakeCache.txt")
[[ -n "${install_libdir}" ]]
link_file="${TEST_ROOT}/download-build/src/cdf/CMakeFiles/cdf_shared.dir/link.txt"
for library in libkrb5 libgssapi_krb5 libcom_err libkrb5support libk5crypto; do
    grep -Fq "deps/${install_libdir}/${library}.so" \
        "${link_file}" || {
        echo "downloaded Kerberos library ${library} is not linked by its exact path" >&2
        exit 1
    }
done
if grep -Eq -- '-llib(gssapi_krb5|com_err|krb5support|k5crypto)' \
    "${link_file}"; then
    echo "downloaded Kerberos libraries use invalid -llib... linker names" >&2
    exit 1
fi

echo "native Make tool tests passed"
