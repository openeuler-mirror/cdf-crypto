#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

if ! command -v ninja >/dev/null 2>&1; then
    echo "SKIP: Ninja is not available" >&2
    exit 77
fi
if ! command -v gmake >/dev/null 2>&1 &&
   ! command -v make >/dev/null 2>&1; then
    echo "SKIP: GNU Make is not available" >&2
    exit 77
fi

TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-native-make.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT

for dependency in openssl libboundscheck krb5; do
    if grep -q 'CMAKE_MAKE_PROGRAM' \
        "${PROJECT_ROOT}/cmake/deps/${dependency}.cmake"; then
        echo "${dependency} incorrectly uses the outer CMake generator tool" >&2
        exit 1
    fi
done

cmake -G Ninja -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/build" \
    -DBUILD_TEST=ON \
    -DENABLE_MODULES=rand \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null

build_step="${TEST_ROOT}/build/deps/src/openssl-stamp/openssl-build-Release.cmake"
install_step="${TEST_ROOT}/build/deps/src/openssl-stamp/openssl-install-Release.cmake"
grep -Eq 'set\(command ".*/(g?make)"\)' "${build_step}"
grep -Eq 'set\(command ".*/(g?make);install"\)' "${install_step}"
grep -Eq '^build .*deps/[^ ]+/libcrypto\.a.*: CUSTOM_COMMAND' \
    "${TEST_ROOT}/build/build.ninja"
grep -Eq '^build .*deps/[^ ]+/libgtest\.a.*: CUSTOM_COMMAND' \
    "${TEST_ROOT}/build/build.ninja"
grep -Eq '^build .*deps/[^ ]+/libgtest_main\.a.*: CUSTOM_COMMAND' \
    "${TEST_ROOT}/build/build.ninja"

cmake -Werror=dev -G Ninja -S "${PROJECT_ROOT}" -B "${TEST_ROOT}/download-build" \
    -DBUILD_TEST=OFF \
    -DENABLE_MODULES=authentication \
    -DENABLE_DOWNLOAD_DEPENDENCY=ON >/dev/null
for library in libkrb5 libgssapi_krb5 libcom_err libkrb5support libk5crypto; do
    grep -Eq "^build .*deps/[^ ]+/${library}\\.so.*: CUSTOM_COMMAND" \
        "${TEST_ROOT}/download-build/build.ninja"
done

link_commands=$(ninja -C "${TEST_ROOT}/download-build" -t commands)
install_libdir=$(sed -n 's/^CMAKE_INSTALL_LIBDIR:PATH=//p' \
    "${TEST_ROOT}/download-build/CMakeCache.txt")
[[ -n "${install_libdir}" ]]
for library in libkrb5 libgssapi_krb5 libcom_err libkrb5support libk5crypto; do
    [[ "${link_commands}" == *"deps/${install_libdir}/${library}.so"* ]] || {
        echo "downloaded Kerberos library ${library} is not linked by its exact path" >&2
        exit 1
    }
done
if [[ "${link_commands}" == *"-llibgssapi_krb5"* ||
      "${link_commands}" == *"-llibcom_err"* ||
      "${link_commands}" == *"-llibkrb5support"* ||
      "${link_commands}" == *"-llibk5crypto"* ]]; then
    echo "downloaded Kerberos libraries use invalid -llib... linker names" >&2
    exit 1
fi

echo "native Make tool tests passed"
