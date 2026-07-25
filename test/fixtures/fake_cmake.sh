#!/usr/bin/env bash

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
