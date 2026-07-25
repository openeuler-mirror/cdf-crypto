#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD_DIR=$(mktemp -d /tmp/cdf-packaging-config.XXXXXX)
trap 'rm -rf "${BUILD_DIR}"' EXIT

cmake -S "${PROJECT_ROOT}" -B "${BUILD_DIR}" \
    -DBUILD_TEST=OFF \
    -DENABLE_MODULES=authorization \
    -DENABLE_DOWNLOAD_DEPENDENCY=OFF >/dev/null

[[ -f "${BUILD_DIR}/CPackConfig.cmake" ]]
[[ -f "${BUILD_DIR}/cdf-crypto.spec" ]]

spec_file="${BUILD_DIR}/cdf-crypto.spec"
project_version=$(sed -n 's/^CMAKE_PROJECT_VERSION:STATIC=//p' \
    "${BUILD_DIR}/CMakeCache.txt")
install_bindir=$(sed -n 's/^CMAKE_INSTALL_BINDIR:PATH=//p' \
    "${BUILD_DIR}/CMakeCache.txt")
install_includedir=$(sed -n 's/^CMAKE_INSTALL_INCLUDEDIR:PATH=//p' \
    "${BUILD_DIR}/CMakeCache.txt")
install_libdir=$(sed -n 's/^CMAKE_INSTALL_LIBDIR:PATH=//p' \
    "${BUILD_DIR}/CMakeCache.txt")
[[ -n "${project_version}" && -n "${install_bindir}" &&
   -n "${install_includedir}" && -n "${install_libdir}" ]]
grep -Fq "Version:        ${project_version}" "${spec_file}"
grep -Fq "%define cdf_cmake_bindir ${install_bindir}" "${spec_file}"
grep -Fq "%define cdf_cmake_includedir ${install_includedir}" "${spec_file}"
grep -Fq "%define cdf_cmake_libdir ${install_libdir}" "${spec_file}"
grep -Fq "%define cdf_cpack_stage ${BUILD_DIR}/cpack-staging" "${spec_file}"
[[ -f "${BUILD_DIR}/StageCPackInstall.cmake" ]]
if grep -q 'output/cdf\|cdf_staging_prefix\|/lib64' "${spec_file}"; then
    echo "RPM spec still hard-codes a staging or library directory" >&2
    exit 1
fi
grep -q '^%files -f ' "${spec_file}"
if grep -q 'modules/authentication/jwt/define.h' "${spec_file}"; then
    echo "RPM file list still hard-codes module artifacts" >&2
    exit 1
fi
if grep -Eq 'chmod[[:space:]]+.*[ug]\+s|%attr\([[:space:]]*[2467][0-7]{3}' \
    "${spec_file}"; then
    echo "RPM spec requests a setuid/setgid file mode" >&2
    exit 1
fi

# The manifest may own the three private cdf trees, but never their shared
# system parents.  Match the manifest-generating commands rather than RPM
# metadata such as the destination used by mkdir/cp.
grep -q '%{buildroot}%{_bindir}/cdf' "${spec_file}"
grep -q '%{buildroot}%{_includedir}/cdf' "${spec_file}"
grep -q '%{buildroot}%{_libdir}/cdf' "${spec_file}"
if grep -Eq 'find[[:space:]]+"?%\{buildroot\}"?([[:space:]]|$)|owned_root.*%\{buildroot\}([[:space:]\\]|$)' \
    "${spec_file}"; then
    echo "RPM manifest enumerates the complete buildroot" >&2
    exit 1
fi

target_help=$(cmake --build "${BUILD_DIR}" --target help)
if [[ "${target_help}" == *"build_install"* ||
      "${target_help}" == *"build_rpm"* ]]; then
    echo "legacy packaging helper targets are still present" >&2
    exit 1
fi

echo "packaging configuration tests passed"
