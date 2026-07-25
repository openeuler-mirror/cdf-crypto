#!/usr/bin/env bash

set -Eeuo pipefail

for tool in cmake cpack rpmbuild rpm; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "SKIP: ${tool} is required for the RPM integration test" >&2
        exit 77
    fi
done

PROJECT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-rpm-package.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT
SHADOW_ROOT="${TEST_ROOT}/project"

mkdir -p "${SHADOW_ROOT}"
cp "${PROJECT_ROOT}/build.sh" "${SHADOW_ROOT}/build.sh"
for path in CMakeLists.txt cmake config scripts src; do
    cp -a "${PROJECT_ROOT}/${path}" "${SHADOW_ROOT}/${path}"
done
ln -s "${PROJECT_ROOT}/external" "${SHADOW_ROOT}/external"

bash "${SHADOW_ROOT}/build.sh" package rpm \
    --modules authorization --jobs 2

rpm_file=$(find "${SHADOW_ROOT}/package/rpm" -maxdepth 1 \
    -type f -name '*.rpm' -print -quit)
[[ -n "${rpm_file}" ]] || {
    echo "RPM package was not generated" >&2
    exit 1
}

# Direct CPack must consume its own temporary install tree rather than the
# build.sh staging prefix.
rm -rf -- "${SHADOW_ROOT}/output"
direct_cpack_dir="${SHADOW_ROOT}/build/direct-cpack-output"
cpack --config "${SHADOW_ROOT}/build/release/CPackConfig.cmake" \
    -G RPM -B "${direct_cpack_dir}"
rpm_file=$(find "${direct_cpack_dir}" -type f -name '*.rpm' -print -quit)
[[ -n "${rpm_file}" ]] || {
    echo "Direct CPack did not generate an RPM" >&2
    exit 1
}

package_files=$(rpm -qpl "${rpm_file}")
if grep -Eq '^/usr$|^/usr/bin$|^/usr/include$|^/usr/lib$|^/usr/lib64$' \
    <<<"${package_files}"; then
    echo "RPM owns a shared system parent directory" >&2
    exit 1
fi

grep -Eq '^/usr/lib(64)?/cdf/libcdf\.a$' <<<"${package_files}"
grep -Eq '^/usr/lib(64)?/cdf/libcdf_shared\.so$' <<<"${package_files}"
grep -q '^/usr/include/cdf/modules/authorization/' <<<"${package_files}"
if grep -q '/modules/rand/' <<<"${package_files}"; then
    echo "RPM contains an unselected module" >&2
    exit 1
fi

echo "RPM package integration test passed"
