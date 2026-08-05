#!/usr/bin/env bash

#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2026. All rights reserved.
# Confidential Data defensive Framework is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan
# PSL v2. You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY
# KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
#

set -Eeuo pipefail

PROJECT_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." >/dev/null 2>&1 && pwd)
SPEC_FILE="${PROJECT_ROOT_DIR}/scripts/rpm/cdf-crypto.spec"
RPMBUILD_ROOT="${PROJECT_ROOT_DIR}/build/rpmbuild"
RPMBUILD_SOURCE_DIR="${RPMBUILD_ROOT}/SOURCES"
RPMBUILD_SPEC_DIR="${RPMBUILD_ROOT}/SPECS"
PACKAGE_DIR="${PROJECT_ROOT_DIR}/package"
OPENSSL_SOURCE_SHA256="eb1ab04781474360f77c318ab89d8c5a03abc38e63d65a603cabbf1b00a1dc90"
BLAKE3_SOURCE_SHA256="220bd81286e2a0585beac66d41ac3f4c2c33ae8a4e339fc88cf22d5e00514fe9"

log_info() {
    printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

require_tool() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "Error: required tool '$1' was not found" >&2
        exit 1
    }
}

download_source() {
    local name=$1
    local url=$2
    local destination=$3
    local expected_sha256=$4
    local actual_sha256

    log_info "Downloading ${name}"
    curl --fail --location --retry 3 --silent --show-error \
        --proto '=https' --tlsv1.2 --output "${destination}" "${url}"
    read -r actual_sha256 _ < <(sha256sum "${destination}")
    [[ "${actual_sha256}" == "${expected_sha256}" ]] || {
        echo "Error: SHA-256 mismatch for ${name}" >&2
        exit 1
    }
    log_info "Verified ${name}"
}

for tool in curl git rpmbuild rsync sha256sum tar; do
    require_tool "${tool}"
done

[[ -f "${SPEC_FILE}" ]] || {
    echo "Error: RPM spec was not found: ${SPEC_FILE}" >&2
    exit 1
}

PACKAGE_NAME=$(sed -n 's/^Name:[[:space:]]*//p' "${SPEC_FILE}" | head -n 1)
PACKAGE_VERSION=$(sed -n 's/^Version:[[:space:]]*//p' "${SPEC_FILE}" | head -n 1)
[[ -n "${PACKAGE_NAME}" && -n "${PACKAGE_VERSION}" ]] || {
    echo "Error: failed to read Name and Version from ${SPEC_FILE}" >&2
    exit 1
}

SOURCE_BASENAME="${PACKAGE_NAME}-${PACKAGE_VERSION}"
SOURCE_TARBALL="${RPMBUILD_SOURCE_DIR}/${SOURCE_BASENAME}.tar.gz"
SOURCE_CHECKSUM="${RPMBUILD_SOURCE_DIR}/${SOURCE_BASENAME}-sources.SHA256"
OPENSSL_SOURCE_FILENAME=$(sed -n 's/^Source1:[[:space:]]*//p' "${SPEC_FILE}" | head -n 1)
[[ "${OPENSSL_SOURCE_FILENAME}" =~ ^openssl-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz$ ]] || {
    echo "Error: Source1 must be named openssl-<version>.tar.gz" >&2
    exit 1
}
OPENSSL_VERSION=${BASH_REMATCH[1]}
OPENSSL_SOURCE_TARBALL="${RPMBUILD_SOURCE_DIR}/${OPENSSL_SOURCE_FILENAME}"
BLAKE3_SOURCE_FILENAME=$(sed -n 's/^Source2:[[:space:]]*//p' "${SPEC_FILE}" | head -n 1)
[[ "${BLAKE3_SOURCE_FILENAME}" =~ ^blake3-([0-9]+\.[0-9]+\.[0-9]+)\.tar\.gz$ ]] || {
    echo "Error: Source2 must be named blake3-<version>.tar.gz" >&2
    exit 1
}
BLAKE3_VERSION=${BASH_REMATCH[1]}
BLAKE3_SOURCE_TARBALL="${RPMBUILD_SOURCE_DIR}/${BLAKE3_SOURCE_FILENAME}"

log_info "Preparing RPM build directories"
rm -rf "${RPMBUILD_ROOT}" "${PACKAGE_DIR}/rpm" "${PACKAGE_DIR}/srpm"
mkdir -p "${RPMBUILD_SOURCE_DIR}" "${RPMBUILD_SPEC_DIR}" \
    "${RPMBUILD_ROOT}/BUILD" "${RPMBUILD_ROOT}/BUILDROOT"

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/cdf-rpmbuild.XXXXXX")
trap 'rm -rf -- "${TEMP_DIR}"' EXIT
SOURCE_STAGE="${TEMP_DIR}/${SOURCE_BASENAME}"
mkdir -p "${SOURCE_STAGE}"

log_info "Creating ${SOURCE_BASENAME}.tar.gz"
git -C "${PROJECT_ROOT_DIR}" ls-files -z > "${TEMP_DIR}/tracked-files"
rsync -a --from0 --files-from="${TEMP_DIR}/tracked-files" \
    --ignore-missing-args "${PROJECT_ROOT_DIR}/" "${SOURCE_STAGE}/"

tar -C "${TEMP_DIR}" -czf "${SOURCE_TARBALL}" "${SOURCE_BASENAME}"
download_source "OpenSSL ${OPENSSL_VERSION}" \
    "https://www.openssl.org/source/old/3.0/${OPENSSL_SOURCE_FILENAME}" \
    "${OPENSSL_SOURCE_TARBALL}" "${OPENSSL_SOURCE_SHA256}"
download_source "BLAKE3 ${BLAKE3_VERSION}" \
    "https://github.com/BLAKE3-team/BLAKE3/archive/refs/tags/${BLAKE3_VERSION}.tar.gz" \
    "${BLAKE3_SOURCE_TARBALL}" "${BLAKE3_SOURCE_SHA256}"
tar -tzf "${OPENSSL_SOURCE_TARBALL}" >/dev/null
tar -tzf "${BLAKE3_SOURCE_TARBALL}" >/dev/null
log_info "Writing source checksum manifest"
sha256sum "${SOURCE_TARBALL}" "${OPENSSL_SOURCE_TARBALL}" \
    "${BLAKE3_SOURCE_TARBALL}" \
    > "${SOURCE_CHECKSUM}"
cp -f "${SPEC_FILE}" "${RPMBUILD_SPEC_DIR}/"
find "${PROJECT_ROOT_DIR}/scripts/rpm" -maxdepth 1 -type f -name '*.patch' \
    -exec cp -f {} "${RPMBUILD_SOURCE_DIR}/" \;

log_info "Running rpmbuild"
rpmbuild -ba "${RPMBUILD_SPEC_DIR}/$(basename "${SPEC_FILE}")" \
    --define "_sourcedir ${RPMBUILD_SOURCE_DIR}" \
    --define "_specdir ${RPMBUILD_SPEC_DIR}" \
    --define "_srcrpmdir ${PACKAGE_DIR}/srpm" \
    --define "_rpmdir ${PACKAGE_DIR}/rpm" \
    --define "_builddir ${RPMBUILD_ROOT}/BUILD" \
    --define "_buildrootdir ${RPMBUILD_ROOT}/BUILDROOT"

echo "Source archive: ${SOURCE_TARBALL}"
echo "Checksum:       ${SOURCE_CHECKSUM}"
echo "Binary RPMs:    ${PACKAGE_DIR}/rpm"
echo "Source RPM:     ${PACKAGE_DIR}/srpm"
