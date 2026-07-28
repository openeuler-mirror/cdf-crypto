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
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/cdf-copy-worktree.XXXXXX")
trap 'rm -rf -- "${TEST_ROOT}"' EXIT
SOURCE_DIR="${TEST_ROOT}/source"
DESTINATION_DIR="${TEST_ROOT}/destination"

mkdir -p "${SOURCE_DIR}"
git -C "${SOURCE_DIR}" init -q
printf '%s\n' generated.txt >"${SOURCE_DIR}/.gitignore"
printf '%s\n' tracked >"${SOURCE_DIR}/tracked.txt"
git -C "${SOURCE_DIR}" add .gitignore tracked.txt
git -C "${SOURCE_DIR}" \
    -c user.name=CDF -c user.email=cdf@example.invalid \
    commit -qm "test source"
printf '%s\n' stale >"${SOURCE_DIR}/generated.txt"

cmake -DSOURCE_DIR="${SOURCE_DIR}" \
    -DDESTINATION_DIR="${DESTINATION_DIR}" \
    -P "${PROJECT_ROOT}/cmake/CopyGitWorktree.cmake"

[[ -f "${DESTINATION_DIR}/tracked.txt" ]]
[[ ! -e "${DESTINATION_DIR}/generated.txt" ]] || {
    echo "ignored build residue was copied into the dependency snapshot" >&2
    exit 1
}

echo "Git worktree copy test passed"
