#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
resolver="${repo_root}/cmake/ResolveModules.cmake"

if grep -q '[[:space:]]IN_LIST[[:space:]]' "${resolver}"; then
    echo "ResolveModules.cmake must not use IN_LIST; it runs under CMP0057 OLD on older CMake." >&2
    exit 1
fi

echo "ResolveModules.cmake compatibility checks passed"
