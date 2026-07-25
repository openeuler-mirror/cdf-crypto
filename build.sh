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

PROJECT_ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)

COMMAND=build
PACKAGE_TYPE=
CLEAN_SCOPE=build
PROFILE=release
PROFILE_SET=OFF
MODULES=ALL
FETCH_DEPS=OFF
WITH_TESTS=OFF
WITH_TESTS_SET=OFF
JOBS=
INSTALL_PREFIX=
PREFIX_SET=OFF
ENABLE_SHARED=ON

BUILD_TEST=OFF
BUILD_COVERAGE=OFF
BUILD_ASAN=OFF
BUILD_FUZZ=OFF
CMAKE_BUILD_TYPE=Release
BUILD_DIR=

readonly SUPPORTED_MODULES=(
    authentication
    authorization
    cryption
    cli_tool
    key_management
    rand
    psk_management
)

usage() {
    cat <<'EOF'
Usage:
  bash build.sh [command] [options]

Commands:
  build                 Build product targets (default command)
  test                  Build and run CTest tests
  coverage              Build, test, and generate a coverage report
  install               Build and install to a staging prefix
  package rpm           Build and create an RPM package
  fuzz                   Build fuzz-instrumented targets
  clean [scope]         Remove generated directories
  help                  Show this help

Clean scopes:
  build                 Remove build/ (default scope)
  output                Remove output/
  package               Remove package/
  all                   Remove build/, output/, and package/

Options:
  --profile <name>      debug, release, or asan (default: release)
  --modules <a,b,...>   Build selected modules and required dependencies
  --fetch-deps          Allow automatic dependency downloads
  --with-tests          Build test binaries without running them (build only)
  --jobs <n>            Parallel build jobs (default: detected CPU count)
  --prefix <path>       Install staging prefix (install only; default: output/cdf)
  --no-shared           Do not build the shared CDF library
  -h, --help            Show this help

Examples:
  bash build.sh
  bash build.sh build --profile debug --modules rand,authorization
  bash build.sh test --modules rand
  bash build.sh coverage
  bash build.sh install --fetch-deps
  bash build.sh package rpm --fetch-deps
  bash build.sh clean all
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

is_supported_module() {
    local requested=$1
    local module
    for module in "${SUPPORTED_MODULES[@]}"; do
        if [[ "${requested}" == "${module}" ]]; then
            return 0
        fi
    done
    return 1
}

parse_modules() {
    local value=$1
    [[ -n "${value}" ]] || die "--modules requires at least one module"

    local raw_modules=()
    IFS=',' read -r -a raw_modules <<<"${value}"
    local selected=()
    local module existing
    for module in "${raw_modules[@]}"; do
        [[ -n "${module}" ]] || die "--modules contains an empty module name"
        is_supported_module "${module}" ||
            die "Unknown module '${module}'. Supported modules: ${SUPPORTED_MODULES[*]}"
        for existing in "${selected[@]}"; do
            [[ "${existing}" != "${module}" ]] || die "Duplicate module '${module}'"
        done
        selected+=("${module}")
    done
    MODULES=$(IFS=';'; echo "${selected[*]}")
}

require_value() {
    local option=$1
    local remaining=$2
    local value=${3-}
    [[ ${remaining} -ge 2 && -n "${value}" && "${value}" != -* ]] ||
        die "${option} requires a value"
}

parse_args() {
    if [[ $# -gt 0 && "$1" != -* ]]; then
        COMMAND=$1
        shift
    fi

    case "${COMMAND}" in
        build | test | coverage | install | fuzz | help)
            ;;
        package)
            [[ $# -gt 0 ]] || die "package requires a package type; supported: rpm"
            PACKAGE_TYPE=$1
            shift
            [[ "${PACKAGE_TYPE}" == "rpm" ]] ||
                die "Unknown package type '${PACKAGE_TYPE}'; supported: rpm"
            ;;
        clean)
            if [[ $# -gt 0 && "$1" != -* ]]; then
                CLEAN_SCOPE=$1
                shift
            fi
            ;;
        *)
            die "Unknown command '${COMMAND}'. Run 'bash build.sh help' for usage."
            ;;
    esac

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h | --help)
                COMMAND=help
                shift
                ;;
            --profile)
                require_value "$1" "$#" "${2-}"
                PROFILE=$2
                PROFILE_SET=ON
                shift 2
                ;;
            --modules)
                require_value "$1" "$#" "${2-}"
                parse_modules "$2"
                shift 2
                ;;
            --fetch-deps)
                FETCH_DEPS=ON
                shift
                ;;
            --with-tests)
                WITH_TESTS=ON
                WITH_TESTS_SET=ON
                shift
                ;;
            --jobs)
                require_value "$1" "$#" "${2-}"
                JOBS=$2
                shift 2
                ;;
            --prefix)
                require_value "$1" "$#" "${2-}"
                INSTALL_PREFIX=$2
                PREFIX_SET=ON
                shift 2
                ;;
            --no-shared)
                ENABLE_SHARED=OFF
                shift
                ;;
            *)
                die "Unknown option '$1'. Run 'bash build.sh help' for usage."
                ;;
        esac
    done
}

validate_options() {
    if [[ -n "${JOBS}" && ! "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
        die "--jobs must be a positive integer"
    fi

    case "${PROFILE}" in
        debug | release | asan)
            ;;
        *)
            die "Unknown profile '${PROFILE}'; supported: debug, release, asan"
            ;;
    esac

    if [[ "${COMMAND}" == "coverage" || "${COMMAND}" == "fuzz" ||
          "${COMMAND}" == "package" ]]; then
        [[ "${PROFILE_SET}" == "OFF" ]] || die "${COMMAND} does not accept --profile"
    fi
    if [[ "${COMMAND}" != "build" ]]; then
        [[ "${WITH_TESTS_SET}" == "OFF" ]] || die "${COMMAND} does not accept --with-tests"
    fi
    if [[ "${COMMAND}" != "install" ]]; then
        [[ "${PREFIX_SET}" == "OFF" ]] || die "${COMMAND} does not accept --prefix"
    fi

    if [[ "${COMMAND}" == "clean" || "${COMMAND}" == "help" ]]; then
        [[ "${PROFILE_SET}" == "OFF" ]] || die "${COMMAND} does not accept --profile"
        [[ "${MODULES}" == "ALL" ]] || die "${COMMAND} does not accept --modules"
        [[ "${FETCH_DEPS}" == "OFF" ]] || die "${COMMAND} does not accept --fetch-deps"
        [[ -z "${JOBS}" ]] || die "${COMMAND} does not accept --jobs"
        [[ "${ENABLE_SHARED}" == "ON" ]] || die "${COMMAND} does not accept --no-shared"
    fi

    if [[ "${COMMAND}" == "clean" ]]; then
        case "${CLEAN_SCOPE}" in
            build | output | package | all)
                ;;
            *)
                die "Unknown clean scope '${CLEAN_SCOPE}'; supported: build, output, package, all"
                ;;
        esac
    fi

    if [[ "${COMMAND}" == "package" && "${MODULES}" != "ALL" ]]; then
        echo "Warning: partial-module RPMs currently share the cdf-crypto package identity; do not install them alongside a full-module RPM." >&2
    fi
}

require_ctest_junit_support() {
    if ! command -v ctest >/dev/null 2>&1; then
        die "CTest is required for command '${COMMAND}'"
    fi

    local version_output
    version_output=$(ctest --version 2>/dev/null) ||
        die "Unable to determine the CTest version for command '${COMMAND}'"

    local version
    version=$(sed -n '1{s/^ctest version //p;q;}' <<<"${version_output}")
    if [[ ! "${version}" =~ ^([0-9]+)\.([0-9]+)(\.[0-9]+)?([-.+].*)?$ ]]; then
        die "Unable to parse CTest version '${version}' for command '${COMMAND}'"
    fi

    local major=${BASH_REMATCH[1]}
    local minor=${BASH_REMATCH[2]}
    if ((major < 3 || (major == 3 && minor < 21))); then
        die "CTest 3.21 or newer is required to generate JUnit XML; found ${version}"
    fi
}

detect_jobs() {
    if [[ -n "${JOBS}" ]]; then
        return
    fi
    JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)
    if [[ ! "${JOBS}" =~ ^[1-9][0-9]*$ ]]; then
        JOBS=1
    fi
}

select_profile() {
    case "${COMMAND}" in
        coverage)
            PROFILE=coverage
            CMAKE_BUILD_TYPE=Debug
            BUILD_TEST=ON
            BUILD_COVERAGE=ON
            ;;
        fuzz)
            PROFILE=fuzz
            CMAKE_BUILD_TYPE=Debug
            BUILD_TEST=ON
            BUILD_ASAN=ON
            BUILD_FUZZ=ON
            ;;
        package)
            PROFILE=release
            CMAKE_BUILD_TYPE=Release
            ;;
        *)
            case "${PROFILE}" in
                debug)
                    CMAKE_BUILD_TYPE=Debug
                    ;;
                release)
                    CMAKE_BUILD_TYPE=Release
                    ;;
                asan)
                    CMAKE_BUILD_TYPE=Debug
                    BUILD_ASAN=ON
                    ;;
            esac
            ;;
    esac

    if [[ "${COMMAND}" == "test" || "${WITH_TESTS}" == "ON" ]]; then
        BUILD_TEST=ON
    fi

    BUILD_DIR="${PROJECT_ROOT_DIR}/build/${PROFILE}"
    if [[ -z "${INSTALL_PREFIX}" ]]; then
        INSTALL_PREFIX="${PROJECT_ROOT_DIR}/output/cdf"
    elif [[ "${INSTALL_PREFIX}" != /* ]]; then
        INSTALL_PREFIX="${PROJECT_ROOT_DIR}/${INSTALL_PREFIX}"
    fi
}

print_configuration() {
    cat <<EOF
Command            : ${COMMAND}${PACKAGE_TYPE:+ ${PACKAGE_TYPE}}
Profile            : ${PROFILE}
Build directory    : ${BUILD_DIR}
Install prefix     : ${INSTALL_PREFIX}
Modules            : ${MODULES}
Download dependency: ${FETCH_DEPS}
Build tests        : ${BUILD_TEST}
Build shared       : ${ENABLE_SHARED}
Parallel jobs      : ${JOBS}
EOF
}

prepare_install_prefix() {
    if [[ "${PREFIX_SET}" == "OFF" &&
          ("${COMMAND}" == "install" || "${COMMAND}" == "package") ]]; then
        local default_prefix="${PROJECT_ROOT_DIR}/output/cdf"
        [[ "${INSTALL_PREFIX}" == "${default_prefix}" ]] ||
            die "Refusing to clean an unexpected install prefix '${INSTALL_PREFIX}'"
        rm -rf -- "${default_prefix}"
    fi
}

prepare_build_directory() {
    if [[ "${COMMAND}" != "coverage" ]]; then
        return
    fi

    local coverage_dir="${PROJECT_ROOT_DIR}/build/coverage"
    [[ "${BUILD_DIR}" == "${coverage_dir}" ]] ||
        die "Refusing to clean an unexpected coverage directory '${BUILD_DIR}'"
    rm -rf -- "${coverage_dir}"
}

configure_project() {
    cmake -S "${PROJECT_ROOT_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_BUILD_TYPE="${CMAKE_BUILD_TYPE}" \
        -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}" \
        -DBUILD_TEST="${BUILD_TEST}" \
        -DBUILD_COVERAGE="${BUILD_COVERAGE}" \
        -DBUILD_ASAN="${BUILD_ASAN}" \
        -DBUILD_FUZZ="${BUILD_FUZZ}" \
        -DENABLE_SHARED="${ENABLE_SHARED}" \
        -DENABLE_DOWNLOAD_DEPENDENCY="${FETCH_DEPS}" \
        -DENABLE_ALL_MODULES=OFF \
        -DENABLE_MODULE_AUTHENTICATION=OFF \
        -DENABLE_MODULE_AUTHORIZATION=OFF \
        -DENABLE_MODULE_CRYPTION=OFF \
        -DENABLE_MODULE_CLI_TOOL=OFF \
        -DENABLE_MODULE_KEY_MANAGEMENT=OFF \
        -DENABLE_MODULE_RAND=OFF \
        -DENABLE_MODULE_PSK_MANAGEMENT=OFF \
        -DENABLE_MODULES="${MODULES}"
}

validate_output_subdirectory() {
    local name=$1
    local value=$2
    [[ -n "${value}" && "${value}" != /* && "${value}" != "." &&
       "${value}" != ".." && "${value}" != ../* &&
       "${value}" != */../* && "${value}" != */.. ]] ||
        die "CMake reported an unsafe ${name} value '${value}'"
}

prepare_product_output_directories() {
    local cache_file="${BUILD_DIR}/CMakeCache.txt"
    [[ -f "${cache_file}" ]] ||
        die "CMake configuration did not create '${cache_file}'"

    local bindir libdir
    bindir=$(sed -n 's/^CMAKE_INSTALL_BINDIR:PATH=//p' "${cache_file}")
    libdir=$(sed -n 's/^CMAKE_INSTALL_LIBDIR:PATH=//p' "${cache_file}")
    validate_output_subdirectory CMAKE_INSTALL_BINDIR "${bindir}"
    validate_output_subdirectory CMAKE_INSTALL_LIBDIR "${libdir}"

    # CMake does not remove files produced by targets disabled on a later
    # reconfigure. Remove only final product directories; object files and
    # per-profile dependency builds remain available for incremental builds.
    rm -rf -- "${BUILD_DIR}/${bindir}" "${BUILD_DIR}/${libdir}"
    mkdir -p "${BUILD_DIR}/${bindir}" "${BUILD_DIR}/${libdir}"
}

build_project() {
    cmake --build "${BUILD_DIR}" --config "${CMAKE_BUILD_TYPE}" \
        --parallel "${JOBS}"
}

run_ctest() {
    local report_directory="${BUILD_DIR}/Testing"
    local report_path="${report_directory}/test_results.xml"
    local report_relative_path="Testing/test_results.xml"

    mkdir -p "${report_directory}"
    rm -f -- "${report_path}"

    local ctest_status=0
    (cd "${BUILD_DIR}" &&
        ctest -C "${CMAKE_BUILD_TYPE}" --output-on-failure \
            --output-junit "${report_relative_path}") || ctest_status=$?

    [[ -s "${report_path}" ]] ||
        die "CTest did not produce a non-empty JUnit report at '${report_path}'"
    return "${ctest_status}"
}

install_project() {
    cmake --build "${BUILD_DIR}" --target install \
        --config "${CMAKE_BUILD_TYPE}" --parallel "${JOBS}"
}

package_rpm() {
    local package_dir="${PROJECT_ROOT_DIR}/package/rpm"
    local cpack_output_dir="${BUILD_DIR}/package-output"

    [[ "${package_dir}" == "${PROJECT_ROOT_DIR}/package/rpm" ]] ||
        die "Refusing to replace an unexpected package directory '${package_dir}'"
    [[ "${cpack_output_dir}" == "${BUILD_DIR}/package-output" ]] ||
        die "Refusing to replace an unexpected CPack output directory '${cpack_output_dir}'"

    rm -rf -- "${package_dir}" "${cpack_output_dir}"
    mkdir -p "${package_dir}"
    cpack --config "${BUILD_DIR}/CPackConfig.cmake" \
        -C "${CMAKE_BUILD_TYPE}" -G RPM -B "${cpack_output_dir}"

    local rpm_files=()
    local rpm_file
    while IFS= read -r -d '' rpm_file; do
        rpm_files+=("${rpm_file}")
    done < <(find "${cpack_output_dir}" -type f -name '*.rpm' -print0)

    [[ ${#rpm_files[@]} -gt 0 ]] ||
        die "CPack completed without producing an RPM below '${cpack_output_dir}'"

    for rpm_file in "${rpm_files[@]}"; do
        mv -f "${rpm_file}" "${package_dir}/"
    done
}

clean_generated() {
    local scope=$1
    local paths=()
    case "${scope}" in
        build)
            paths=("${PROJECT_ROOT_DIR}/build")
            ;;
        output)
            paths=("${PROJECT_ROOT_DIR}/output")
            ;;
        package)
            paths=("${PROJECT_ROOT_DIR}/package")
            ;;
        all)
            paths=(
                "${PROJECT_ROOT_DIR}/build"
                "${PROJECT_ROOT_DIR}/output"
                "${PROJECT_ROOT_DIR}/package"
            )
            ;;
    esac

    local path
    for path in "${paths[@]}"; do
        if [[ -e "${path}" ]]; then
            rm -rf -- "${path}"
            echo "Removed ${path}"
        else
            echo "Already clean: ${path}"
        fi
    done
}

main() {
    parse_args "$@"
    validate_options

    if [[ "${COMMAND}" == "help" ]]; then
        usage
        return
    fi
    if [[ "${COMMAND}" == "clean" ]]; then
        clean_generated "${CLEAN_SCOPE}"
        return
    fi

    if [[ "${COMMAND}" == "test" || "${COMMAND}" == "coverage" ]]; then
        require_ctest_junit_support
    fi

    detect_jobs
    select_profile
    print_configuration
    prepare_install_prefix
    prepare_build_directory
    configure_project
    prepare_product_output_directories
    build_project

    case "${COMMAND}" in
        test)
            run_ctest
            ;;
        coverage)
            run_ctest
            cmake --build "${BUILD_DIR}" --target coverage \
                --config "${CMAKE_BUILD_TYPE}" --parallel "${JOBS}"
            ;;
        install)
            install_project
            ;;
        package)
            install_project
            package_rpm
            ;;
    esac
}

main "$@"
