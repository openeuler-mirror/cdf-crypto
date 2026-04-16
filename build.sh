#!/bin/bash

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

###
### build.sh --- build project
###
### Usage:
###     build.sh <target> [-D] [-C] [-t <target>]
###
### Options:
###     <target>        Build target used by Make
###     -h | --help     Show help message
###     -D | --debug    Build debug version
###     -C | --coverage Generate coverage report files
###     -t | --target   Specifying build target, default is `all`
###                     Supported targets:
###                         `all`              build all target in source code
###                         `test`             build all tests in test/ directory
###                         `output`           build output
###                         `cicd_default`     build mode for cicd output only
###                         `cicd_coverage`    build mode for cicd coverage only
###          --enable   Enable specific modules (space-separated). Supported modules: `authentication` `authorization` `cert` `cryption` `cli_tool` `key_management` `rand` `psk_management`

# 函数内命令（后台命令）失败时，立即退出函数
set -o errtrace
# 脚本内命令（前台命令）失败时，立即退出脚本
set -o errexit

build_target='all'
build_type='Release'
enable_coverage='Off'
enable_test='On'
enable_download_dependency='On' # 是否自动下载依赖，否则请手动下载依赖至 project_root/external 文件夹
enable_fuzz='Off'
enable_modules=()  # 初始化编译模块数组
readonly ALLOWED_MODULES=("authentication" "authorization" "cert" "cryption" "cli_tool" "key_management" "rand" "psk_management")

CPU_NUM=$(grep -w processor /proc/cpuinfo|wc -l)

# 版本号
package_version="$(($(date "+%Y") % 100)).$((($(date "+%m") - 1) / 3)).0"
package_release=1

# 获取项目根目录（目前为构建脚本所在目录）
PROJECT_ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

OUTPUT_DIR=${PROJECT_ROOT_DIR}/output

# 脚本出错时捕获错误，并执行 trap_error 处理错误
trap 'trap_error $LINENO ${FUNCNAME} $BASH_LINENO' ERR
# 脚本退出时，恢复到脚本的执行目录
trap 'cd $PROJECT_ROOT_DIR' EXIT

FAILURE='[\033[1;31mFAILED\033[0;39m]'

# 日志打印辅助函数
function log_info() {
    if [ $# -lt 1 ]; then
        return
    fi
    echo "$(date +"%F %T") [INFO] $*" >>"$LOG_FILE"
    echo "$(date +"%F %T") [INFO] $*"
}

# 脚本错误处理
function trap_error() {
    local err=$?
    local line=$1 # LINENO
    [ "$2" != "" ] && local func_stack=$2 # func name
    [ "$3" != "" ] && local line_call_func=$3 # line where func was called
    echo "<---"
    echo "ERROR: line $line - command exited with status: $err"
    if [ "$func_stack" != "" ]; then
        echo -n "   ... Error at function ${func_stack[0]}() "
        if [ "$line_call_func" != "" ]; then
            echo -n "called at line $3"
        fi
        echo
    fi
    echo "--->"
}

function echo_failure() {
    echo -e "CDF project : $FAILURE"
}

function build_default() {
    # 生成分号分隔的模块列表
    local module_list
    if [ ${#enable_modules[@]} -gt 0 ]; then
        module_list=$(IFS=';'; echo "${enable_modules[*]}")
    fi
    cmake ..\
        -DCMAKE_BUILD_TYPE=${build_type}\
        -DBUILD_CDF_ONLY=Off\
        -DBUILD_TEST=${enable_test}\
        -DBUILD_COVERAGE=${enable_coverage}\
        -DENABLE_DOWNLOAD_DEPENDENCY=${enable_download_dependency}\
        -DBUILD_FUZZ=${enable_fuzz}\
        ${module_list:+-DENABLE_MODULES="$module_list"}

    make -j${CPU_NUM}
}

function build_output() {
    # 生成分号分隔的模块列表
    local module_list
    if [ ${#enable_modules[@]} -gt 0 ]; then
        module_list=$(IFS=';'; echo "${enable_modules[*]}")
    fi
    cmake ..\
        -DCMAKE_BUILD_TYPE=${build_type}\
        -DBUILD_TEST=${enable_test}\
        -DBUILD_COVERAGE=${enable_coverage}\
        -DENABLE_DOWNLOAD_DEPENDENCY=${enable_download_dependency}\
        -DBUILD_CDF_ONLY=On\
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/cdf\
        ${module_list:+-DENABLE_MODULES="$module_list"}

    make -j${CPU_NUM}
    make install

    process_output
}

function build_rpm() {
    cmake .. \
        -DCMAKE_BUILD_TYPE=${build_type} \
        -DBUILD_TEST=${enable_test} \
        -DENABLE_COVERAGE=${enable_coverage} \
        -DENABLE_DOWNLOAD_DEPENDENCY=${enable_download_dependency}\
        -DBUILD_CDF_ONLY=On\
        -DCMAKE_INSTALL_PREFIX=${OUTPUT_DIR}/cdf\
        -DRPM_PACKAGE_VERSION="${package_version}" \
        -DRPM_PACKAGE_RELEASE="${package_release}"

    make build_"${build_target}" -j${CPU_NUM}
    process_output
}

function process_output() {
    # 修改目录文件权限
    find ${OUTPUT_DIR} -type d -exec chmod 750 {} \;
    find ${OUTPUT_DIR} -name "*.h" -type f -exec chmod 440 {} \;
    find ${OUTPUT_DIR} -name "*.so" -type f -exec chmod 550 {} \;
    # 仅在编译所有模块或编译cli_tool时才配置config权限
    if [[ ${#enable_modules[@]} -eq 0 || " ${enable_modules[*]} " =~ " cli_tool " ]]; then
        chmod 550 ${OUTPUT_DIR}/cdf/bin/crypto_tool
        chmod -R 750 ${OUTPUT_DIR}/cdf/config
        chmod 640 ${OUTPUT_DIR}/cdf/config/crypto_tool_config.json
    fi
}

function run_test() {
    if [[ "${enable_test}" == 'On' ]]; then
        ctest --output-junit test_results.xml --output-on-failure --test-output-size-passed 0 --test-output-size-failed 0
    fi
    if [[ "${enable_coverage}" == 'On' ]]; then
        make coverage
    fi
}

# 执行 CMake 构建
function build_cmake() {

    if [[ "${enable_clean}" == 'On' ]]; then
        clean ${build_target}
    fi

    log_info "***** start build_cmake *****"

    pushd build
    log_info "building target ${build_target}."
    if [[ "${build_target}" == 'all' ]]; then
        build_default
    fi

    if [[ "${build_target}" == 'test' ]]; then
        enable_test='On' # enable test
        enable_download_dependency='Off'
        build_default
        run_test
    fi

    if [[ "${build_target}" == 'output' ]]; then
        build_type='Release' # always release
        enable_test='Off' # alwasy disable test
        enable_coverage='Off' # alwasy disable coverage
        build_output
    fi

    if [[ "${build_target}" == 'cicd_default' ]]; then
        build_type='Release'
        enable_test='Off'
        enable_coverage='Off'
        enable_download_dependency='Off'
        build_output
    fi

    if [[ "${build_target}" == 'rpm' ]]; then
        build_type='Release'
        enable_test='Off'
        enable_coverage='Off'
        build_rpm
    fi

    if [[ "${build_target}" == 'cicd_coverage' ]]; then
        build_type='Release'
        enable_test='On'
        enable_coverage='On'
        enable_download_dependency='Off'
        build_default
        run_test
    fi

    if [[ "${build_target}" == 'fuzz' ]]; then
        build_type='Debug'
        enable_test='On'
        enable_coverage='Off'
        enable_download_dependency='Off'
        enable_fuzz='On'
        build_default
    fi

    local ret=$?
    popd

    if [ $ret -ne 0 ]; then
        log_info "build_cmake failed"
        echo_failure
        exit 1
    fi
}

# 解析 help 信息并打印，help 信息放在文件头
# 注意：脚本内其他地方不要以 ### 开头进行注释
function help() {
    sed -rn 's/^### ?//;T;p;' "$0"
}

# 脚本参数解析
function parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
        -h | --help)
            help
            exit
            ;;
        -D | --debug)
            build_type='Debug'
            shift
            ;;
        -t | --target)
            if [[ $# -gt 1 && "$2" != "-"* ]]; then
                build_target="$2"
                shift 2
            else
                log_info "Error: Argument required after -t|--target."
                exit 1
            fi
            ;;
        -C | --coverage)
            enable_coverage='On'
            shift
            ;;
        -c | --clean)
            clean   # 清理构建目录
            shift
            ;;
        --enable)
            shift  # 跳过 --enable
            # 处理模块参数
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                module="$1"
                # 校验模块名称
                if ! [[ " ${ALLOWED_MODULES[*]} " =~ " ${module} " ]]; then
                    echo "Error: Invalid module '$module'. Allowed: ${ALLOWED_MODULES[*]}"
                    exit 1
                fi
                # 防止重复
                if [[ " ${enable_modules[*]} " =~ " ${module} " ]]; then
                    echo "Error: Module '$module' already specified"
                    exit 1
                fi
                enable_modules+=("$module")
                shift
            done
            # 检查至少添加了一个模块
            if [ ${#enable_modules[@]} -eq 0 ]; then
                echo "Error: No modules specified after --enable"
                exit 1
            fi
            ;;
        *)
            [ "$1" != "" ] &&build_target="$1"
            shift
            ;;
        esac
    done
}

function clean() {
    local target_dirs=()
    case "$1" in
        "3rdparty")
            target_dirs+=("${PROJECT_ROOT_DIR}/deps")
            ;;
        "package")
            target_dirs+=("${PROJECT_ROOT_DIR}/build")
            target_dirs+=("${PROJECT_ROOT_DIR}/output")
            ;;
        *)
            target_dirs+=("${PROJECT_ROOT_DIR}/build")
            ;;
    esac

    for target_dir in "${target_dirs[@]}"; do
        if [ ! -d "$target_dir" ]; then
            echo "Warning: Directory '$target_dir' does not exist."
        else
            rm -rf "$target_dir"
            echo "Directory '$target_dir' has been cleaned."
        fi
    done

    if [[ ! -d "${PROJECT_ROOT_DIR}/build" ]]; then
        mkdir -p "${PROJECT_ROOT_DIR}/build"
        echo "Directory 'build' has been recreated."
    fi
}

echo $(date +"[%Y-%m-%d %H:%M]"): "$0" "$@"
START_TIME=$(date +%s.%N)

PROJECT_BUILD_DIR=$PROJECT_ROOT_DIR/build
LOG_FILE=$PROJECT_BUILD_DIR/build.log
cd "${PROJECT_ROOT_DIR}"

[ ! -d "${PROJECT_ROOT_DIR}/build" ] && mkdir -p ${PROJECT_ROOT_DIR}/build

parse_args "$@" # 解析脚本参数
build_cmake # 执行 CMake 构建

END_TIME=$(date +%s.%N)
EXEC_TIME=$(echo "scale=3; ($END_TIME - $START_TIME) / 1" | bc)
echo -e $(date +"[%Y-%m-%d %H:%M]"): "\033[32m" Build complated in "$EXEC_TIME"s '\033[0m'
