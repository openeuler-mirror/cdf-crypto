# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

cmake_minimum_required(VERSION 3.14.1)

project(cdf CXX C)

cmake_policy(SET CMP0097 NEW)

# ------------------------------------------------------------------------------
# User Options
# ------------------------------------------------------------------------------

option(BUILD_TEST "Enable/Disable tests" On)
option(BUILD_COVERAGE "Enable/Disable Coverage Report" Off)
option(BUILD_FUZZ "Enable/Disable fuzz" Off)
option(BUILD_ASAN "Enable/Disable Address Sanitier" Off)
option(BUILD_CDF_ONLY "Buld CDF Content Only" Off)
option(ENABLE_DOWNLOAD_DEPENDENCY "Download Dependecies Automatically" Off)

option(ENABLE_SHARED "Build cdf shared lib" On)
# ENABLE_MODULES: Enable specific modules Separate with ";". Supported modules:
# `authentication` `authorization` `cert` `cryption` `cli_tool` `key_management` `rand` `psk_management`
# Build all available modules
set(ENABLE_ALL_MODULES Off)
# Enable module authentication
set(ENABLE_MODULE_AUTHENTICATION Off)
# Enable module authorization
set(ENABLE_MODULE_AUTHORIZATION Off)
# Enable module cryption
set(ENABLE_MODULE_CRYPTION Off)
# Enable module key management
set(ENABLE_MODULE_KEY_MANAGEMENT Off)
# Enable module cert
set(ENABLE_MODULE_CERT Off)
# Enable module cli tool
set(ENABLE_MODULE_CLI_TOOL Off)
# Enable module rand
set(ENABLE_MODULE_RAND Off)
# Enable module psk management
set(ENABLE_MODULE_PSK_MANAGEMENT Off)

set(DOWNLOAD_DIR
    "${PROJECT_SOURCE_DIR}/external"
    CACHE
      STRING
      "Pre-Built Dependency Directory, default to ${PROJECT_SOURCE_DIR}/external"
)

# ------------------------------------------------------------------------------
# Processing User Options
# ------------------------------------------------------------------------------

# 检查ENABLE_DOWNLOAD_DEPENDENCY，首先检查旧选项是否存在，如果存在则将其值赋给新选项
if(DEFINED DOWNLOAD_DEPENDENCY)
  # 发出警告提示选项名称已更改
  message(
    WARNING
      "The option 'DOWNLOAD_DEPENDENCY' is deprecated, please use 'ENABLE_DOWNLOAD_DEPENDENCY' instead."
  )
  # 将旧选项的值赋给新选项
  set(ENABLE_DOWNLOAD_DEPENDENCY
      ${DOWNLOAD_DEPENDENCY}
      CACHE BOOL "Download Dependencies Automatically" FORCE)
endif()

if(DEFINED ENABLE_MODULES)
  message(STATUS "Enable Modules: ${ENABLE_MODULES}")
  foreach(module IN LISTS ENABLE_MODULES)
    string(TOUPPER ${module} module_upper)
    set(ENABLE_MODULE_${module_upper} ON)
  endforeach()
  message(STATUS "Building specific modules: ${ENABLE_MODULES}")
else()
  set(ENABLE_MODULES ALL) # 默认编译所有模块
  message(STATUS "Building all modules (default)")
endif()

# 检查是否是编译所有模块
if("${ENABLE_MODULES}" MATCHES "ALL")
  set(ENABLE_ALL_MODULES ON)
  message(STATUS "Enabling build for ALL modules")
endif()

# Check user options.
if(BUILD_COVERAGE AND NOT BUILD_TEST)
  message(
    WARNING
      "BUILD_COVERAGE has been set to ON, but BUILD_TEST has been set to Off,\
 turn on BUILD_TEST automatically.")
  set(BUILD_TEST On)
endif()

if(BUILD_ASAN AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(
    WARNING
      "BUILD_ASAN has been set to ON, but CMAKE_BUILD_TYPE has not been set to\
 Debug, set CMAKE_BUILD_TYPE=Debug automatically.")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

# Check user options.
if(BUILD_FUZZ AND NOT BUILD_TEST)
  message(
    WARNING
      "BUILD_FUZZ has been set to ON, but BUILD_TEST has been set to Off, turn\
 on BUILD_TEST automatically.")
  set(BUILD_TEST On)
endif()

# Check user options.
if(BUILD_FUZZ AND NOT BUILD_ASAN)
  message(
    WARNING
      "BUILD_FUZZ has been set to ON, but BUILD_ASAN has been set to Off, turn\
 on BUILD_ASAN automatically.")
  set(BUILD_ASAN On)
endif()

# Check user options.
if(BUILD_FUZZ AND NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
  message(
    WARNING
      "BUILD_FUZZ has been set to ON, but CMAKE_BUILD_TYPE has not been set to\
 Debug, set CMAKE_BUILD_TYPE=Debug automatically.")
  set(CMAKE_BUILD_TYPE "Debug")
endif()

if(ENABLE_MODULE_AUTHENTICATION AND NOT ENABLE_MODULE_CRYPTION)
  message(
    WARNING
      "`authentication` has already been set in option `--enable`, `cryption` is not set, automatically adding `cryption`."
  )
  set(ENABLE_MODULE_CRYPTION On)
endif()

if(ENABLE_MODULE_CLI_TOOL AND NOT ENABLE_MODULE_CRYPTION)
  message(
    WARNING
      "`cli_tool` has already been set in option `--enable`, `cryption` is not set, automatically adding `cryption`."
  )
  set(ENABLE_MODULE_CRYPTION On)
endif()

if(ENABLE_MODULE_RAND AND NOT ENABLE_MODULE_CRYPTION)
  message(
    WARNING
      "`rand` has already been set in option `--enable`, `cryption` is not set, automatically adding `cryption`."
  )
  set(ENABLE_MODULE_CRYPTION On)
endif()

if(ENABLE_MODULE_CRYPTION AND NOT ENABLE_MODULE_KEY_MANAGEMENT)
  message(
    WARNING
      "`cryption` has already been set in option `--enable`, `key_management` is not set, automatically adding `key_management`."
  )
  set(ENABLE_MODULE_KEY_MANAGEMENT On)
endif()

if(ENABLE_MODULE_PSK_MANAGEMENT AND NOT ENABLE_MODULE_KEY_MANAGEMENT)
  message(
          WARNING
          "`psk_management` has already been set in option `--enable`, `rand` is not set, automatically adding `key_management`."
  )
  set(ENABLE_MODULE_RAND On)
endif()

if(ENABLE_MODULE_PSK_MANAGEMENT AND NOT ENABLE_MODULE_RAND)
  message(
          WARNING
          "`psk_management` has already been set in option `--enable`, `rand` is not set, automatically adding `rand`."
  )
  set(ENABLE_MODULE_RAND On)
endif()

if(ENABLE_MODULE_CRYPTION AND NOT ENABLE_MODULE_RAND)
  message(
    WARNING
      "`cryption` has already been set in option `--enable`, `rand` is not set, automatically adding `rand`."
  )
  set(ENABLE_MODULE_RAND On)
endif()

# Download dependency setup
include(GNUInstallDirs)

set(DEPENDENCY_INSTALL_PREFIX_NAME deps)
set(CMAKE_DEPENDENCY_INSTALL_PREFIX
    ${CMAKE_BINARY_DIR}/${DEPENDENCY_INSTALL_PREFIX_NAME})
set(CMAKE_DEPENDENCY_INCLUDEDIR
    ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(CMAKE_DEPENDENCY_LIBDIR
    ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})

if(ENABLE_DOWNLOAD_DEPENDENCY)
  # if dependecy is auto downloaded, the source path is in build dir
  set(CMAKE_DEPENDENCY_SRCDIR ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src)
else()
  # if dependecy is pre-downloaded, set denependency source dir to user download dir
  set(CMAKE_DEPENDENCY_SRCDIR ${DOWNLOAD_DIR})
endif()

# If install prefix is not specified, default to install in building folder
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set_property(CACHE CMAKE_INSTALL_PREFIX PROPERTY VALUE ${PROJECT_BINARY_DIR})
endif()

# If build type is not specified, default to debug
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE debug)
endif()

# If cpu type is not specified, default to arm64
if(NOT DEFINED CPU_TYPE)
  set(CPU_TYPE "arm_64")
endif()

# ------------------------------------------------------------------------------
# Processing Different Modes
# ------------------------------------------------------------------------------

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/")
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

include(ImportLib)

if(BUILD_TEST)
  include(CTest)
  include(SetSecureFlags)
  set(BUILD_ASAN On)
  set_secure_flags()
  list(APPEND CMAKE_CTEST_ARGUMENTS "--output-on-failure")
  enable_testing()

endif()

if(BUILD_COVERAGE)
  include(SetupCoverage)
  include(AddCompilerFlags)
  # HACK dsisable some macros under coverage mode
  add_compile_definitions(LCOV_IGNORE)
  setup_coverage()
endif()

# ------------------------------------------------------------------------------
# Compiler and Linker Configuration
# ------------------------------------------------------------------------------

# Load cmake module
include(AddCompilerFlags)

# Set c and cxx standard
set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

# Do not add run time path information
set(CMAKE_SKIP_RPATH TRUE)

# Build position independent code, even for static lib
set(CMAKE_POSITION_INDEPENDENT_CODE On)

# Turn off rpath
set(CMAKE_SKIP_RPATH TRUE)

# Empty cmake's default flags
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_DEBUG "")

# Check and add flags to ${CMAKE_CXX_FLAGS}
add_compiler_flags("-Wall")
add_compiler_flags("-Wextra")
add_compiler_flags("-Werror")

# for huawei compiling standard
add_compiler_flags("-fno-common")
add_compiler_flags("-pipe")

add_compiler_flags(-fPIC) # PIC

# Check and add flags to ${CMAKE_CXX_FLAGS_RELEASE}
add_release_compiler_flags("-fstack-protector-strong") # stack protection
add_release_compiler_flags("-Wl,-z,now") # BIND_NOW
add_release_compiler_flags("-Wl,-z,noexecstack") # NX
add_release_compiler_flags("-ftrapv") # ftrapv
add_release_compiler_flags("-s") # strip
add_release_compiler_flags("-D_FORTIFY_SOURCE=2") # fs
add_release_compiler_flags("-fPIE") # PIE
add_release_compiler_flags("-fPIC") # PIC
add_release_compiler_flags("-Wl,-z,relro") # relro
add_release_compiler_flags("-O2") # use O2 optimization

# Check and add flags to ${CMAKE_CXX_FLAGS_DEBUG}
add_debug_compiler_flags("-g")
# add_debug_compiler_flags("-rdynamic")

# set(CMAKE_C_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  # HUAWEI_SECURE_BUILD_FLAGS (LINKER FLAGS)
  add_link_options("-s")
  if(NOT BUILD_TEST)
    add_link_options("-pie")
  endif()

  # for kmc
  set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS}")
endif()
# CXX flags
# add_compiler_flags("-fuse-ld=gold")
add_compiler_flags("-Winvalid-pch")
add_compiler_flags("-fms-extensions")
add_compiler_flags("-Wunused-variable")
add_compiler_flags("-Wunused-value")
add_compiler_flags("-Wcast-align")
add_compiler_flags("-Winvalid-pch")
add_compiler_flags("-Wcast-qual")
add_compiler_flags("-Wwrite-strings")
add_compiler_flags("-Wdate-time")
add_compiler_flags("-fno-strict-aliasing")
add_compiler_flags("-Wstrict-prototypes")
add_compiler_flags("-Wunused")
add_compiler_flags("-freg-struct-return")
add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wdelete-non-virtual-dtor>)
add_compiler_flags("-fstrong-eval-order")
add_compiler_flags("-Wtrampolines")
add_compiler_flags("-Woverloaded-virtua")

# HACK disabled some warning for dependency dependencies
# add_compiler_flags("-Wno-error=pragmas")
# add_compiler_flags("-Wno-sign-compare")
# add_compiler_flags("-Wno-unused-function")

add_c_compiler_flags("-Wdate-time")
add_c_compiler_flags("-fno-strict-aliasing")
add_c_compiler_flags("-Wstrict-prototypes")
add_c_compiler_flags("-Wunused")
add_c_compiler_flags("-Wfloat-equal")
add_c_compiler_flags("-Wvla")
add_c_compiler_flags("-freg-struct-return")
add_c_compiler_flags("-Wshadow")
add_c_compiler_flags("-Wcast-align")
add_c_compiler_flags("-fstrong-eval-order")
add_c_compiler_flags("-Wtrampolines")
add_c_compiler_flags("-Wstack-usage=8192")

add_link_options("-Wl,-Bsymbolic")
add_link_options("-rdynamic")
add_link_options("-Wl,--no-undefined")

# Make it colorful under ninja-build
if(CMAKE_GENERATOR STREQUAL Ninja)
  add_compiler_flags(-fdiagnostics-color=always)
endif()

if(BUILD_ASAN)
  set(MEMORYCHECK_COMMAND_OPTIONS
      "--error-exitcode=1 --errors-for-leak-kinds=definite --track-origins=yes
--error-limit=no")

  add_compiler_flags(-fno-omit-frame-pointer)
  # add_compiler_flags(-static-libasan) # always use static libasan

  # HACK see:
  # https://github.com/google/sanitizers/issues/856#issuecomment-727254300
  #
  # add_compiler_flags(-fsanitize=address)
  add_link_options(-fno-pie)

  add_custom_target(asan COMMAND ctest -T memcheck)
endif()

if(BUILD_FUZZ)
  # HACK add_compile_options("-fsanitize=address")
  # add_compile_options("-fsanitize-coverage=trace-pc,trace-cmp")
  # add_compiler_flags("-g") add_compiler_flags("-fPIC")
  # add_compiler_flags("-fno-omit-frame-pointer")
  # add_compile_options("-fprofile-arcs") add_compiler_flags("-ftest-coverage")
  # add_compiler_flags("-fstack-protector-strong") add_compiler_flags("-ftrapv")
  # add_compiler_flags("-fPIE") add_compile_options(-fsanitize=address
  # -fsanitize-coverage=trace-pc,trace-cmp -fno-omit-frame-pointer)
  # add_link_options(-fsanitize=address -fsanitize-coverage=trace-pc,trace-cmp
  # -fno-omit-frame-pointer) add_compiler_flags("-fdump-rtl-expand")
  # add_compiler_flags("-O0") link_libraries(asan gcov)
endif()

# If cpu type is not specified, default to arm64
if(NOT DEFINED CPU_TYPE)
  set(CPU_TYPE "arm_64")
endif()

# ------------------------------------------------------------------------------
# CMake Modules and Dependency Dependencies
# ------------------------------------------------------------------------------

get_property(
  cdf_link_options
  DIRECTORY
  PROPERTY LINK_OPTIONS)

message(STATUS "==============================================================")
message(STATUS "User Options and Configurations")
message(STATUS "==============================================================")
message(STATUS "CMake Version             : ${CMAKE_VERSION}")
message(STATUS "Build Type                : ${CMAKE_BUILD_TYPE}")
message(STATUS "CPU Type                  : ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Compiler                  : ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "Compiler Version          : ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "C++ Standard              : ${CMAKE_CXX_STANDARD}")
message(STATUS "Compiler Flags            : \n${CMAKE_CXX_FLAGS}")
message(STATUS "Linker Flags              : \n${cdf_link_options}")
message(STATUS "CMAKE_INSTALL_PREFIX      : ${CMAKE_INSTALL_PREFIX}")
message(STATUS "CMAKE_DEPENDENCY_SRCDIR   : ${CMAKE_DEPENDENCY_SRCDIR}")
message(
  STATUS "(opt) ENABLE_DOWNLOAD_DEPENDENCY : ${ENABLE_DOWNLOAD_DEPENDENCY}")
message(STATUS "(opt) BUILD_TEST          : ${BUILD_TEST}")
message(STATUS "(opt) BUILD_COVERAGE      : ${BUILD_COVERAGE}")
message(STATUS "(opt) BUILD_FUZZ          : ${BUILD_FUZZ}")
message(STATUS "(opt) BUILD_ASAN          : ${BUILD_ASAN}")
message(STATUS "ENABLE_ALL_MODULES          : ${ENABLE_ALL_MODULES}")
message(STATUS "ENABLE_MODULE_AUTHENTICATION: ${ENABLE_MODULE_AUTHENTICATION}")
message(STATUS "ENABLE_MODULE_AUTHORIZATION : ${ENABLE_MODULE_AUTHORIZATION}")
message(STATUS "ENABLE_MODULE_CRYPTION      : ${ENABLE_MODULE_CRYPTION}")
message(STATUS "ENABLE_MODULE_KEY_MANAGEMENT: ${ENABLE_MODULE_KEY_MANAGEMENT}")
message(STATUS "ENABLE_MODULE_CERT          : ${ENABLE_MODULE_CERT}")
message(STATUS "ENABLE_MODULE_CLI_TOOL      : ${ENABLE_MODULE_CLI_TOOL}")
message(STATUS "ENABLE_MODULE_RAND          : ${ENABLE_MODULE_RAND}")
message(STATUS "ENABLE_MODULE_PSK_MANAGEMENT: ${ENABLE_MODULE_PSK_MANAGEMENT}")
message(STATUS "==============================================================")

include(FetchContent)
include(ExternalProject)

set(FETCHCONTENT_BASE_DIR ${CMAKE_DEPENDENCY_INSTALL_PREFIX}/src)

if(BUILD_TEST)
  include(deps/gtest)
endif()

if(BUILD_FUZZ)
  include(deps/secodefuzz)
endif()

include(deps/libboundscheck)

if(ENABLE_ALL_MODULES
   OR ENABLE_MODULE_CRYPTION
   OR ENABLE_MODULE_RAND)
  include(deps/openssl)
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_AUTHENTICATION)
  include(deps/krb5)
endif()


if(ENABLE_ALL_MODULES
   OR ENABLE_MODULE_AUTHORIZATION
   OR ENABLE_MODULE_KEY_MANAGEMENT)
  include(deps/rapidjson)
endif()

# ------------------------------------------------------------------------------
# Project Configuration
# ------------------------------------------------------------------------------

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR})
set(CMAKE_INCLUDE_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_INCLUDEDIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    ${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR})

# Use add_cdf_test_if to add sub-module test
include(AddCDFTestIf)

add_subdirectory(src/cdf)

if(BUILD_TEST)
  add_subdirectory(test)
endif()

add_custom_target(build_install COMMAND make install)
add_custom_target(build_rpm
        COMMAND mkdir -p ${PROJECT_SOURCE_DIR}/package/rpm
        # clean last build
        COMMAND rm -rf ${PROJECT_BINARY_DIR}/build/_CPack_Packages
        COMMAND cpack -G RPM -D CPACK_RPM_USER_BINARY_SPECFILE=${PROJECT_BINARY_DIR}/cdf-crypto.spec
        COMMAND mv *.rpm ${PROJECT_SOURCE_DIR}/package/rpm
        COMMENT "package all files to rpm"
        WORKING_DIRECTORY ${PROJECT_BINARY_DIR})
add_dependencies(build_rpm build_install)

set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_USER_BINARY_SPECFILE ${PROJECT_BINARY_DIR}/cdf-crypto.spec)
set(CPACK_PACKAGE_RELOCATABLE NO)
set(CPACK_RPM_PACKAGE_DIR "${PROJECT_SOURCE_DIR}/package")
# 使用 configure_file() 生成实际的 .spec 文件
configure_file(
        ${PROJECT_SOURCE_DIR}/scripts/rpm/cdf-crypto.spec.in
        ${PROJECT_BINARY_DIR}/cdf-crypto.spec
        @ONLY
)
include(CPack)
