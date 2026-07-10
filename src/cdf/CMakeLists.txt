#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

add_library(cdf_obj OBJECT)

if(BUILD_TEST)
  target_compile_definitions(cdf_obj PRIVATE CDF_RAND_TESTING)
endif()

target_include_directories(
  cdf_obj
  PUBLIC
    # this include path will only be used in build tree
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    # PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_DEPENDENCY_INCLUDEDIR}
    ${CMAKE_DEPENDENCY_INCLUDEDIR}/securec)

set(CDF_SOURCE_FILES "")

if(NOT BUILD_TEST)
  # only used in src
  add_compiler_flags("-fuse-ld=gold")
  add_compiler_flags("-Wunused-variable")
  add_compiler_flags("-Wunused-value")
  add_compiler_flags("-Wformat=2")
  add_compiler_flags("-Wfloat-equal")
  #add_compiler_flags("-Wvla")
  #add_compiler_flags("-Wconversion")
  #add_compiler_flags("-Wnon-virtual-dtor")
  add_compiler_flags("-Wshadow")
  add_compiler_flags("-Wtrampolines")
  add_compiler_flags("-Wswitch-default")
  add_compiler_flags("-Wundef")
endif()

add_subdirectory(base)
add_subdirectory(utils)
add_subdirectory(connector)

# 检查是否在要编译的模块列表中
if(ENABLE_ALL_MODULES OR ENABLE_MODULE_CLI_TOOL)
  message(STATUS "Enabling module: cli_tool")
  add_subdirectory(cli)
else()
  message(STATUS "Skipping module: cli_tool")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_AUTHENTICATION)
  message(STATUS "Enabling module: authentication")
  add_subdirectory(modules/authentication)
  target_link_libraries(cdf_obj PUBLIC Dependency::krb5)
else()
  message(STATUS "Skipping module: authentication")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_AUTHORIZATION)
  message(STATUS "Enabling module: authorization")
  add_subdirectory(modules/authorization)
  target_link_libraries(cdf_obj PUBLIC Dependency::rapidjson)
else()
  message(STATUS "Skipping module: authorization")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_CRYPTION)
  message(STATUS "Enabling module: cryption")
  add_subdirectory(modules/cryption)
else()
  message(STATUS "Skipping module: cryption")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_KEY_MANAGEMENT)
  message(STATUS "Enabling module: key_management")
  add_subdirectory(modules/key_management)
  target_link_libraries(cdf_obj PUBLIC Dependency::rapidjson)
else()
  message(STATUS "Skipping module: key_management")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_PSK_MANAGEMENT)
  message(STATUS "Enabling module: psk_management")
  add_subdirectory(modules/psk_management)
else()
  message(STATUS "Skipping module: psk_management")
endif()

if(ENABLE_ALL_MODULES OR ENABLE_MODULE_RAND)
  message(STATUS "Enabling module: rand")
  add_subdirectory(modules/rand)
  target_link_libraries(cdf_obj PUBLIC Dependency::openssl)
else()
  message(STATUS "Skipping module: rand")
endif()

target_sources(cdf_obj PRIVATE ${CDF_SOURCE_FILES})

target_link_libraries(cdf_obj PUBLIC Dependency::secure_c Dependency::openssl# static lib
)

# ----------------------
# Output Libs
# ----------------------

add_library(cdf STATIC)
target_link_libraries(cdf PRIVATE cdf_obj Dependency::openssl)
target_include_directories(
  cdf
  PUBLIC
    # this include path will only be used in build tree
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
    # PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${CMAKE_DEPENDENCY_INCLUDEDIR}
    ${CMAKE_DEPENDENCY_INCLUDEDIR}/securec)
add_library(CDF::cdf ALIAS cdf) # alias

if(ENABLE_SHARED)
  add_library(cdf_shared SHARED)
  target_link_libraries(cdf_shared PRIVATE cdf_obj)
endif()

# if(NOT ENABLE_COVERAGE)
# if(NOT BUILD_HSE_ONLY)
# add_subdirectory(cli)
# endif()
# endif()

# if(BUILD_FUZZ)
# target_link_libraries(cdf PRIVATE Dependency::secodefuzz)
# endif()
