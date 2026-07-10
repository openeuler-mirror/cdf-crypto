#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

add_executable(
  crypto_tool
  ${CMAKE_CURRENT_LIST_DIR}/cmd.cpp
  ${CMAKE_CURRENT_LIST_DIR}/config_handler.cpp
  ${CMAKE_CURRENT_LIST_DIR}/cryption_tool.cpp
  ${CMAKE_CURRENT_LIST_DIR}/kmc_cmd.cpp)

target_compile_options(crypto_tool PRIVATE -fvisibility=hidden)

target_link_libraries(crypto_tool PUBLIC CDF::cdf Dependency::secure_c)

# Add -pie flag for security (only for executable, not for shared libraries)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  target_link_options(crypto_tool PRIVATE -pie)
endif()

target_include_directories(
  crypto_tool
  PRIVATE ${CMAKE_DEPENDENCY_INCLUDEDIR}
          "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
          "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

# 创建config目录
file(MAKE_DIRECTORY ${CMAKE_INSTALL_PREFIX}/config)

# 复制crypto_tool_config文件
file(COPY ${CMAKE_SOURCE_DIR}/config/crypto_tool_config.json
        DESTINATION ${CMAKE_INSTALL_PREFIX}/config)
