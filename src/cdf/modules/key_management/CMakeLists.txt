# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES}
                          ${CMAKE_CURRENT_LIST_DIR}/key_manager_factory.cpp)

add_subdirectory(openbao)
add_subdirectory(vault)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/define.h
        ${CMAKE_CURRENT_LIST_DIR}/key_manager_factory.h
        ${CMAKE_CURRENT_LIST_DIR}/key_manager.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/key_management)
