# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES}
                          ${CMAKE_CURRENT_LIST_DIR}/psk.cpp
                          ${CMAKE_CURRENT_LIST_DIR}/psk_manager.cpp
                          ${CMAKE_CURRENT_LIST_DIR}/psk_callback_mgr.cpp)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/psk_define.h
        ${CMAKE_CURRENT_LIST_DIR}/psk.h
        ${CMAKE_CURRENT_LIST_DIR}/psk_manager.h
        ${CMAKE_CURRENT_LIST_DIR}/psk_callback_mgr.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/psk_management)

