#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES} ${CMAKE_CURRENT_LIST_DIR}/openbao_key_manager.cpp
    ${CMAKE_CURRENT_LIST_DIR}/openbao_utils.cpp)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/openbao_key_manager.h
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/key_management/openbao)
