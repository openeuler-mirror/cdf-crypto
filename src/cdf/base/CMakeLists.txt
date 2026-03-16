#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES}
                          ${CMAKE_CURRENT_LIST_DIR}/custom_logger.cpp
)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/custom_logger.h
        ${CMAKE_CURRENT_LIST_DIR}/common_define.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdf/base)
