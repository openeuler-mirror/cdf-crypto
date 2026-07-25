#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES}
                          ${CMAKE_CURRENT_LIST_DIR}/vault_key_manager.cpp)

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

cdf_install_headers(
  "${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/key_management/vault"
  ${CMAKE_CURRENT_LIST_DIR}/vault_key_manager.h)
