#
# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
#

file(GLOB SRC_CPP *.cpp)

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES} ${SRC_CPP})

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/krb_client.h
        ${CMAKE_CURRENT_LIST_DIR}/krb_server.h
        ${CMAKE_CURRENT_LIST_DIR}/define.h
  DESTINATION
    ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/authentication/kerberos)
