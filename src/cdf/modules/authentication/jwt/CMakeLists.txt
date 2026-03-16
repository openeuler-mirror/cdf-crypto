# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.

file(GLOB SRC_CPP *.cpp)

set(CDF_SOURCE_FILES ${CDF_SOURCE_FILES} ${SRC_CPP})

set(CDF_SOURCE_FILES
    ${CDF_SOURCE_FILES}
    PARENT_SCOPE)

install(
  FILES ${CMAKE_CURRENT_LIST_DIR}/define.h
        ${CMAKE_CURRENT_LIST_DIR}/option.h
        ${CMAKE_CURRENT_LIST_DIR}/jwt_auth_server.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/authentication/jwt)
