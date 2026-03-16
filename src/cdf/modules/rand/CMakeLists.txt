# Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

set(CDF_SOURCE_FILES
        ${CDF_SOURCE_FILES}
        ${CMAKE_CURRENT_LIST_DIR}/rand.cpp)

set(CDF_SOURCE_FILES
        ${CDF_SOURCE_FILES}
        PARENT_SCOPE)

install(
        FILES ${CMAKE_CURRENT_LIST_DIR}/rand.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cdf/modules/rand)